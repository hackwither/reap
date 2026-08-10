// Package cli wires flags, the authorization gate, and the probe pipeline
// together. This is the only place in the codebase allowed to decide
// "should a network request happen at all" — that decision is centralized
// here on purpose so it can't be quietly bypassed by a probe or template.
package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hackwither/reap/internal/discovery"
	"github.com/hackwither/reap/internal/probe"
	"github.com/hackwither/reap/internal/probe/common"
	"github.com/hackwither/reap/internal/probe/mcp"
	"github.com/hackwither/reap/internal/report"
	"github.com/hackwither/reap/internal/template"
)

const banner = `
REAP: active reconnaissance for AI agent endpoints (MCP, and growing)

This tool sends real requests to the target and only performs read-only
protocol operations (handshake, capability/tool listing, header
inspection). It never invokes a discovered tool and never attempts
exploitation.

USE ONLY AGAINST SYSTEMS YOU OWN OR ARE EXPLICITLY AUTHORIZED TO TEST.
Unauthorized access to computer systems is illegal in most jurisdictions
(e.g. the US Computer Fraud and Abuse Act) even when the requests
themselves are "just" reads. happy (ethical) hacking!
`

// collectTargets gathers targets from -t flag, --targets-file, and stdin.
// Returns deduplicated list in order of appearance.
func collectTargets(opts *Options, stderr *os.File) ([]string, error) {
	var targets []string
	seen := make(map[string]bool)

	// 1. From -t flag
	if opts.Target != "" {
		targets = append(targets, opts.Target)
		seen[opts.Target] = true
	}

	// 2. From --targets-file
	if opts.TargetsFile != "" {
		data, err := os.ReadFile(opts.TargetsFile)
		if err != nil {
			return nil, fmt.Errorf("error reading --targets-file: %w", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !seen[line] {
				targets = append(targets, line)
				seen[line] = true
			}
		}
	}

	// 3. From stdin (if not a TTY)
	stat, err := os.Stdin.Stat()
	if err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
		// stdin is piped
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !seen[line] {
				targets = append(targets, line)
				seen[line] = true
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading stdin: %w", err)
		}
	}

	return targets, nil
}

type Options struct {
	Target          string
	TargetsFile     string
	Protocol        string
	Mode            string
	NoBanner        bool
	VersionFlag     bool
	ListDetectors   bool
	AuthHeader      string
	Timeout         time.Duration
	TemplatesDir    string
	FingerprintsDir string
	Output          string
	OutFile         string
	Include         string
	Exclude         string
	ListProbes      bool
	Authorized      bool
	Concurrency     int
	Verbose         bool
	Quiet           bool
	Color           string
	FailOn          string
	Logger          *log.Logger
}

// progress prints a short stage-transition line to stderr, on by default —
// unlike -v/--verbose (dense, per-probe), this is the coarse "what phase is
// this scan in" signal nmap/nuclei both show without being asked.
func progress(opts *Options, stderr *os.File, format string, args ...any) {
	if opts.Quiet {
		return
	}
	fmt.Fprintf(stderr, "  "+format+"\n", args...)
}

func verboseLog(opts *Options, format string, args ...any) {
	if opts == nil || opts.Logger == nil {
		return
	}
	opts.Logger.Printf(format, args...)
}

func humanColorEnabled(mode string, output *os.File) bool {
	switch mode {
	case "always":
		return true
	case "never":
		return false
	}
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	info, err := output.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func Run(args []string, stdout, stderr *os.File) int {
	opts, fs, err := parseFlags(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if opts == nil { // -h/--help
		return 0
	}
	if opts.VersionFlag {
		fmt.Fprintf(stdout, "reap v%s\n", Version)
		return 0
	}
	if !opts.NoBanner && !opts.Quiet {
		PrintBanner(stderr)
	}
	if opts.Verbose {
		opts.Logger = log.New(stderr, "", 0)
	}

	reg := probe.NewRegistry()
	for _, p := range mcp.BuiltinProbes() {
		reg.Register(p)
	}
	tmplDir := opts.TemplatesDir
	if tmplDir != "" {
		templates, loadErrs := template.LoadDir(tmplDir)
		for _, e := range loadErrs {
			fmt.Fprintf(stderr, "[template load error] %v\n", e)
		}
		for _, t := range templates {
			reg.Register(t.AsProbe())
		}
	}

	if opts.ListProbes {
		for _, p := range reg.All() {
			fmt.Fprintf(stdout, "%-40s protocol=%s\n", p.ID(), p.Protocol())
		}
		return 0
	}

	// discovery / detector listing
	if opts.ListDetectors {
		dreg := buildDiscoveryRegistry(opts, stderr)
		for _, d := range dreg.All() {
			fmt.Fprintf(stdout, "%-40s kinds=%v\n", d.ID(), d.Kinds())
		}
		return 0
	}

	// Collect targets from all sources
	targets, err := collectTargets(opts, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error collecting targets: %v\n", err)
		return 2
	}

	if len(targets) == 0 {
		fmt.Fprintln(stderr, "error: must provide -t, --targets-file, or pipe targets via stdin")
		fs.Usage()
		return 2
	}

	if opts.Mode == "discover" {
		dreg := buildDiscoveryRegistry(opts, stderr)

		enc := json.NewEncoder(stdout)
		for _, t := range targets {
			c := classifyCandidate(t)
			fp := discovery.Run(context.Background(), dreg, c, discovery.DetectOptions{Timeout: opts.Timeout, AuthHeader: opts.AuthHeader})
			if fp == nil {
				// print minimal object indicating no fingerprint
				_ = enc.Encode(map[string]any{"input": t, "fingerprint": nil})
			} else {
				_ = enc.Encode(fp)
			}
		}
		return 0
	}

	// Authorization assertion is optional; warn if absent.
	if !opts.Authorized {
		fmt.Fprintln(stderr, "warning: scanning without authorization assertion; ensure you have permission before using this tool.")
	}

	// Single target: original flow
	if len(targets) == 1 {
		return scanSingleTarget(targets[0], opts, reg, stdout, stderr)
	}

	// Batch mode: multiple targets with concurrency
	return scanBatch(targets, opts, reg, stdout, stderr)
}

// classifyCandidate applies the same "is this a full URL or a bare
// host:port" heuristic --mode=discover and --protocol=auto both need before
// they can build a discovery.Candidate.
func classifyCandidate(target string) discovery.Candidate {
	var c discovery.Candidate
	c.RawInput = target
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		// A bare origin (no path, or just "/") hasn't told us where the
		// actual endpoint lives — e.g. "https://api.x.com" with the real
		// MCP endpoint at "/mcp". Treat it like a bare host:port so
		// well-known-path expansion gets a chance to find it, instead of
		// trying the origin verbatim (which finds nothing) the way a
		// fully-specified endpoint URL like ".../mcp" would be tried as-is.
		if u, err := url.Parse(target); err == nil && (u.Path == "" || u.Path == "/") {
			c.Kind = discovery.KindHostPort
			c.Host = u.Hostname()
			if portStr := u.Port(); portStr != "" {
				if port, err := strconv.Atoi(portStr); err == nil {
					c.Port = port
				}
			}
			return c
		}
		c.Kind = discovery.KindURL
		c.URL = target
		return c
	}
	c.Kind = discovery.KindHostPort
	return c
}

// resolveViaDiscovery runs Discovery against target when opts.Protocol ==
// "auto", populating rep.Target's discovery-derived fields and returning the
// resolved protocol to scan with. For any other --protocol value it's a
// no-op passthrough. Falls back to "mcp" when discovery finds nothing,
// since that's the only implemented protocol pipeline today.
// resolveViaDiscovery runs Discovery (when opts.Protocol == "auto") and
// returns both the resolved protocol AND the resolved endpoint URL to
// actually scan. The second part matters as much as the first: a bare
// origin like "https://api.x.com" only tells Discovery where to start
// looking — the real endpoint well-known-path expansion finds (e.g.
// ".../mcp") lives on the matched Fingerprint's Candidate, not on the
// input string. Returning just the protocol and leaving the caller to scan
// the original bare origin is exactly the bug where discovery "finds" the
// right endpoint but the scan still hits the wrong URL and times out.
func resolveViaDiscovery(ctx context.Context, target string, opts *Options, rep *report.Report, stderr *os.File) (protocol, resolvedTarget string) {
	candidate := classifyCandidate(target)

	if opts.Protocol != "auto" {
		if candidate.Kind != discovery.KindHostPort {
			// A full endpoint URL (has a real path) — the user told us
			// exactly where it is, nothing to resolve.
			return opts.Protocol, target
		}
		// A bare origin (e.g. "https://api.x.com") under a fixed
		// --protocol: the protocol is asserted, but the path isn't known
		// any more than it is under --protocol=auto. "Which path" and
		// "which protocol" are separate questions — resolve the path via
		// the same well-known-path discovery, restricted to confirming an
		// endpoint for the protocol already asserted, without touching
		// which protocol actually runs.
		fp := runDiscovery(ctx, candidate, opts, stderr)
		if fp == nil || fp.Protocol != opts.Protocol || fp.Candidate.URL == "" {
			verboseLog(opts, "no %s endpoint found via well-known paths for %s, scanning the bare origin as given", opts.Protocol, target)
			return opts.Protocol, target
		}
		rep.Target.Transport = fp.Transport
		rep.Target.DiscoveryMethod = fp.DetectorID
		rep.Target.DiscoveryConfidence = fp.Confidence
		rep.Target.URL = fp.Candidate.URL
		verboseLog(opts, "resolved bare origin %s -> %s (detector=%s)", target, fp.Candidate.URL, fp.DetectorID)
		return opts.Protocol, fp.Candidate.URL
	}

	fp := runDiscovery(ctx, candidate, opts, stderr)
	if fp == nil {
		rep.Target.DiscoveryMethod = "none"
		verboseLog(opts, "discovery found nothing for %s, falling back to mcp", target)
		return "mcp", target
	}
	rep.Target.Protocol = fp.Protocol
	rep.Target.Transport = fp.Transport
	rep.Target.DiscoveryMethod = fp.DetectorID
	rep.Target.DiscoveryConfidence = fp.Confidence
	if fp.ServerName != "" {
		rep.Target.ServerName = fp.ServerName
	}
	if fp.ServerVer != "" {
		rep.Target.ServerVer = fp.ServerVer
	}
	if fp.ProtocolVer != "" {
		rep.Target.ProtocolVer = fp.ProtocolVer
	}
	resolvedTarget = target
	if fp.Candidate.URL != "" {
		resolvedTarget = fp.Candidate.URL
		rep.Target.URL = resolvedTarget // report what was actually scanned, not just what the user typed
	}
	verboseLog(opts, "discovery resolved %s as protocol=%s transport=%s confidence=%s endpoint=%s (detector=%s)", target, fp.Protocol, fp.Transport, fp.Confidence, resolvedTarget, fp.DetectorID)
	return fp.Protocol, resolvedTarget
}

// runDiscovery assembles the registry and runs it against one candidate —
// shared by both branches of resolveViaDiscovery (protocol-detection under
// --protocol=auto, and endpoint-path resolution for a bare origin under a
// fixed --protocol) so they don't each hand-roll the same two calls.
func runDiscovery(ctx context.Context, candidate discovery.Candidate, opts *Options, stderr *os.File) *discovery.Fingerprint {
	dreg := buildDiscoveryRegistry(opts, stderr)
	return discovery.Run(ctx, dreg, candidate, discovery.DetectOptions{Timeout: opts.Timeout, AuthHeader: opts.AuthHeader})
}

// newSessionForTransport builds the probe.Session implementation matching
// the transport discovery resolved (or "http-streamable", the static
// --protocol=mcp default). This is the one place that decides which
// concrete Session type a scan uses — every downstream consumer (probes,
// mcp.InitializeSession) only ever sees the probe.Session interface.
func newSessionForTransport(target, transport, authHeader string, timeout time.Duration) (probe.Session, error) {
	switch transport {
	case "http-sse-legacy":
		return mcp.NewSSESession(target, authHeader, timeout), nil
	case "websocket":
		return mcp.NewWSSession(target, authHeader, timeout)
	default: // "http-streamable", "", or anything unrecognized
		return mcp.NewSession(target, authHeader, timeout), nil
	}
}

// buildDiscoveryRegistry assembles the discovery.Registry from hand-written
// Go detectors plus any data-driven fingerprints found in opts.FingerprintsDir
// — the same two-source pattern probe.Registry already uses for built-in
// probes plus loaded templates.
func buildDiscoveryRegistry(opts *Options, stderr *os.File) *discovery.Registry {
	dreg := discovery.NewRegistry()
	for _, d := range discovery.BuiltinDetectors() {
		dreg.Register(d)
	}
	if opts.FingerprintsDir != "" {
		fingerprints, loadErrs := discovery.LoadFingerprintDir(opts.FingerprintsDir)
		for _, e := range loadErrs {
			fmt.Fprintf(stderr, "[fingerprint load error] %v\n", e)
		}
		for _, fpt := range fingerprints {
			dreg.Register(fpt.AsDetector())
		}
	}
	return dreg
}

// scanSingleTarget handles a single target (backward compatible path)
func scanSingleTarget(target string, opts *Options, reg *probe.Registry, stdout, stderr *os.File) int {
	rep := runScan(target, opts, reg, stderr)
	return writeReport(rep, opts, stdout, stderr)
}

// runScan performs the full discovery → fingerprint → enumerate → probe
// pipeline for one target and returns the finished report. Both the
// single-target and batch paths share this — they used to duplicate the
// whole scan body, which is exactly the kind of place a fix (like the
// confirmation-gating logic below) silently lands in only one of the two
// copies.
func runScan(target string, opts *Options, reg *probe.Registry, stderr *os.File) *report.Report {
	verboseLog(opts, "scanning %s", target)
	rep := &report.Report{
		Tool:      "reap",
		Version:   Version,
		StartedAt: time.Now().UTC(),
		Target:    report.Target{URL: target, Protocol: opts.Protocol},
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout*4)
	defer cancel()

	progress(opts, stderr, "discovery  %s", target)
	protocol, resolvedTarget := resolveViaDiscovery(ctx, target, opts, rep, stderr)
	if resolvedTarget != target {
		progress(opts, stderr, "discovery  resolved endpoint %s", resolvedTarget)
		verboseLog(opts, "discovery resolved endpoint %s -> %s", target, resolvedTarget)
	}
	if rep.Target.Transport == "" {
		// Discovery wasn't asked to run (--protocol=mcp, the static
		// default path) — the session below is always mcp.NewSession,
		// i.e. streamable-HTTP, so record that instead of leaving
		// Transport blank. No probe filtering changes as a result: every
		// built-in probe already supports http-streamable.
		rep.Target.Transport = "http-streamable"
	}

	captureTargetFingerprint(ctx, resolvedTarget, rep, opts.Timeout)

	progress(opts, stderr, "fingerprint  handshake (%s over %s)", protocol, rep.Target.Transport)
	sess, err := newSessionForTransport(resolvedTarget, rep.Target.Transport, opts.AuthHeader, opts.Timeout)
	if err != nil {
		rep.AddError(fmt.Errorf("establish %s session: %w", rep.Target.Transport, err))
		rep.Target.Confirmed = false
		rep.Target.ConfirmState = report.ConfirmStateUnconfirmed
		rep.Target.ConfirmReason = fmt.Sprintf("could not establish a %s connection: %v", rep.Target.Transport, err)
		rep.FinishedAt = time.Now().UTC()
		return rep
	}

	init, initRaw, err := mcp.InitializeSession(ctx, sess)
	if initRaw != nil && initRaw.Headers != nil {
		// Captured regardless of handshake success — a CDN/edge Server
		// header (e.g. "cloudflare") is a fact about what's fronting the
		// target, not a security finding, and it's present on error
		// responses too. Surfacing it in the fingerprint block up front
		// (WriteHuman's "edge" line) reframes the rest of the report
		// correctly: you're often probing the edge, not the origin.
		rep.Target.EdgeServer = initRaw.Headers.Get("Server")
	}

	// A 401/403 on initialize is only a scan failure if the response looks
	// nothing like MCP. If it's auth-gated but MCP-consistent (problem+json,
	// a JSON-RPC error envelope, or a Bearer challenge), the target IS an
	// MCP endpoint that requires credentials — that's confirmed, not an
	// error. See mcp.ClassifyAuthGate.
	isAuthStatus := initRaw != nil && (initRaw.StatusCode == http.StatusUnauthorized || initRaw.StatusCode == http.StatusForbidden)
	var authGate mcp.AuthGateSignal
	if err != nil && isAuthStatus {
		authGate = mcp.ClassifyAuthGate(initRaw)
	}

	switch {
	case err == nil && init != nil:
		rep.Target.Confirmed = true
		rep.Target.ConfirmState = report.ConfirmStateConfirmed
		rep.Target.ServerName = init.ServerInfo.Name
		rep.Target.ServerVer = init.ServerInfo.Version
		rep.Target.ProtocolVer = init.ProtocolVersion
		verboseLog(opts, "initialize handshake success: server=%s version=%s protocol=%s", init.ServerInfo.Name, init.ServerInfo.Version, init.ProtocolVersion)

	case err != nil && isAuthStatus && authGate.Any():
		// Auth gate is expected behavior for a protected MCP server, not a
		// tool error — deliberately no rep.AddError and Confirmed stays true.
		rep.Target.Confirmed = true
		rep.Target.ConfirmState = report.ConfirmStateAuthGated
		rep.Target.ConfirmReason = fmt.Sprintf("initialize requires auth: HTTP %d (%s)", initRaw.StatusCode, authGate.String())
		verboseLog(opts, "initialize requires auth: HTTP %d (%s) — treating target as confirmed", initRaw.StatusCode, authGate.String())

	case err != nil:
		rep.AddError(fmt.Errorf("initialize handshake failed: %w", err))
		rep.Target.Confirmed = false
		rep.Target.ConfirmState = report.ConfirmStateUnconfirmed
		rep.Target.ConfirmReason = fmt.Sprintf("%s initialize handshake failed: %v", protocol, err)
		verboseLog(opts, "initialize handshake failed: %v", err)
	}

	byProtocol := reg.ForProtocol(protocol)
	byTransport := reg.ForProtocolAndTransport(protocol, rep.Target.Transport)
	transportSkipped := len(byProtocol) - len(byTransport)
	probes := filterProbes(byTransport, opts.Include, opts.Exclude)
	progress(opts, stderr, "enumerate + probe  %d checks", len(probes))
	perProbeCounts := make(map[string]int, len(probes))
	for _, p := range probes {
		verboseLog(opts, "running probe %s", p.ID())
		before := len(rep.Findings)
		if err := p.Run(ctx, sess, rep); err != nil {
			rep.AddError(fmt.Errorf("probe %s: %w", p.ID(), err))
			verboseLog(opts, "probe %s failed: %v", p.ID(), err)
		} else {
			verboseLog(opts, "probe %s completed", p.ID())
		}
		perProbeCounts[p.ID()] = len(rep.Findings) - before
	}
	rep.ComputeCoverage(perProbeCounts, transportSkipped)
	rep.ApplyConfidenceDowngrade()
	rep.FinishedAt = time.Now().UTC()

	return rep
}

// captureTargetFingerprint fills in the best-effort facts shown in the
// report's fingerprint block (resolved IP, TLS summary) once up front,
// regardless of whether any probe later turns them into a finding — a
// scanner announcing what it found before it announces what's wrong is
// table stakes (nmap does the same with its port/service map).
func captureTargetFingerprint(ctx context.Context, target string, rep *report.Report, timeout time.Duration) {
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" {
		return
	}
	if ips, err := net.DefaultResolver.LookupHost(ctx, u.Hostname()); err == nil && len(ips) > 0 {
		rep.Target.ResolvedIP = ips[0]
	}
	if u.Scheme == "https" {
		if state, cert, err := common.InspectTLS(ctx, target); err == nil {
			validity := "valid"
			if time.Now().After(cert.NotAfter) || time.Now().Before(cert.NotBefore) {
				validity = "invalid"
			}
			rep.Target.TLSSummary = fmt.Sprintf("%s · %s · %s", common.TLSVersionName(state.Version), validity, cert.Subject.CommonName)
		}
	}
}

// scanBatch handles multiple targets with concurrency
func scanBatch(targets []string, opts *Options, reg *probe.Registry, stdout, stderr *os.File) int {
	verboseLog(opts, "running batch scan for %d targets (concurrency=%d)", len(targets), opts.Concurrency)
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 5
	}

	// Collect all reports
	results := make([]*report.Report, len(targets))
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Create worker pool
	jobs := make(chan struct {
		idx    int
		target string
	}, concurrency)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				rep := runScan(job.target, opts, reg, os.Stderr)
				mu.Lock()
				results[job.idx] = rep
				mu.Unlock()
			}
		}()
	}

	// Enqueue jobs
	for i, t := range targets {
		jobs <- struct {
			idx    int
			target string
		}{i, t}
	}
	close(jobs)
	wg.Wait()

	// Write batch output
	return writeBatchReport(results, opts, stdout, stderr)
}

// writeBatchReport handles output for multiple targets
func writeBatchReport(reports []*report.Report, opts *Options, stdout, stderr *os.File) int {
	var f *os.File
	if opts.OutFile != "" {
		var err error
		f, err = os.Create(opts.OutFile)
		if err != nil {
			fmt.Fprintf(stderr, "error creating --out file: %v\n", err)
			return 1
		}
		defer f.Close()
	}

	switch opts.Output {
	case "json":
		// NDJSON (newline-delimited JSON) for batch mode
		target := stdout
		if f != nil {
			target = f
		}
		enc := json.NewEncoder(target)
		for _, rep := range reports {
			if err := enc.Encode(rep); err != nil {
				fmt.Fprintf(stderr, "error writing JSON: %v\n", err)
				return 1
			}
		}
	case "sarif":
		// Multi-run SARIF (one run per target in a single document)
		target := stdout
		if f != nil {
			target = f
		}
		if err := writeBatchSARIF(reports, target); err != nil {
			fmt.Fprintf(stderr, "error writing SARIF: %v\n", err)
			return 1
		}
	default:
		// Human-readable: per-target header + report
		for _, rep := range reports {
			rep.WriteHumanDossier(stdout, humanColorEnabled(opts.Color, stdout), opts.Verbose)
		}
	}

	for _, rep := range reports {
		if exitCode(rep.Errors, rep.MeetsSeverity(report.Severity(opts.FailOn))) == 1 {
			return 1
		}
	}
	return 0
}

// writeBatchSARIF writes all reports as a single SARIF document with multiple runs
func writeBatchSARIF(reports []*report.Report, w *os.File) error {
	runs := make([]map[string]any, 0, len(reports))
	for _, rep := range reports {
		// De-duplicate rules by finding ID
		rulesByID := make(map[string]report.Finding)
		for _, f := range rep.Findings {
			rulesByID[f.ID] = f
		}

		// Build rules array (deduplicated)
		rules := make([]map[string]any, 0, len(rulesByID))
		for _, id := range uniqueFindingIDsFromFindings(rep.Findings) {
			f := rulesByID[id]
			rules = append(rules, map[string]any{
				"id": f.ID,
				"shortDescription": map[string]string{
					"text": f.Title,
				},
				"fullDescription": map[string]string{
					"text": f.Description,
				},
				"help": map[string]string{
					"text": f.Remediation,
				},
				"properties": map[string]any{
					"tags": f.ASI,
				},
			})
		}

		// Build results array
		results := make([]map[string]any, 0, len(rep.Findings))
		for _, f := range rep.Findings {
			results = append(results, map[string]any{
				"ruleId": f.ID,
				"level":  severityToSARIFLevel(f.Severity),
				"message": map[string]string{
					"text": f.Description,
				},
				"locations": []map[string]any{
					{
						"physicalLocation": map[string]any{
							"artifactLocation": map[string]string{
								"uri": rep.Target.URL,
							},
						},
					},
				},
			})
		}

		runs = append(runs, map[string]any{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":           "reap",
					"informationUri": "https://github.com/hackwither/reap",
					"version":        rep.Version,
					"rules":          rules,
				},
			},
			"results": results,
		})
	}

	sarifDoc := map[string]any{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs":    runs,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifDoc)
}

// uniqueFindingIDsFromFindings returns unique finding IDs in order of appearance
func uniqueFindingIDsFromFindings(findings []report.Finding) []string {
	seen := make(map[string]bool)
	var ids []string
	for _, f := range findings {
		if !seen[f.ID] {
			ids = append(ids, f.ID)
			seen[f.ID] = true
		}
	}
	return ids
}

// severityToSARIFLevel maps reap severity to SARIF level
func severityToSARIFLevel(sev report.Severity) string {
	switch sev {
	case report.SeverityHigh:
		return "error"
	case report.SeverityMedium:
		return "warning"
	case report.SeverityLow, report.SeverityInfo:
		return "note"
	default:
		return "note"
	}
}

func filterProbes(all []probe.Probe, include, exclude string) []probe.Probe {
	inc := splitCSV(include)
	exc := splitCSV(exclude)
	if len(inc) == 0 && len(exc) == 0 {
		return all
	}
	var out []probe.Probe
	for _, p := range all {
		if len(inc) > 0 && !containsStr(inc, p.ID()) {
			continue
		}
		if containsStr(exc, p.ID()) {
			continue
		}
		out = append(out, p)
	}
	return out
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func writeReport(rep *report.Report, opts *Options, stdout, stderr *os.File) int {
	var w = stdout
	var f *os.File
	if opts.OutFile != "" {
		var err error
		f, err = os.Create(opts.OutFile)
		if err != nil {
			fmt.Fprintf(stderr, "error creating --out file: %v\n", err)
			return 1
		}
		defer f.Close()
	}

	switch opts.Output {
	case "json":
		target := stdout
		if f != nil {
			target = f
		}
		if err := rep.WriteJSON(target); err != nil {
			fmt.Fprintf(stderr, "error writing JSON: %v\n", err)
			return 1
		}
	case "sarif":
		target := stdout
		if f != nil {
			target = f
		}
		if err := rep.WriteSARIF(target); err != nil {
			fmt.Fprintf(stderr, "error writing SARIF: %v\n", err)
			return 1
		}
	default:
		rep.WriteHumanDossier(w, humanColorEnabled(opts.Color, w), opts.Verbose)
		if f != nil {
			_ = rep.WriteJSON(f)
		}
	}

	return exitCode(rep.Errors, rep.MeetsSeverity(report.Severity(opts.FailOn)))
}

// exitCode centralizes the two independent reasons a scan should fail a
// pipeline: the run itself errored (handshake failure, etc — always
// visible in CI regardless of --fail-on), or a finding met the configured
// --fail-on severity threshold.
func exitCode(errs []string, severityTripped bool) int {
	if len(errs) > 0 || severityTripped {
		return 1
	}
	return 0
}

func parseFlags(args []string) (*Options, *flag.FlagSet, error) {
	fs := flag.NewFlagSet("reap", flag.ContinueOnError)
	o := &Options{}
	fs.StringVar(&o.Target, "t", "", "target MCP endpoint URL (e.g. https://host/mcp)")
	fs.StringVar(&o.Target, "target", "", "target MCP endpoint URL (e.g. https://host/mcp)")
	fs.StringVar(&o.TargetsFile, "targets-file", "", "file with one target URL per line (optionally combined with -t and stdin)")
	fs.IntVar(&o.Concurrency, "concurrency", 5, "number of concurrent target scans in batch mode")
	fs.StringVar(&o.Protocol, "protocol", "mcp", "protocol to probe (currently: mcp|auto)")
	fs.StringVar(&o.Mode, "mode", "scan", "mode to run: scan|discover|full (discover prints fingerprints)")
	fs.BoolVar(&o.NoBanner, "no-banner", false, "suppress startup banner on stderr")
	fs.BoolVar(&o.VersionFlag, "version", false, "print version and exit")
	fs.BoolVar(&o.ListDetectors, "list-detectors", false, "list discovery detectors and exit")
	fs.StringVar(&o.AuthHeader, "auth-header", "", `optional Authorization header value to send, e.g. "Bearer xyz"`)
	fs.DurationVar(&o.Timeout, "timeout", 10*time.Second, "per-request timeout")
	fs.StringVar(&o.TemplatesDir, "templates", "templates", "directory of JSON probe templates (empty string to disable)")
	fs.StringVar(&o.FingerprintsDir, "fingerprints", "fingerprints", "directory of JSON discovery fingerprints (empty string to disable)")
	fs.StringVar(&o.Output, "output", "text", "output format: text|json|sarif (JSON is NDJSON in batch mode)")
	fs.StringVar(&o.OutFile, "out", "", "write report to file in addition to stdout")
	fs.BoolVar(&o.Verbose, "v", false, "verbose output")
	fs.BoolVar(&o.Verbose, "verbose", false, "verbose output")
	fs.StringVar(&o.Include, "include", "", "comma-separated probe IDs to run (default: all)")
	fs.StringVar(&o.Exclude, "exclude", "", "comma-separated probe IDs to skip")
	fs.BoolVar(&o.ListProbes, "list-probes", false, "list all registered probe IDs and exit")
	fs.BoolVar(&o.Authorized, "authorized", false, "confirm you own or are explicitly authorized to test the target(s)")
	fs.BoolVar(&o.Quiet, "quiet", false, "suppress banner and stage-progress lines on stderr")
	fs.StringVar(&o.Color, "color", "auto", "colorize output: auto|always|never")
	fs.StringVar(&o.FailOn, "fail-on", "none", "exit 1 on finding at/above severity: none|low|medium|high")

	fs.Usage = func() {
		PrintBanner(fs.Output())
		fmt.Fprintln(fs.Output(), "usage: reap -t <url> --authorized [flags]")
		fmt.Fprintln(fs.Output(), "       reap --targets-file <file> --authorized [flags]")
		fmt.Fprintln(fs.Output(), "       cat targets.txt | reap --authorized [flags]")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil, fs, nil
		}
		return nil, fs, err
	}
	switch o.Color {
	case "auto", "always", "never":
	default:
		return nil, fs, fmt.Errorf("invalid --color value %q: expected auto, always, or never", o.Color)
	}
	return o, fs, nil
}
