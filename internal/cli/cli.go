// Package cli wires flags, the authorization gate, and the probe pipeline
// together. This is the only place in the codebase allowed to decide
// "should a network request happen at all" — that decision is centralized
// here on purpose so it can't be quietly bypassed by a probe or template.
package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hackwither/reap/internal/discovery"
	"github.com/hackwither/reap/internal/httpx"
	"github.com/hackwither/reap/internal/probe"
	"github.com/hackwither/reap/internal/probe/common"
	"github.com/hackwither/reap/internal/probe/generic"
	"github.com/hackwither/reap/internal/probe/mcp"
	"github.com/hackwither/reap/internal/probe/transport"
	"github.com/hackwither/reap/internal/report"
	"github.com/hackwither/reap/internal/template"
	"github.com/hackwither/reap/internal/version"

	embeddedFingerprints "github.com/hackwither/reap/fingerprints"
	embeddedTemplates "github.com/hackwither/reap/templates"
)

// embeddedSource is the sentinel --templates/--fingerprints value that loads
// reap's built-in set from the binary itself rather than from disk. It is the
// default so a `go install`'d reap works with no checkout; pass a directory to
// override, or "" to disable.
const embeddedSource = "embedded"

// Exit codes. These are part of reap's contract with CI systems, so they are
// named rather than sprinkled as literals.
//
// A probe or handshake error no longer means exit 1. An auth-gated endpoint
// used to fail a pipeline, which punished the operator for scanning a
// correctly-configured server. Findings drive exit 1 (and only at or above
// --fail-on); a scan that could not complete gets its own code so "we
// couldn't look" stays distinguishable from "we looked and it was clean".
const (
	exitOK         = 0
	exitFindings   = 1
	exitUsage      = 2
	exitIncomplete = 3
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
// shouldReadStdin decides whether reading stdin is safe and wanted.
func (o *Options) shouldReadStdin() bool {
	if o.Stdin {
		return true // explicit request: blocking is the caller's choice
	}
	if o.Target != "" || o.TargetsFile != "" {
		return false // a target source was named; never risk a blocking read
	}
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) == 0
}

func collectTargets(opts *Options) ([]string, error) {
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

	// 3. From stdin — but only when the caller actually asked for it.
	//
	// reap used to read stdin whenever it wasn't a character device, even with
	// -t supplied. Any caller that handed it an open pipe it never wrote to —
	// `slow | reap -t URL`, a CI runner, or subprocess.run(stdin=PIPE) — hung
	// forever, with no timeout covering it.
	if opts.shouldReadStdin() {
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
	Stdin           bool
	Headers         headerList
	ScanTimeout     time.Duration
	Proxy           string
	Insecure        bool
	UserAgent       string
	Retries         int
	Delay           time.Duration
	RateLimit       float64
	MinSeverity     string
	Logger          *log.Logger

	// derived during validation
	client      *httpx.Client
	failOn      report.Severity
	failOnSet   bool
	minSeverity report.Severity
	minSevSet   bool
	scanBudget  time.Duration
}

// headerList collects repeatable -H/--header flags.
type headerList struct {
	values map[string]string
	order  []string
}

func (h *headerList) String() string { return strings.Join(h.order, ", ") }

func (h *headerList) Set(v string) error {
	name, value, ok := strings.Cut(v, ":")
	if !ok {
		return fmt.Errorf("expected 'Name: value', got %q", v)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("empty header name in %q", v)
	}
	if h.values == nil {
		h.values = map[string]string{}
	}
	h.values[name] = strings.TrimSpace(value)
	h.order = append(h.order, name)
	return nil
}

var (
	validModes     = []string{"scan", "discover", "full"}
	validOutputs   = []string{"text", "json", "sarif"}
	validProtocols = []string{"auto", "mcp"}
)

// validateOptions rejects unusable flag combinations up front, so a typo
// surfaces as a usage error instead of silently changing behaviour.
func validateOptions(opts *Options) error {
	if !containsStr(validModes, opts.Mode) {
		return fmt.Errorf("invalid --mode %q (want one of: %s)", opts.Mode, strings.Join(validModes, ", "))
	}
	if !containsStr(validOutputs, opts.Output) {
		return fmt.Errorf("invalid --output %q (want one of: %s)", opts.Output, strings.Join(validOutputs, ", "))
	}
	if !containsStr(validProtocols, opts.Protocol) {
		return fmt.Errorf("invalid --protocol %q (want one of: %s)", opts.Protocol, strings.Join(validProtocols, ", "))
	}
	if opts.Timeout <= 0 {
		return fmt.Errorf("--timeout must be positive")
	}
	if opts.Concurrency < 1 {
		return fmt.Errorf("--concurrency must be at least 1")
	}
	if opts.Retries < 0 {
		return fmt.Errorf("--retries cannot be negative")
	}
	if opts.FailOn != "" && opts.FailOn != "none" {
		sev, err := report.ParseSeverity(opts.FailOn)
		if err != nil {
			return fmt.Errorf("invalid --fail-on: %w", err)
		}
		opts.failOn, opts.failOnSet = sev, true
	}
	if opts.MinSeverity != "" {
		sev, err := report.ParseSeverity(opts.MinSeverity)
		if err != nil {
			return fmt.Errorf("invalid --min-severity: %w", err)
		}
		opts.minSeverity, opts.minSevSet = sev, true
	}
	// "full" means discover-then-scan, so it implies protocol auto-detection.
	if opts.Mode == "full" {
		opts.Protocol = "auto"
	}
	if opts.ScanTimeout > 0 {
		opts.scanBudget = opts.ScanTimeout
	} else {
		// A whole scan used to get --timeout*4 (40s by default) for every
		// probe combined, so a slow target quietly reported no findings.
		opts.scanBudget = opts.Timeout * 8
	}
	return nil
}

// validateProbeSelection errors on an unknown --include/--exclude ID. A typo
// used to select zero probes, emit an empty report, and exit 0, so a CI
// pipeline could stay green forever without running a single check.
func validateProbeSelection(reg *probe.Registry, opts *Options) error {
	known := map[string]bool{}
	ids := make([]string, 0, len(reg.All()))
	for _, p := range reg.All() {
		known[p.ID()] = true
		ids = append(ids, p.ID())
	}
	sort.Strings(ids)

	for _, sel := range []struct{ flag, csv string }{{"--include", opts.Include}, {"--exclude", opts.Exclude}} {
		for _, id := range splitCSV(sel.csv) {
			if known[id] {
				continue
			}
			msg := fmt.Sprintf("unknown probe ID %q in %s", id, sel.flag)
			if near := nearestIDs(id, ids); len(near) > 0 {
				msg += fmt.Sprintf("; did you mean %s?", strings.Join(near, ", "))
			}
			return fmt.Errorf("%s (run --list-probes to see all %d)", msg, len(ids))
		}
	}
	return nil
}

// nearestIDs offers substring-based suggestions for a mistyped probe ID.
func nearestIDs(want string, ids []string) []string {
	var out []string
	trimmed := strings.ReplaceAll(strings.ToLower(want), "-", "")
	for _, id := range ids {
		candidate := strings.ReplaceAll(strings.ToLower(id), "-", "")
		if strings.Contains(candidate, trimmed) || strings.Contains(trimmed, candidate) {
			out = append(out, id)
		}
	}
	if len(out) > 3 {
		out = out[:3]
	}
	return out
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
		fmt.Fprintf(stdout, "reap v%s\n", version.Version)
		return exitOK
	}
	if !opts.NoBanner && !opts.Quiet {
		PrintBanner(stderr)
	}
	if opts.Verbose {
		opts.Logger = log.New(stderr, "", 0)
	}

	if err := validateOptions(opts); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}

	client, err := httpx.New(httpx.Config{
		Timeout:   opts.Timeout,
		Proxy:     opts.Proxy,
		Insecure:  opts.Insecure,
		UserAgent: opts.UserAgent,
		Headers:   opts.Headers.values,
		Retries:   opts.Retries,
		Delay:     opts.Delay,
		RateLimit: opts.RateLimit,
	}, version.UserAgent())
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}
	opts.client = client

	reg := probe.NewRegistry()
	for _, p := range mcp.BuiltinProbes() {
		reg.Register(p)
	}
	// Protocol-neutral transport checks, registered with Protocol() == "*" so
	// they run against every protocol reap can identify — including A2A and
	// OpenAPI, which have no enumeration probes yet.
	for _, p := range transport.BuiltinProbes(opts.client) {
		reg.Register(p)
	}
	if tmplDir := opts.TemplatesDir; tmplDir != "" {
		var templates []*template.Template
		var loadErrs []error
		if tmplDir == embeddedSource {
			templates, loadErrs = template.LoadFS(embeddedTemplates.FS)
		} else {
			templates, loadErrs = template.LoadDir(tmplDir)
		}
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

	if err := validateProbeSelection(reg, opts); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}

	// Collect targets from all sources
	targets, err := collectTargets(opts)
	if err != nil {
		fmt.Fprintf(stderr, "error collecting targets: %v\n", err)
		return exitUsage
	}

	if len(targets) == 0 {
		fmt.Fprintln(stderr, "error: must provide -t, --targets-file, or pipe targets via stdin")
		fs.Usage()
		return exitUsage
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
// newSessionForTransport picks a Session implementation for a protocol and
// transport.
//
// The protocol switch is the seam docs/ARCHITECTURE.md promised and cli.go
// didn't have: it used to build an MCP session for every target regardless of
// what discovery said, so identifying an A2A or OpenAPI endpoint produced a
// fingerprint and then a failed MCP handshake, and no posture at all.
func newSessionForTransport(protocol, target, transport, authHeader string, client *httpx.Client) (probe.Session, error) {
	if protocol != "mcp" {
		// No enumeration probes for this protocol yet, but the
		// protocol-neutral transport checks only need a URL and an HTTP
		// client, so the target still gets a real report.
		return generic.NewSession(target, authHeader, client), nil
	}
	switch transport {
	case "http-sse-legacy":
		return mcp.NewSSESession(target, authHeader, client)
	case "websocket":
		return mcp.NewWSSession(target, authHeader, client)
	default:
		return mcp.NewSession(target, authHeader, client), nil
	}
}

func buildDiscoveryRegistry(opts *Options, stderr *os.File) *discovery.Registry {
	dreg := discovery.NewRegistry()
	for _, d := range discovery.BuiltinDetectors() {
		dreg.Register(d)
	}
	if fpDir := opts.FingerprintsDir; fpDir != "" {
		var fingerprints []*discovery.FingerprintTemplate
		var loadErrs []error
		if fpDir == embeddedSource {
			fingerprints, loadErrs = discovery.LoadFingerprintFS(embeddedFingerprints.FS)
		} else {
			fingerprints, loadErrs = discovery.LoadFingerprintDir(fpDir)
		}
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
	rep := report.New(target, target, opts.Protocol)

	ctx, cancel := context.WithTimeout(context.Background(), opts.scanBudget)
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

	rep.Target.URL = resolvedTarget
	captureTargetFingerprint(ctx, resolvedTarget, rep, opts.client)

	progress(opts, stderr, "fingerprint  handshake (%s over %s)", protocol, rep.Target.Transport)
	sess, err := newSessionForTransport(protocol, resolvedTarget, rep.Target.Transport, opts.AuthHeader, opts.client)
	if err != nil {
		rep.AddError(fmt.Errorf("establish %s session: %w", rep.Target.Transport, err))
		rep.Target.Confirmed = false
		rep.Target.ConfirmState = report.ConfirmStateUnconfirmed
		rep.Target.ConfirmReason = fmt.Sprintf("could not establish a %s connection: %v", rep.Target.Transport, err)
		rep.Target.AuthState = report.AuthStateUnreached
		rep.MarkIncomplete(fmt.Sprintf("could not establish a %s connection", rep.Target.Transport))
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
		if ms, ok := sess.(*mcp.Session); ok {
			if v := ms.NegotiatedVersion(); v != "" {
				rep.Target.ProtocolVer = v
			}
		}
		verboseLog(opts, "initialize handshake success: server=%s version=%s protocol=%s", init.ServerInfo.Name, init.ServerInfo.Version, rep.Target.ProtocolVer)

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
		rep.Target.AuthState = report.AuthStateUnreached
		rep.MarkIncomplete("handshake failed")
		verboseLog(opts, "initialize handshake failed: %v", err)
	}

	byProtocol := reg.ForProtocol(protocol)
	byTransport := reg.ForProtocolAndTransport(protocol, rep.Target.Transport)
	transportSkipped := len(byProtocol) - len(byTransport)
	probes := filterProbes(byTransport, opts.Include, opts.Exclude)
	progress(opts, stderr, "enumerate + probe  %d checks", len(probes))
	for _, p := range probes {
		if ctx.Err() != nil {
			rep.RecordProbe(p.ID(), report.ProbeAborted, "scan deadline exceeded before this probe ran", 0)
			continue
		}
		runProbe(ctx, p, sess, rep, opts)
	}
	if ctx.Err() != nil {
		rep.MarkIncomplete("scan deadline exceeded")
	}
	rep.ComputeCoverage(transportSkipped)
	rep.ApplyConfidenceDowngrade()
	rep.FinishedAt = time.Now().UTC()

	return rep
}

// runProbe executes one probe and records its outcome.
//
// The three-way distinction is the point. Probes used to return nil both when
// they found nothing and when they couldn't look, so a report full of silence
// was indistinguishable from a clean result.
func runProbe(ctx context.Context, p probe.Probe, sess probe.Session, rep *report.Report, opts *Options) {
	verboseLog(opts, "running probe %s", p.ID())
	before := len(rep.Findings)
	err := p.Run(ctx, sess, rep)
	added := len(rep.Findings) - before

	switch {
	case err == nil:
		rep.RecordProbe(p.ID(), report.ProbeRan, "", added)
		verboseLog(opts, "probe %s ran (%d findings)", p.ID(), added)
	case errors.Is(err, probe.ErrNotApplicable):
		rep.RecordProbe(p.ID(), report.ProbeNotApplicable, err.Error(), added)
		verboseLog(opts, "probe %s not applicable: %v", p.ID(), err)
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		rep.RecordProbe(p.ID(), report.ProbeAborted, err.Error(), added)
		verboseLog(opts, "probe %s aborted: %v", p.ID(), err)
	default:
		// Recorded as a probe status, not pushed into rep.Errors: one probe
		// failing is a coverage gap, not a scan-level failure.
		rep.RecordProbe(p.ID(), report.ProbeError, err.Error(), added)
		verboseLog(opts, "probe %s failed: %v", p.ID(), err)
	}
}

// captureTargetFingerprint fills in the best-effort facts shown in the
// report's fingerprint block (resolved IP, TLS summary) once up front,
// regardless of whether any probe later turns them into a finding — a
// scanner announcing what it found before it announces what's wrong is
// table stakes (nmap does the same with its port/service map).
func captureTargetFingerprint(ctx context.Context, target string, rep *report.Report, client *httpx.Client) {
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" {
		return
	}
	if ips, err := net.DefaultResolver.LookupHost(ctx, u.Hostname()); err == nil && len(ips) > 0 {
		rep.Target.ResolvedIP = ips[0]
	}
	if u.Scheme == "https" {
		if state, cert, err := common.InspectTLS(ctx, client, target); err == nil {
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
	applyMinSeverity(reports, opts)

	var f *os.File
	if opts.OutFile != "" {
		var err error
		f, err = os.Create(opts.OutFile)
		if err != nil {
			fmt.Fprintf(stderr, "error creating --out file: %v\n", err)
			return exitUsage
		}
		defer f.Close()
	}

	// --out is written for every format, text included. It used to be honoured
	// only for json/sarif, so a batch text run created the file and left it
	// empty — silent data loss.
	write := func(w io.Writer, colorize bool) error {
		switch opts.Output {
		case "json":
			// NDJSON (newline-delimited JSON) for batch mode.
			enc := json.NewEncoder(w)
			for _, rep := range reports {
				if err := enc.Encode(rep); err != nil {
					return err
				}
			}
			return nil
		case "sarif":
			// Multi-run SARIF: one run per target in a single document.
			return report.WriteSARIFRuns(reports, w)
		default:
			for _, rep := range reports {
				rep.WriteHumanDossier(w, colorize, opts.Verbose)
			}
			return nil
		}
	}

	if err := write(stdout, humanColorEnabled(opts.Color, stdout)); err != nil {
		fmt.Fprintf(stderr, "error writing %s output: %v\n", opts.Output, err)
		return exitUsage
	}
	if f != nil {
		// Never colorize a file: ANSI escapes in a committed report are noise.
		if err := write(f, false); err != nil {
			fmt.Fprintf(stderr, "error writing %s to --out: %v\n", opts.Output, err)
			return exitUsage
		}
	}

	return exitCodeFor(reports, opts)
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
	applyMinSeverity([]*report.Report{rep}, opts)
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

	return exitCodeFor([]*report.Report{rep}, opts)
}

// exitCode centralizes the two independent reasons a scan should fail a
// pipeline: the run itself errored (handshake failure, etc — always
// visible in CI regardless of --fail-on), or a finding met the configured
// --fail-on severity threshold.
// exitCodeFor implements the documented exit contract.
//
// Errors no longer force a nonzero exit on their own: an auth-gated endpoint
// used to fail a pipeline, which punished the operator for scanning a
// correctly-configured server. Findings gate exit 1 (only at or above
// --fail-on), and a scan that could not complete gets its own code.
func exitCodeFor(reports []*report.Report, opts *Options) int {
	incomplete := false
	tripped := false
	for _, rep := range reports {
		if rep.Status == report.StatusIncomplete {
			incomplete = true
		}
		if opts.failOnSet && rep.MeetsSeverity(opts.failOn) {
			tripped = true
		}
	}
	if tripped {
		return exitFindings
	}
	if incomplete {
		return exitIncomplete
	}
	return exitOK
}

// applyMinSeverity drops findings below the requested floor. This is an output
// filter, not a probe selector: every probe still runs, so the per-probe
// coverage record stays accurate.
func applyMinSeverity(reports []*report.Report, opts *Options) {
	if !opts.minSevSet {
		return
	}
	for _, rep := range reports {
		kept := make([]report.Finding, 0, len(rep.Findings))
		for _, f := range rep.Findings {
			if f.Severity.Rank() >= opts.minSeverity.Rank() {
				kept = append(kept, f)
			}
		}
		rep.Findings = kept
	}
}

func parseFlags(args []string) (*Options, *flag.FlagSet, error) {
	fs := flag.NewFlagSet("reap", flag.ContinueOnError)
	o := &Options{}
	fs.StringVar(&o.Target, "t", "", "target endpoint URL, or a bare host:port with --protocol auto")
	fs.StringVar(&o.Target, "target", "", "target endpoint URL, or a bare host:port with --protocol auto")
	fs.StringVar(&o.TargetsFile, "targets-file", "", "file with one target per line")
	fs.IntVar(&o.Concurrency, "concurrency", 5, "number of concurrent target scans in batch mode")
	fs.StringVar(&o.Protocol, "protocol", "auto", "protocol to probe: auto|mcp (auto runs discovery first, so a bare host:port works)")
	fs.StringVar(&o.Mode, "mode", "scan", "mode to run: scan|discover|full (discover prints fingerprints)")
	fs.BoolVar(&o.NoBanner, "no-banner", false, "suppress startup banner on stderr")
	fs.BoolVar(&o.VersionFlag, "version", false, "print version and exit")
	fs.BoolVar(&o.ListDetectors, "list-detectors", false, "list discovery detectors and exit")
	fs.StringVar(&o.AuthHeader, "auth-header", "", `optional Authorization header value to send, e.g. "Bearer xyz"`)
	fs.DurationVar(&o.Timeout, "timeout", 10*time.Second, "per-request timeout")
	fs.StringVar(&o.TemplatesDir, "templates", embeddedSource, `directory of JSON probe templates ("embedded" for built-ins, empty string to disable)`)
	fs.StringVar(&o.FingerprintsDir, "fingerprints", embeddedSource, `directory of JSON discovery fingerprints ("embedded" for built-ins, empty string to disable)`)
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
	fs.StringVar(&o.MinSeverity, "min-severity", "", "drop findings below this severity from output: info|low|medium|high")
	fs.BoolVar(&o.Stdin, "stdin", false, "read targets from stdin (implied when no other target source is given)")
	fs.Var(&o.Headers, "H", `extra request header, repeatable, e.g. -H "Cookie: a=b"`)
	fs.Var(&o.Headers, "header", "extra request header, repeatable")
	fs.DurationVar(&o.ScanTimeout, "scan-timeout", 0, "total budget for one target's scan (default: 8x --timeout)")
	fs.StringVar(&o.Proxy, "proxy", "", "route all requests through a proxy, e.g. http://127.0.0.1:8080 for Burp")
	fs.BoolVar(&o.Insecure, "insecure", false, "skip TLS certificate verification when connecting to targets")
	fs.StringVar(&o.UserAgent, "user-agent", "", "override the User-Agent sent to targets")
	fs.IntVar(&o.Retries, "retries", 0, "retry attempts after a transport error, 429, or 5xx")
	fs.DurationVar(&o.Delay, "delay", 0, "minimum delay between outbound requests")
	fs.Float64Var(&o.RateLimit, "rate-limit", 0, "maximum outbound requests per second (0 = unlimited)")

	fs.Usage = func() {
		PrintBanner(fs.Output())
		fmt.Fprintln(fs.Output(), "usage: reap -t <url> --authorized [flags]")
		fmt.Fprintln(fs.Output(), "       reap --targets-file <file> --authorized [flags]")
		fmt.Fprintln(fs.Output(), "       cat targets.txt | reap --authorized [flags]")
		fmt.Fprintln(fs.Output(), "\nexit codes: 0 ok, 1 findings at/above --fail-on, 2 usage error, 3 scan incomplete")
		fmt.Fprintln(fs.Output())
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
