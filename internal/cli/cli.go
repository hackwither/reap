// Package cli wires flags, target collection, and the probe pipeline
// together.
//
// It is also the only place that decides which Session implementation a target
// gets, which output format is written, and what the process exit code means.
// Centralizing those three decisions here is deliberate: a probe can't quietly
// change how reap reports or how it exits.
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
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hackwither/reap/internal/discovery"
	"github.com/hackwither/reap/internal/httpx"
	"github.com/hackwither/reap/internal/probe"
	"github.com/hackwither/reap/internal/probe/generic"
	"github.com/hackwither/reap/internal/probe/mcp"
	"github.com/hackwither/reap/internal/probe/transport"
	"github.com/hackwither/reap/internal/report"
	"github.com/hackwither/reap/internal/template"
	"github.com/hackwither/reap/internal/version"
)

// Exit codes. These are part of reap's contract with CI systems, so they are
// named rather than sprinkled as literals.
//
// The important change from earlier versions: a probe or handshake error no
// longer means exit 1. An auth-gated endpoint used to fail a pipeline, which
// punished the operator for scanning a correctly-configured server. Findings
// drive exit 1 (and only above the --fail-on threshold); an incomplete scan
// gets its own code so "we couldn't look" is distinguishable from "we looked
// and it was clean".
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

var (
	validModes    = []string{"scan", "discover", "full"}
	validOutputs  = []string{"text", "json", "sarif"}
	validProtocol = []string{"auto", "mcp"}
)

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

type Options struct {
	Target          string
	TargetsFile     string
	Stdin           bool
	Protocol        string
	Mode            string
	NoBanner        bool
	VersionFlag     bool
	ListDetectors   bool
	AuthHeader      string
	Headers         headerList
	Timeout         time.Duration
	ScanTimeout     time.Duration
	Proxy           string
	Insecure        bool
	UserAgent       string
	Retries         int
	Delay           time.Duration
	RateLimit       float64
	TemplatesDir    string
	FingerprintsDir string
	Output          string
	OutFile         string
	Include         string
	Exclude         string
	MinSeverity     string
	FailOn          string
	ListProbes      bool
	Authorized      bool
	Concurrency     int
	Verbose         bool
	Logger          *log.Logger

	// derived
	client       *httpx.Client
	failOn       report.Severity
	failOnSet    bool
	minSeverity  report.Severity
	minSevSet    bool
	scanBudget   time.Duration
	discoverOnly bool
}

func verboseLog(opts *Options, format string, args ...any) {
	if opts == nil || opts.Logger == nil {
		return
	}
	opts.Logger.Printf(format, args...)
}

// collectTargets gathers targets from -t, --targets-file, and stdin.
//
// stdin is only consulted when the user asked for it, either explicitly with
// --stdin or implicitly by supplying no other target source. reap used to read
// stdin whenever it wasn't a terminal, which meant that any caller handing it
// an open pipe it never wrote to — `foo | reap -t URL`, a CI runner, or
// subprocess.run(stdin=PIPE) — blocked forever with no timeout covering it.
func collectTargets(opts *Options) ([]string, error) {
	var targets []string
	seen := make(map[string]bool)
	add := func(t string) {
		if t == "" || strings.HasPrefix(t, "#") || seen[t] {
			return
		}
		targets = append(targets, t)
		seen[t] = true
	}

	if opts.Target != "" {
		add(opts.Target)
	}

	if opts.TargetsFile != "" {
		data, err := os.ReadFile(opts.TargetsFile)
		if err != nil {
			return nil, fmt.Errorf("error reading --targets-file: %w", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			add(strings.TrimSpace(line))
		}
	}

	if opts.shouldReadStdin() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			add(strings.TrimSpace(scanner.Text()))
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading stdin: %w", err)
		}
	}

	return targets, nil
}

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

func Run(args []string, stdout, stderr *os.File) int {
	opts, fs, err := parseFlags(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	if opts == nil { // -h/--help
		return exitOK
	}
	if opts.VersionFlag {
		fmt.Fprintf(stdout, "reap v%s\n", version.Version)
		return exitOK
	}
	if !opts.NoBanner {
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
	}, version.UserAgent)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}
	opts.client = client

	reg, loadErrs := buildProbeRegistry(opts)
	for _, e := range loadErrs {
		fmt.Fprintf(stderr, "[template load error] %v\n", e)
	}

	if opts.ListProbes {
		for _, p := range reg.All() {
			fmt.Fprintf(stdout, "%-40s protocol=%s\n", p.ID(), p.Protocol())
		}
		return exitOK
	}
	if opts.ListDetectors {
		for _, d := range buildDiscoveryRegistry(opts, stderr).All() {
			fmt.Fprintf(stdout, "%-40s kinds=%v\n", d.ID(), d.Kinds())
		}
		return exitOK
	}

	// Probe selection is validated against what is actually registered. A
	// typo used to silently select zero probes and exit 0, so a CI pipeline
	// with a misspelled --include stayed green forever.
	if err := validateProbeSelection(reg, opts); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}

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
		return runDiscoverMode(targets, opts, stdout, stderr)
	}

	if !opts.Authorized {
		fmt.Fprintln(stderr, "warning: scanning without --authorized; ensure you have permission before using this tool.")
	}

	reports := scanTargets(targets, opts, reg, stderr)
	if code := writeOutput(reports, opts, stdout, stderr); code != exitOK {
		return code
	}
	return exitCodeFor(reports, opts)
}

// validateOptions rejects unusable flag combinations up front, so a typo
// surfaces as a usage error instead of silently changing behaviour.
func validateOptions(opts *Options) error {
	if !contains(validModes, opts.Mode) {
		return fmt.Errorf("invalid --mode %q (want one of: %s)", opts.Mode, strings.Join(validModes, ", "))
	}
	if !contains(validOutputs, opts.Output) {
		return fmt.Errorf("invalid --output %q (want one of: %s)", opts.Output, strings.Join(validOutputs, ", "))
	}
	if !contains(validProtocol, opts.Protocol) {
		return fmt.Errorf("invalid --protocol %q (want one of: %s)", opts.Protocol, strings.Join(validProtocol, ", "))
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
	if opts.FailOn != "" {
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
	opts.discoverOnly = opts.Mode == "discover"

	if opts.ScanTimeout <= 0 {
		// A whole scan used to get --timeout*4 (40s by default) for every
		// probe combined, so a slow target quietly reported no findings. The
		// budget now scales with the per-request timeout instead.
		opts.scanBudget = opts.Timeout * 8
	} else {
		opts.scanBudget = opts.ScanTimeout
	}
	return nil
}

func validateProbeSelection(reg *probe.Registry, opts *Options) error {
	known := map[string]bool{}
	ids := make([]string, 0, len(reg.All()))
	for _, p := range reg.All() {
		known[p.ID()] = true
		ids = append(ids, p.ID())
	}
	sort.Strings(ids)

	for flagName, csv := range map[string]string{"--include": opts.Include, "--exclude": opts.Exclude} {
		for _, id := range splitCSV(csv) {
			if known[id] {
				continue
			}
			msg := fmt.Sprintf("unknown probe ID %q in %s", id, flagName)
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
	lower := strings.ToLower(want)
	trimmed := strings.ReplaceAll(lower, "-", "")
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

func buildProbeRegistry(opts *Options) (*probe.Registry, []error) {
	reg := probe.NewRegistry()
	for _, p := range mcp.BuiltinProbes() {
		reg.Register(p)
	}
	// Protocol-neutral transport checks. Registered with Protocol() == "*" so
	// they run against every protocol reap can identify, including ones with
	// no enumeration probes yet.
	for _, p := range transport.BuiltinProbes(opts.client) {
		reg.Register(p)
	}

	var errs []error
	if opts.TemplatesDir != "" {
		templates, loadErrs := template.LoadDir(opts.TemplatesDir)
		errs = append(errs, loadErrs...)
		for _, t := range templates {
			reg.Register(t.AsProbe())
		}
	}
	return reg, errs
}

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

func (o *Options) detectOptions() discovery.DetectOptions {
	return discovery.DetectOptions{Timeout: o.Timeout, AuthHeader: o.AuthHeader, Client: o.client}
}

func runDiscoverMode(targets []string, opts *Options, stdout, stderr *os.File) int {
	dreg := buildDiscoveryRegistry(opts, stderr)
	enc := json.NewEncoder(stdout)
	for _, t := range targets {
		ctx, cancel := context.WithTimeout(context.Background(), opts.scanBudget)
		fp := discovery.Run(ctx, dreg, classifyCandidate(t), opts.detectOptions())
		cancel()
		if fp == nil {
			_ = enc.Encode(map[string]any{"input": t, "fingerprint": nil})
			continue
		}
		_ = enc.Encode(fp)
	}
	return exitOK
}

// classifyCandidate applies the "is this a full URL or a bare host:port"
// heuristic that discovery needs to build a Candidate.
func classifyCandidate(target string) discovery.Candidate {
	var c discovery.Candidate
	c.RawInput = target
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		c.Kind = discovery.KindURL
		c.URL = target
	} else {
		c.Kind = discovery.KindHostPort
	}
	return c
}

// resolved is what discovery (or the absence of it) tells the scanner about a
// target before any probe runs.
type resolved struct {
	protocol string
	url      string
}

// resolveTarget decides which protocol and URL to scan.
//
// The URL matters as much as the protocol: discovery already worked out that
// "localhost:8080" means "http://localhost:8080/mcp", but that result was
// thrown away and the raw string handed to the session, which then failed with
// `unsupported protocol scheme "localhost"`. Bare host:port is the nmap-shaped
// entry point, so it has to survive the handoff.
func resolveTarget(ctx context.Context, target string, opts *Options, rep *report.Report, stderr *os.File) (resolved, error) {
	hasScheme := strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")

	if opts.Protocol != "auto" {
		if !hasScheme {
			return resolved{}, fmt.Errorf("target %q has no scheme; add http:// or https://, or use --protocol auto to let discovery resolve it", target)
		}
		return resolved{protocol: opts.Protocol, url: target}, nil
	}

	dreg := buildDiscoveryRegistry(opts, stderr)
	fp := discovery.Run(ctx, dreg, classifyCandidate(target), opts.detectOptions())
	if fp == nil {
		rep.Target.DiscoveryMethod = "none"
		verboseLog(opts, "discovery found nothing for %s", target)
		if !hasScheme {
			return resolved{}, fmt.Errorf("discovery found no agent endpoint at %q, and the input has no scheme to fall back on", target)
		}
		// Assume MCP: it's the only protocol with enumeration probes, and a
		// server that refuses discovery may still answer a handshake.
		return resolved{protocol: "mcp", url: target}, nil
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

	url := fp.Candidate.URL
	if url == "" {
		url = target
	}
	verboseLog(opts, "discovery resolved %s as protocol=%s transport=%s url=%s confidence=%s (detector=%s)",
		target, fp.Protocol, fp.Transport, url, fp.Confidence, fp.DetectorID)
	return resolved{protocol: fp.Protocol, url: url}, nil
}

// newSession picks a Session implementation for a protocol.
//
// This is the seam docs/ARCHITECTURE.md promised and cli.go didn't have: it
// used to build an mcp.Session for every target regardless of what discovery
// said, so identifying an A2A or OpenAPI endpoint produced a fingerprint and
// then a failed MCP handshake.
func newSession(protocol, url, authHeader string, client *httpx.Client) probe.Session {
	switch protocol {
	case "mcp":
		return mcp.NewSession(url, authHeader, client)
	default:
		return generic.NewSession(url, authHeader, client)
	}
}

func scanTargets(targets []string, opts *Options, reg *probe.Registry, stderr *os.File) []*report.Report {
	results := make([]*report.Report, len(targets))
	if len(targets) == 1 {
		results[0] = scanTarget(targets[0], opts, reg, stderr)
		return results
	}

	verboseLog(opts, "running batch scan for %d targets (concurrency=%d)", len(targets), opts.Concurrency)
	type job struct {
		idx    int
		target string
	}
	jobs := make(chan job)
	var wg sync.WaitGroup
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				// Distinct slice slots, so no mutex is needed.
				results[j.idx] = scanTarget(j.target, opts, reg, stderr)
			}
		}()
	}
	for i, t := range targets {
		jobs <- job{i, t}
	}
	close(jobs)
	wg.Wait()
	return results
}

// scanTarget runs the full pipeline against one target. This is the single
// scan path; there used to be two near-identical copies, one for the
// single-target case and one for batch.
func scanTarget(target string, opts *Options, reg *probe.Registry, stderr *os.File) *report.Report {
	verboseLog(opts, "scanning %s", target)
	rep := report.New(target, target, opts.Protocol)

	ctx, cancel := context.WithTimeout(context.Background(), opts.scanBudget)
	defer cancel()

	res, err := resolveTarget(ctx, target, opts, rep, stderr)
	if err != nil {
		rep.AddError(err)
		rep.MarkIncomplete(err.Error())
		rep.Target.AuthState = report.AuthStateUnreached
		rep.FinishedAt = time.Now().UTC()
		return rep
	}
	rep.Target.URL = res.url
	rep.Target.Protocol = res.protocol

	sess := newSession(res.protocol, res.url, opts.AuthHeader, opts.client)

	if ms, ok := sess.(*mcp.Session); ok {
		handshake(ctx, ms, rep, opts)
	}

	probes := filterProbes(reg.ForProtocol(res.protocol), opts.Include, opts.Exclude)
	verboseLog(opts, "running %d probes for %s", len(probes), res.url)
	for _, p := range probes {
		if ctx.Err() != nil {
			rep.RecordProbe(p.ID(), report.ProbeAborted, "scan deadline exceeded before this probe ran")
			continue
		}
		runProbe(ctx, p, sess, rep, opts)
	}

	if ctx.Err() != nil {
		rep.MarkIncomplete("scan deadline exceeded")
	}
	rep.FinishedAt = time.Now().UTC()
	return rep
}

// handshake performs the MCP negotiation and records what it learned.
//
// A failed handshake is not automatically an error: a 401 means the endpoint is
// live and gated, which is a recon result. Only a genuine transport or protocol
// failure goes into the report's error list.
func handshake(ctx context.Context, ms *mcp.Session, rep *report.Report, opts *Options) {
	init, raw, err := ms.Initialize(ctx)
	if err != nil {
		if mcp.IsAuthGated(raw) {
			rep.Target.AuthState = report.AuthStateGated
			verboseLog(opts, "initialize is auth-gated: %v", err)
			return
		}
		rep.AddError(fmt.Errorf("initialize handshake failed: %w", err))
		rep.MarkIncomplete("MCP handshake failed")
		rep.Target.AuthState = report.AuthStateUnreached
		verboseLog(opts, "initialize handshake failed: %v", err)
		return
	}
	if init == nil {
		return
	}
	rep.Target.ServerName = init.ServerInfo.Name
	rep.Target.ServerVer = init.ServerInfo.Version
	rep.Target.ProtocolVer = ms.NegotiatedVersion()
	verboseLog(opts, "handshake ok: server=%s version=%s protocol=%s",
		init.ServerInfo.Name, init.ServerInfo.Version, ms.NegotiatedVersion())
}

// runProbe executes one probe and records its outcome.
//
// The three-way distinction is the point. Probes used to return nil both when
// they found nothing and when they couldn't look, so a report full of silence
// was indistinguishable from a clean result.
func runProbe(ctx context.Context, p probe.Probe, sess probe.Session, rep *report.Report, opts *Options) {
	verboseLog(opts, "running probe %s", p.ID())
	err := p.Run(ctx, sess, rep)
	switch {
	case err == nil:
		rep.RecordProbe(p.ID(), report.ProbeRan, "")
		verboseLog(opts, "probe %s ran", p.ID())
	case errors.Is(err, probe.ErrNotApplicable):
		rep.RecordProbe(p.ID(), report.ProbeNotApplicable, err.Error())
		verboseLog(opts, "probe %s not applicable: %v", p.ID(), err)
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		rep.RecordProbe(p.ID(), report.ProbeAborted, err.Error())
		verboseLog(opts, "probe %s aborted: %v", p.ID(), err)
	default:
		rep.RecordProbe(p.ID(), report.ProbeError, err.Error())
		verboseLog(opts, "probe %s failed: %v", p.ID(), err)
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
		if len(inc) > 0 && !contains(inc, p.ID()) {
			continue
		}
		if contains(exc, p.ID()) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// applyMinSeverity drops findings below the requested floor. This is an output
// filter, not a probe selector: every probe still runs, so the per-probe status
// record stays accurate.
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

// writeOutput renders every report in the requested format, to stdout and/or
// --out. Single-target and batch share this path; --out used to be silently
// ignored for batch text output.
func writeOutput(reports []*report.Report, opts *Options, stdout, stderr *os.File) int {
	applyMinSeverity(reports, opts)

	writers := []io.Writer{stdout}
	if opts.OutFile != "" {
		f, err := os.Create(opts.OutFile)
		if err != nil {
			fmt.Fprintf(stderr, "error creating --out file: %v\n", err)
			return exitUsage
		}
		defer f.Close()
		writers = append(writers, f)
	}

	for _, w := range writers {
		if err := renderReports(reports, opts.Output, w); err != nil {
			fmt.Fprintf(stderr, "error writing %s output: %v\n", opts.Output, err)
			return exitUsage
		}
	}
	return exitOK
}

func renderReports(reports []*report.Report, format string, w io.Writer) error {
	switch format {
	case "json":
		// NDJSON for more than one target, so the stream stays greppable.
		if len(reports) == 1 {
			return reports[0].WriteJSON(w)
		}
		enc := json.NewEncoder(w)
		for _, rep := range reports {
			if err := enc.Encode(rep); err != nil {
				return err
			}
		}
		return nil
	case "sarif":
		return report.WriteSARIFRuns(reports, w)
	default:
		for _, rep := range reports {
			rep.WriteHuman(w)
		}
		return nil
	}
}

// exitCodeFor implements the documented exit contract.
func exitCodeFor(reports []*report.Report, opts *Options) int {
	incomplete := false
	worst := report.SeverityInfo
	any := false
	for _, rep := range reports {
		if rep.Status == report.StatusIncomplete {
			incomplete = true
		}
		if sev, ok := rep.MaxSeverity(); ok {
			any = true
			if sev.Rank() > worst.Rank() {
				worst = sev
			}
		}
	}

	if opts.failOnSet && any && worst.Rank() >= opts.failOn.Rank() {
		return exitFindings
	}
	if incomplete {
		return exitIncomplete
	}
	return exitOK
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func parseFlags(args []string) (*Options, *flag.FlagSet, error) {
	fs := flag.NewFlagSet("reap", flag.ContinueOnError)
	o := &Options{}

	fs.StringVar(&o.Target, "t", "", "target endpoint URL, or bare host:port with --protocol auto")
	fs.StringVar(&o.Target, "target", "", "target endpoint URL, or bare host:port with --protocol auto")
	fs.StringVar(&o.TargetsFile, "targets-file", "", "file with one target per line")
	fs.BoolVar(&o.Stdin, "stdin", false, "read targets from stdin (implied when no other target source is given)")
	fs.IntVar(&o.Concurrency, "concurrency", 5, "number of concurrent target scans in batch mode")
	fs.StringVar(&o.Protocol, "protocol", "auto", "protocol to probe: auto|mcp (auto runs discovery first)")
	fs.StringVar(&o.Mode, "mode", "scan", "mode to run: scan|discover|full (discover prints fingerprints; full implies --protocol auto)")
	fs.BoolVar(&o.NoBanner, "no-banner", false, "suppress startup banner on stderr")
	fs.BoolVar(&o.VersionFlag, "version", false, "print version and exit")
	fs.BoolVar(&o.ListDetectors, "list-detectors", false, "list discovery detectors and exit")
	fs.BoolVar(&o.ListProbes, "list-probes", false, "list all registered probe IDs and exit")

	fs.StringVar(&o.AuthHeader, "auth-header", "", `Authorization header value to send, e.g. "Bearer xyz"`)
	fs.Var(&o.Headers, "H", `extra request header, repeatable, e.g. -H "Cookie: a=b"`)
	fs.Var(&o.Headers, "header", `extra request header, repeatable`)

	fs.DurationVar(&o.Timeout, "timeout", 10*time.Second, "per-request timeout")
	fs.DurationVar(&o.ScanTimeout, "scan-timeout", 0, "total budget for one target's scan (default: 8x --timeout)")
	fs.StringVar(&o.Proxy, "proxy", "", "route all requests through a proxy, e.g. http://127.0.0.1:8080 for Burp")
	fs.BoolVar(&o.Insecure, "insecure", false, "skip TLS certificate verification when connecting to targets")
	fs.StringVar(&o.UserAgent, "user-agent", "", "override the User-Agent sent to targets")
	fs.IntVar(&o.Retries, "retries", 0, "retry attempts after a transport error, 429, or 5xx")
	fs.DurationVar(&o.Delay, "delay", 0, "minimum delay between outbound requests")
	fs.Float64Var(&o.RateLimit, "rate-limit", 0, "maximum outbound requests per second (0 = unlimited)")

	fs.StringVar(&o.TemplatesDir, "templates", "templates", "directory of JSON probe templates (empty string to disable)")
	fs.StringVar(&o.FingerprintsDir, "fingerprints", "fingerprints", "directory of JSON discovery fingerprints (empty string to disable)")

	fs.StringVar(&o.Output, "output", "text", "output format: text|json|sarif (JSON is NDJSON for multiple targets)")
	fs.StringVar(&o.OutFile, "out", "", "also write the report to this file")
	fs.StringVar(&o.Include, "include", "", "comma-separated probe IDs to run (default: all)")
	fs.StringVar(&o.Exclude, "exclude", "", "comma-separated probe IDs to skip")
	fs.StringVar(&o.MinSeverity, "min-severity", "", "drop findings below this severity from output: info|low|medium|high")
	fs.StringVar(&o.FailOn, "fail-on", "", "exit 1 when a finding at or above this severity is reported: info|low|medium|high")

	fs.BoolVar(&o.Verbose, "v", false, "verbose output")
	fs.BoolVar(&o.Verbose, "verbose", false, "verbose output")
	fs.BoolVar(&o.Authorized, "authorized", false, "confirm you own or are explicitly authorized to test the target(s)")

	fs.Usage = func() {
		PrintBanner(fs.Output())
		fmt.Fprintln(fs.Output(), "usage: reap -t <url|host:port> --authorized [flags]")
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
	return o, fs, nil
}
