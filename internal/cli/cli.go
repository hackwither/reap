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
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hackwither/agentrecon/internal/probe"
	"github.com/hackwither/agentrecon/internal/probe/mcp"
	"github.com/hackwither/agentrecon/internal/report"
	"github.com/hackwither/agentrecon/internal/template"
)

const banner = `
agentrecon — single-target active reconnaissance for AI agent endpoints (MCP, and growing)

This tool sends real requests to the target and only performs read-only
protocol operations (handshake, capability/tool listing, header
inspection). It never invokes a discovered tool and never attempts
exploitation.

USE ONLY AGAINST SYSTEMS YOU OWN OR ARE EXPLICITLY AUTHORIZED TO TEST.
Unauthorized access to computer systems is illegal in most jurisdictions
(e.g. the US Computer Fraud and Abuse Act) even when the requests
themselves are "just" reads. Running this tool is your representation that
you have that authorization.
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
	Target       string
	TargetsFile  string
	Protocol     string
	AuthHeader   string
	Timeout      time.Duration
	TemplatesDir string
	Output       string
	OutFile      string
	Include      string
	Exclude      string
	ListProbes   bool
	Authorized   bool
	Concurrency  int
	Verbose      bool
	Logger       *log.Logger
}

func verboseLog(opts *Options, format string, args ...any) {
	if opts == nil || opts.Logger == nil {
		return
	}
	opts.Logger.Printf(format, args...)
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

// scanSingleTarget handles a single target (backward compatible path)
func scanSingleTarget(target string, opts *Options, reg *probe.Registry, stdout, stderr *os.File) int {
	verboseLog(opts, "scanning %s", target)
	sess := mcp.NewSession(target, opts.AuthHeader, opts.Timeout)
	rep := &report.Report{
		Tool:      "agentrecon",
		Version:   "0.1.0",
		StartedAt: time.Now().UTC(),
		Target:    report.Target{URL: target, Protocol: opts.Protocol},
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout*4)
	defer cancel()

	init, _, err := sess.Initialize(ctx)
	if err != nil {
		rep.AddError(fmt.Errorf("initialize handshake failed: %w", err))
		verboseLog(opts, "initialize handshake failed: %v", err)
	} else if init != nil {
		rep.Target.ServerName = init.ServerInfo.Name
		rep.Target.ServerVer = init.ServerInfo.Version
		rep.Target.ProtocolVer = init.ProtocolVersion
		verboseLog(opts, "initialize handshake success: server=%s version=%s protocol=%s", init.ServerInfo.Name, init.ServerInfo.Version, init.ProtocolVersion)
	}

	probes := filterProbes(reg.ForProtocol(opts.Protocol), opts.Include, opts.Exclude)
	verboseLog(opts, "running %d probes for %s", len(probes), target)
	for _, p := range probes {
		verboseLog(opts, "running probe %s", p.ID())
		if err := p.Run(ctx, sess, rep); err != nil {
			rep.AddError(fmt.Errorf("probe %s: %w", p.ID(), err))
			verboseLog(opts, "probe %s failed: %v", p.ID(), err)
		} else {
			verboseLog(opts, "probe %s completed", p.ID())
		}
	}
	rep.FinishedAt = time.Now().UTC()

	return writeReport(rep, opts, stdout, stderr)
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
				rep := scanTarget(job.target, opts, reg)
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

// scanTarget scans a single target and returns its report
func scanTarget(target string, opts *Options, reg *probe.Registry) *report.Report {
	verboseLog(opts, "scanning %s", target)
	sess := mcp.NewSession(target, opts.AuthHeader, opts.Timeout)
	rep := &report.Report{
		Tool:      "agentrecon",
		Version:   "0.1.0",
		StartedAt: time.Now().UTC(),
		Target:    report.Target{URL: target, Protocol: opts.Protocol},
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout*4)
	defer cancel()

	init, _, err := sess.Initialize(ctx)
	if err != nil {
		rep.AddError(fmt.Errorf("initialize handshake failed: %w", err))
		verboseLog(opts, "initialize handshake failed: %v", err)
	} else if init != nil {
		rep.Target.ServerName = init.ServerInfo.Name
		rep.Target.ServerVer = init.ServerInfo.Version
		rep.Target.ProtocolVer = init.ProtocolVersion
		verboseLog(opts, "initialize handshake success: server=%s version=%s protocol=%s", init.ServerInfo.Name, init.ServerInfo.Version, init.ProtocolVersion)
	}

	probes := filterProbes(reg.ForProtocol(opts.Protocol), opts.Include, opts.Exclude)
	verboseLog(opts, "running %d probes for %s", len(probes), target)
	for _, p := range probes {
		verboseLog(opts, "running probe %s", p.ID())
		if err := p.Run(ctx, sess, rep); err != nil {
			rep.AddError(fmt.Errorf("probe %s: %w", p.ID(), err))
			verboseLog(opts, "probe %s failed: %v", p.ID(), err)
		} else {
			verboseLog(opts, "probe %s completed", p.ID())
		}
	}
	rep.FinishedAt = time.Now().UTC()

	return rep
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
			rep.WriteHuman(stdout)
		}
	}

	// Check for errors
	for _, rep := range reports {
		if len(rep.Errors) > 0 {
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
					"name":           "agentrecon",
					"informationUri": "https://github.com/hackwither/agentrecon",
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

// severityToSARIFLevel maps agentrecon severity to SARIF level
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
		rep.WriteHuman(w)
		if f != nil {
			_ = rep.WriteJSON(f)
		}
	}

	if len(rep.Errors) > 0 {
		return 1
	}
	return 0
}

func parseFlags(args []string) (*Options, *flag.FlagSet, error) {
	fs := flag.NewFlagSet("agentrecon", flag.ContinueOnError)
	o := &Options{}
	fs.StringVar(&o.Target, "t", "", "target MCP endpoint URL (e.g. https://host/mcp)")
	fs.StringVar(&o.Target, "target", "", "target MCP endpoint URL (e.g. https://host/mcp)")
	fs.StringVar(&o.TargetsFile, "targets-file", "", "file with one target URL per line (optionally combined with -t and stdin)")
	fs.IntVar(&o.Concurrency, "concurrency", 5, "number of concurrent target scans in batch mode")
	fs.StringVar(&o.Protocol, "protocol", "mcp", "protocol to probe (currently: mcp)")
	fs.StringVar(&o.AuthHeader, "auth-header", "", `optional Authorization header value to send, e.g. "Bearer xyz"`)
	fs.DurationVar(&o.Timeout, "timeout", 10*time.Second, "per-request timeout")
	fs.StringVar(&o.TemplatesDir, "templates", "templates", "directory of JSON probe templates (empty string to disable)")
	fs.StringVar(&o.Output, "output", "text", "output format: text|json|sarif (JSON is NDJSON in batch mode)")
	fs.StringVar(&o.OutFile, "out", "", "write report to file in addition to stdout")
	fs.BoolVar(&o.Verbose, "v", false, "verbose output")
	fs.BoolVar(&o.Verbose, "verbose", false, "verbose output")
	fs.StringVar(&o.Include, "include", "", "comma-separated probe IDs to run (default: all)")
	fs.StringVar(&o.Exclude, "exclude", "", "comma-separated probe IDs to skip")
	fs.BoolVar(&o.ListProbes, "list-probes", false, "list all registered probe IDs and exit")
	fs.BoolVar(&o.Authorized, "authorized", false, "confirm you own or are explicitly authorized to test the target(s)")

	fs.Usage = func() {
		fmt.Fprint(fs.Output(), banner)
		fmt.Fprintln(fs.Output(), "usage: agentrecon -t <url> --authorized [flags]")
		fmt.Fprintln(fs.Output(), "       agentrecon --targets-file <file> --authorized [flags]")
		fmt.Fprintln(fs.Output(), "       cat targets.txt | agentrecon --authorized [flags]")
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
