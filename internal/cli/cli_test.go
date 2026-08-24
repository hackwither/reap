package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hackwither/reap/internal/report"
	"github.com/hackwither/reap/internal/version"
)

// --- target collection --------------------------------------------------

func TestCollectTargets_FileOnly(t *testing.T) {
	fileContent := "https://one.example.com/mcp\n# comment\nhttps://two.example.com/mcp\n"
	filePath := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(filePath, []byte(fileContent), 0o600); err != nil {
		t.Fatal(err)
	}

	targets, err := collectTargets(&Options{TargetsFile: filePath})
	if err != nil {
		t.Fatalf("collectTargets failed: %v", err)
	}
	want := []string{"https://one.example.com/mcp", "https://two.example.com/mcp"}
	if strings.Join(targets, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", targets, want)
	}
}

func TestCollectTargets_StdinWhenNoOtherSource(t *testing.T) {
	withStdin(t, "https://three.example.com/mcp\n", func() {
		targets, err := collectTargets(&Options{})
		if err != nil {
			t.Fatalf("collectTargets failed: %v", err)
		}
		if len(targets) != 1 || targets[0] != "https://three.example.com/mcp" {
			t.Fatalf("expected the stdin target, got %v", targets)
		}
	})
}

// TestCollectTargets_DoesNotBlockOnStdinWhenTargetGiven is the regression test
// for reap's worst reliability bug: it read stdin whenever stdin was not a
// character device, even with -t supplied. Any caller that handed it an open
// pipe it never wrote to — `slow | reap -t URL`, a CI runner, or
// subprocess.run(stdin=PIPE) — hung forever, with no timeout covering it.
func TestCollectTargets_DoesNotBlockOnStdinWhenTargetGiven(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately never written to and never closed, which is exactly the
	// shape of a wrapper's idle stdin pipe.
	defer func() { _ = r.Close(); _ = w.Close() }()

	orig := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = orig }()

	done := make(chan []string, 1)
	go func() {
		targets, err := collectTargets(&Options{Target: "https://example.com/mcp"})
		if err != nil {
			t.Errorf("collectTargets failed: %v", err)
		}
		done <- targets
	}()

	select {
	case targets := <-done:
		if len(targets) != 1 || targets[0] != "https://example.com/mcp" {
			t.Fatalf("expected only the -t target, got %v", targets)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("collectTargets blocked on an open stdin pipe despite -t being set")
	}
}

func TestCollectTargets_StdinFlagIsExplicitOptIn(t *testing.T) {
	withStdin(t, "https://piped.example.com/mcp\n", func() {
		targets, err := collectTargets(&Options{Target: "https://flag.example.com/mcp", Stdin: true})
		if err != nil {
			t.Fatalf("collectTargets failed: %v", err)
		}
		if len(targets) != 2 {
			t.Fatalf("expected --stdin to merge both sources, got %v", targets)
		}
	})
}

// withStdin replaces os.Stdin with a pipe containing content, already closed
// so a read terminates.
func withStdin(t *testing.T, content string, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(content); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()

	orig := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = orig; _ = r.Close() }()
	fn()
}

// --- flag validation ----------------------------------------------------

func TestParseFlags_NoScopeFileFlag(t *testing.T) {
	if _, _, err := parseFlags([]string{"--scope-file", "foo"}); err == nil {
		t.Fatal("expected parseFlags to error on removed --scope-file flag")
	}
}

func TestParseFlags_Verbose(t *testing.T) {
	opts, _, err := parseFlags([]string{"-v", "--target", "https://example.com/mcp"})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if opts == nil || !opts.Verbose {
		t.Fatal("expected verbose enabled for -v")
	}
}

func TestParseFlags_RepeatableHeaders(t *testing.T) {
	opts, _, err := parseFlags([]string{"-H", "Cookie: a=b", "-H", "X-Trace: 1"})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if got := opts.Headers.values["Cookie"]; got != "a=b" {
		t.Fatalf("Cookie header: got %q", got)
	}
	if got := opts.Headers.values["X-Trace"]; got != "1" {
		t.Fatalf("X-Trace header: got %q", got)
	}
}

func TestParseFlags_MalformedHeaderIsUsageError(t *testing.T) {
	if _, _, err := parseFlags([]string{"-H", "no-colon-here"}); err == nil {
		t.Fatal("expected a malformed -H value to be a usage error")
	}
}

func TestValidateOptions_RejectsBadEnums(t *testing.T) {
	for name, opts := range map[string]*Options{
		"mode":     {Mode: "discovery", Output: "text", Protocol: "auto", Timeout: time.Second, Concurrency: 1},
		"output":   {Mode: "scan", Output: "yaml", Protocol: "auto", Timeout: time.Second, Concurrency: 1},
		"protocol": {Mode: "scan", Output: "text", Protocol: "a2a", Timeout: time.Second, Concurrency: 1},
		"fail-on":  {Mode: "scan", Output: "text", Protocol: "auto", Timeout: time.Second, Concurrency: 1, FailOn: "critical"},
	} {
		if err := validateOptions(opts); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestValidateOptions_FullModeImpliesAuto(t *testing.T) {
	opts := &Options{Mode: "full", Output: "text", Protocol: "mcp", Timeout: time.Second, Concurrency: 1}
	if err := validateOptions(opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Protocol != "auto" {
		t.Fatalf("--mode full must imply --protocol auto, got %q", opts.Protocol)
	}
}

// TestRun_UnknownIncludeIsUsageError guards against the silent-green failure:
// a mistyped --include used to select zero probes, emit an empty report, and
// exit 0, so a CI pipeline could pass forever without running a single check.
func TestRun_UnknownIncludeIsUsageError(t *testing.T) {
	code, _, stderr := runCapturingOutput(t, []string{
		"--no-banner", "--authorized", "--templates", "",
		"-t", "https://example.com/mcp",
		"--include", "mcp-unauth-toolslist",
	})
	if code != exitUsage {
		t.Fatalf("expected exit %d for an unknown probe ID, got %d", exitUsage, code)
	}
	if !strings.Contains(stderr, "unknown probe ID") {
		t.Fatalf("expected an explanatory error, got: %s", stderr)
	}
	// The suggestion matters: the whole point is that the operator notices.
	if !strings.Contains(stderr, "mcp-unauth-tools-list") {
		t.Fatalf("expected a near-match suggestion, got: %s", stderr)
	}
}

// --- output and exit codes ----------------------------------------------

func runCapturingOutput(t *testing.T, args []string) (code int, stdout, stderr string) {
	t.Helper()

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	// Read concurrently: a scan can emit more than a pipe buffer holds.
	var outBuf, errBuf bytes.Buffer
	outDone := make(chan struct{})
	errDone := make(chan struct{})
	go func() { _, _ = outBuf.ReadFrom(outR); close(outDone) }()
	go func() { _, _ = errBuf.ReadFrom(errR); close(errDone) }()

	code = Run(args, outW, errW)
	outW.Close()
	errW.Close()
	<-outDone
	<-errDone
	return code, outBuf.String(), errBuf.String()
}

func TestRun_HelpFlagExitsZero(t *testing.T) {
	for _, flag := range []string{"-h", "--help"} {
		code, _, _ := runCapturingOutput(t, []string{flag})
		if code != exitOK {
			t.Fatalf("%s: expected exit code 0, got %d", flag, code)
		}
	}
}

func TestParseFlags_HelpUsageIncludesBannerWordmark(t *testing.T) {
	// -h/--help routes through fs.Usage(), which writes to fs.Output() rather
	// than the stdout/stderr passed into Run, so capture it directly.
	for _, flag := range []string{"-h", "--help"} {
		opts, fs, err := parseFlags([]string{flag})
		if err != nil {
			t.Fatalf("%s: unexpected parse error: %v", flag, err)
		}
		if opts != nil {
			t.Fatalf("%s: expected nil opts for help flag", flag)
		}
		var buf bytes.Buffer
		fs.SetOutput(&buf)
		fs.Usage()
		out := buf.String()
		for _, want := range []string{"Reconnaissance and Enumeration for Agent Protocols", "@hackwither", "exit codes:"} {
			if !strings.Contains(out, want) {
				t.Fatalf("%s: expected usage output to include %q, got: %s", flag, want, out)
			}
		}
	}
}

func TestRun_NoBannerSuppressesBanner(t *testing.T) {
	_, _, withBanner := runCapturingOutput(t, []string{"--list-detectors"})
	if !strings.Contains(withBanner, "Reconnaissance and Enumeration for Agent Protocols") {
		t.Fatalf("expected banner on stderr by default, got: %s", withBanner)
	}
	_, _, noBanner := runCapturingOutput(t, []string{"--list-detectors", "--no-banner"})
	if strings.Contains(noBanner, "Reconnaissance and Enumeration for Agent Protocols") {
		t.Fatalf("expected --no-banner to suppress banner, got: %s", noBanner)
	}
}

func TestRun_VersionFlag(t *testing.T) {
	code, stdout, stderr := runCapturingOutput(t, []string{"--version"})
	if code != exitOK {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout, "reap v"+version.Version) {
		t.Fatalf("expected stdout to contain version string, got: %s", stdout)
	}
	if strings.Contains(stderr, "Reconnaissance and Enumeration for Agent Protocols") {
		t.Fatalf("expected --version to skip the banner, got stderr: %s", stderr)
	}
}

func TestRun_ListProbes_IncludesNeutralTransportChecks(t *testing.T) {
	code, stdout, _ := runCapturingOutput(t, []string{"--list-probes", "--no-banner", "--templates", ""})
	if code != exitOK {
		t.Fatalf("expected exit 0, got %d", code)
	}
	// The renamed, protocol-neutral checks must be registered for "*", which
	// is what lets them run against a non-MCP target.
	for _, want := range []string{
		"transport-plaintext", "transport-downgrade", "tls-cert-health",
		"http-cors-wildcard", "http-rate-limit-absence",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("expected %s in --list-probes output", want)
		}
	}
	if strings.Contains(stdout, "mcp-plaintext-transport") {
		t.Error("old mcp- prefixed transport ID should be gone")
	}
	if !strings.Contains(stdout, "protocol=*") {
		t.Error("expected at least one probe registered for all protocols")
	}
}

// mockMCPServer is an open, insecure MCP endpoint: enough surface to drive the
// end-to-end CLI assertions without reaching the network.
func mockMCPServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID     *int   `json:"id"`
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)

		if body.Method == "notifications/initialized" {
			w.WriteHeader(http.StatusAccepted)
			return
		}

		var result any
		switch body.Method {
		case "initialize":
			result = map[string]any{
				"protocolVersion": "2025-06-18",
				"serverInfo":      map[string]any{"name": "mock-gateway", "version": "0.9.0"},
				"capabilities":    map[string]any{"tools": map[string]any{}},
			}
		case "tools/list":
			result = map[string]any{"tools": []map[string]any{{"name": "exec_shell"}}}
		default:
			result = map[string]any{}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": body.ID, "result": result})
	}))
}

func TestRun_ProtocolAutoUsesDiscoveryAndScansResolvedURL(t *testing.T) {
	srv := mockMCPServer(t)
	defer srv.Close()

	code, stdout, stderr := runCapturingOutput(t, []string{
		"--protocol", "auto", "--authorized", "-t", srv.URL,
		"--templates", "", "--fingerprints", filepath.Join("..", "..", "fingerprints"),
		"--no-banner", "--output", "json",
	})
	if code != exitOK {
		t.Fatalf("expected exit 0, got %d; stderr: %s", code, stderr)
	}

	var rep report.Report
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("failed to decode report JSON: %v; stdout: %s", err, stdout)
	}
	if rep.Target.Protocol != "mcp" {
		t.Fatalf("expected protocol=mcp, got %q", rep.Target.Protocol)
	}
	if rep.Target.DiscoveryMethod != "mcp-http-streamable" {
		t.Fatalf("expected discovery_method=mcp-http-streamable, got %q", rep.Target.DiscoveryMethod)
	}
	if rep.Target.ServerName != "mock-gateway" {
		t.Fatalf("expected server_name from the handshake, got %q", rep.Target.ServerName)
	}
	if rep.Target.AuthState != report.AuthStateOpen {
		t.Fatalf("expected auth_state=open, got %q", rep.Target.AuthState)
	}
	if rep.Target.Capabilities == nil || rep.Target.Capabilities.Tools != 1 {
		t.Fatalf("expected the capability summary to record 1 tool, got %+v", rep.Target.Capabilities)
	}
	if rep.Status != report.StatusComplete {
		t.Fatalf("expected a complete scan, got %q (%s)", rep.Status, rep.IncompleteReason)
	}
	if len(rep.Probes) == 0 {
		t.Fatal("expected per-probe status records")
	}
}

// TestRun_EmptyFindingsSerializeAsArray guards the JSON contract: reap used to
// emit "findings": null, which breaks jq pipelines and any consumer that
// iterates the field.
func TestRun_EmptyFindingsSerializeAsArray(t *testing.T) {
	srv := mockMCPServer(t)
	defer srv.Close()

	_, stdout, _ := runCapturingOutput(t, []string{
		"--authorized", "-t", srv.URL, "--protocol", "mcp",
		"--templates", "", "--fingerprints", "", "--no-banner",
		"--output", "json", "--include", "mcp-instructions-exposure",
	})
	if !strings.Contains(stdout, `"findings": []`) {
		t.Fatalf(`expected "findings": [] in output, got: %s`, stdout)
	}
	if strings.Contains(stdout, `"findings": null`) {
		t.Fatal(`findings must never serialize as null`)
	}
}

func TestRun_FailOnGatesExitCode(t *testing.T) {
	srv := mockMCPServer(t)
	defer srv.Close()

	base := []string{
		"--authorized", "-t", srv.URL, "--protocol", "mcp",
		"--templates", "", "--fingerprints", "", "--no-banner", "--output", "json",
	}

	// Without --fail-on, findings never affect the exit code.
	if code, _, _ := runCapturingOutput(t, base); code != exitOK {
		t.Fatalf("expected exit 0 without --fail-on, got %d", code)
	}
	// The mock leaks tools/list anonymously with an exec-flavoured name, so a
	// high-severity finding exists to trip the gate.
	if code, _, _ := runCapturingOutput(t, append(base, "--fail-on", "high")); code != exitFindings {
		t.Fatalf("expected exit %d with --fail-on high, got %d", exitFindings, code)
	}
}

// TestRun_UnreachableTargetIsIncompleteNotClean covers the evidence-integrity
// rule: a target reap could not reach must never look like a clean one.
func TestRun_UnreachableTargetIsIncompleteNotClean(t *testing.T) {
	srv := mockMCPServer(t)
	url := srv.URL
	srv.Close() // nothing is listening now

	code, stdout, _ := runCapturingOutput(t, []string{
		"--authorized", "-t", url, "--protocol", "mcp",
		"--templates", "", "--fingerprints", "", "--no-banner", "--output", "json",
	})
	if code != exitIncomplete {
		t.Fatalf("expected exit %d for an unreachable target, got %d", exitIncomplete, code)
	}
	var rep report.Report
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("decode report: %v; stdout: %s", err, stdout)
	}
	if rep.Status != report.StatusIncomplete {
		t.Fatalf("expected status=incomplete, got %q", rep.Status)
	}
	if rep.Target.AuthState != report.AuthStateUnreached {
		t.Fatalf("expected auth_state=unreached, got %q", rep.Target.AuthState)
	}
}

// TestRun_OutFileWrittenForTextOutput covers a silent data-loss bug: --out
// created the file but wrote nothing to it for text output in batch mode.
func TestRun_OutFileWrittenForTextOutput(t *testing.T) {
	srv := mockMCPServer(t)
	defer srv.Close()

	targetsFile := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(targetsFile, []byte(srv.URL+"\n"+srv.URL+"/mcp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(t.TempDir(), "report.txt")

	runCapturingOutput(t, []string{
		"--authorized", "--targets-file", targetsFile, "--protocol", "mcp",
		"--templates", "", "--fingerprints", "", "--no-banner",
		"--out", outFile, "--concurrency", "2",
	})

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading --out file: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("--out file is empty for text output")
	}
	if !strings.Contains(string(data), "AI AGENT RECON") {
		t.Fatalf("--out file does not contain a report: %s", data)
	}
	// A file report must not carry terminal escape sequences.
	if strings.Contains(string(data), "\x1b[") {
		t.Fatal("--out file contains ANSI colour escapes")
	}
}

func TestRun_MinSeverityFiltersOutput(t *testing.T) {
	srv := mockMCPServer(t)
	defer srv.Close()

	_, stdout, _ := runCapturingOutput(t, []string{
		"--authorized", "-t", srv.URL, "--protocol", "mcp",
		"--templates", "", "--fingerprints", "", "--no-banner",
		"--output", "json", "--min-severity", "high",
	})
	var rep report.Report
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	for _, f := range rep.Findings {
		if f.Severity != report.SeverityHigh {
			t.Fatalf("--min-severity high let through %s (%s)", f.ID, f.Severity)
		}
	}
	// Probe records must survive the filter, since they describe coverage
	// rather than findings.
	if len(rep.Probes) == 0 {
		t.Fatal("expected probe records to be unaffected by --min-severity")
	}
}
func TestRun_BareOriginResolvesToRealEndpointPath(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // root is NOT an MCP endpoint
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID int `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      body.ID,
			"result": map[string]any{
				"protocolVersion": "2025-06-18",
				"serverInfo":      map[string]any{"name": "bare-origin-gateway", "version": "1.0"},
				"capabilities":    map[string]any{},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	fingerprintsDir := filepath.Join("..", "..", "fingerprints")
	code := Run([]string{
		"--protocol", "auto",
		"--authorized",
		"-t", srv.URL, // bare origin — httptest.NewServer's URL has no path
		"--templates", "",
		"--fingerprints", fingerprintsDir,
		"--no-banner",
		"--output", "json",
		"--timeout", "3s",
	}, outW, errW)

	outW.Close()
	errW.Close()
	var outBuf, errBuf bytes.Buffer
	if _, err := outBuf.ReadFrom(outR); err != nil {
		t.Fatal(err)
	}
	if _, err := errBuf.ReadFrom(errR); err != nil {
		t.Fatal(err)
	}

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d; stderr: %s", code, errBuf.String())
	}

	var rep report.Report
	if err := json.Unmarshal(outBuf.Bytes(), &rep); err != nil {
		t.Fatalf("failed to decode report JSON: %v; stdout: %s", err, outBuf.String())
	}
	if rep.Target.URL != srv.URL+"/mcp" {
		t.Fatalf("expected the report to reflect the resolved endpoint %s/mcp, got %q — discovery found it but the scan still hit the wrong URL", srv.URL, rep.Target.URL)
	}
	if !rep.Target.Confirmed {
		t.Fatalf("expected the handshake against the resolved endpoint to succeed, got Confirmed=false, reason=%q", rep.Target.ConfirmReason)
	}
	if rep.Target.ServerName != "bare-origin-gateway" {
		t.Fatalf("expected server_name from the real /mcp endpoint, got %q", rep.Target.ServerName)
	}
}

func TestRun_BareOriginResolvesUnderStaticProtocol(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID int `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      body.ID,
			"result": map[string]any{
				"protocolVersion": "2025-06-18",
				"serverInfo":      map[string]any{"name": "static-protocol-gateway", "version": "1.0"},
				"capabilities":    map[string]any{},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	fingerprintsDir := filepath.Join("..", "..", "fingerprints")
	code := Run([]string{
		// no --protocol flag at all: exercises the default "mcp" static path
		"--authorized",
		"-t", srv.URL,
		"--templates", "",
		"--fingerprints", fingerprintsDir,
		"--no-banner",
		"--output", "json",
		"--timeout", "3s",
	}, outW, errW)

	outW.Close()
	errW.Close()
	var outBuf, errBuf bytes.Buffer
	if _, err := outBuf.ReadFrom(outR); err != nil {
		t.Fatal(err)
	}
	if _, err := errBuf.ReadFrom(errR); err != nil {
		t.Fatal(err)
	}

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d; stderr: %s", code, errBuf.String())
	}

	var rep report.Report
	if err := json.Unmarshal(outBuf.Bytes(), &rep); err != nil {
		t.Fatalf("failed to decode report JSON: %v; stdout: %s", err, outBuf.String())
	}
	if rep.Target.URL != srv.URL+"/mcp" {
		t.Fatalf("expected the report to reflect the resolved endpoint %s/mcp under static --protocol=mcp, got %q", srv.URL, rep.Target.URL)
	}
	if !rep.Target.Confirmed {
		t.Fatalf("expected the handshake against the resolved endpoint to succeed, got Confirmed=false, reason=%q", rep.Target.ConfirmReason)
	}
}

func TestParseFlags_Color(t *testing.T) {
	for _, mode := range []string{"auto", "always", "never"} {
		opts, _, err := parseFlags([]string{"--color", mode})
		if err != nil {
			t.Fatalf("--color %s: %v", mode, err)
		}
		if opts.Color != mode {
			t.Fatalf("--color %s parsed as %q", mode, opts.Color)
		}
	}
	if _, _, err := parseFlags([]string{"--color", "sometimes"}); err == nil {
		t.Fatal("expected invalid --color value to fail")
	}
}

func TestHumanColorEnabled(t *testing.T) {
	output, err := os.CreateTemp(t.TempDir(), "report")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()

	if humanColorEnabled("auto", output) {
		t.Fatal("auto color must be disabled for redirected output")
	}
	if !humanColorEnabled("always", output) {
		t.Fatal("always must enable color for redirected output")
	}
	if humanColorEnabled("never", output) {
		t.Fatal("never must disable color")
	}
}
