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

	"github.com/hackwither/reap/internal/report"
)

func TestCollectTargets_FileAndStdin(t *testing.T) {
	fileContent := "https://one.example.com/mcp\n# comment\nhttps://two.example.com/mcp\n"
	filePath := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(filePath, []byte(fileContent), 0o600); err != nil {
		t.Fatal(err)
	}

	origStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close(); os.Stdin = origStdin }()
	os.Stdin = r
	_, _ = w.WriteString("https://three.example.com/mcp\n")
	_ = w.Close()

	targets, err := collectTargets(&Options{TargetsFile: filePath}, os.Stdout)
	if err != nil {
		t.Fatalf("collectTargets failed: %v", err)
	}
	if len(targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(targets))
	}
	if targets[0] != "https://one.example.com/mcp" || targets[1] != "https://two.example.com/mcp" || targets[2] != "https://three.example.com/mcp" {
		t.Fatalf("unexpected targets: %v", targets)
	}
}

func TestParseFlags_NoScopeFileFlag(t *testing.T) {
	_, _, err := parseFlags([]string{"--scope-file", "foo"})
	if err == nil {
		t.Fatal("expected parseFlags to error on removed --scope-file flag")
	}
}

func TestRun_UnauthorizedBatchRefusesBeforeNetwork(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(filePath, []byte("https://example.com/mcp\nhttps://example.org/mcp\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout := os.NewFile(uintptr(1), "/dev/null")
	stderr := os.NewFile(uintptr(2), "/dev/null")
	code := Run([]string{"--targets-file", filePath}, stdout, stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 for unauthorized batch run, got %d", code)
	}
}

// runCapturingOutput runs Run(args, ...) with real os.Pipe()s for stdout and
// stderr so output written through the *os.File parameters (banner, version,
// --list-detectors) can be asserted on directly.
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

	code = Run(args, outW, errW)

	outW.Close()
	errW.Close()

	var outBuf, errBuf bytes.Buffer
	if _, err := outBuf.ReadFrom(outR); err != nil {
		t.Fatal(err)
	}
	if _, err := errBuf.ReadFrom(errR); err != nil {
		t.Fatal(err)
	}
	return code, outBuf.String(), errBuf.String()
}

func TestRun_HelpFlagExitsZero(t *testing.T) {
	for _, flag := range []string{"-h", "--help"} {
		code, _, _ := runCapturingOutput(t, []string{flag})
		if code != 0 {
			t.Fatalf("%s: expected exit code 0, got %d", flag, code)
		}
	}
}

func TestParseFlags_HelpUsageIncludesBannerWordmark(t *testing.T) {
	// -h/--help route through fs.Usage(), which (per Go's flag package
	// default) writes to fs.Output(), not the stdout/stderr *os.File passed
	// into Run — so capture it directly via SetOutput rather than through
	// Run's pipes.
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
		if !strings.Contains(out, "Reconnaissance and Enumeration for Agent Protocols") {
			t.Fatalf("%s: expected usage output to include banner wordmark, got: %s", flag, out)
		}
		if !strings.Contains(out, "@hackwither") {
			t.Fatalf("%s: expected usage output to include attribution, got: %s", flag, out)
		}
	}
}

func TestRun_NoBannerSuppressesBanner(t *testing.T) {
	_, _, stderrWithBanner := runCapturingOutput(t, []string{"--list-detectors"})
	if !strings.Contains(stderrWithBanner, "Reconnaissance and Enumeration for Agent Protocols") {
		t.Fatalf("expected banner on stderr by default, got: %s", stderrWithBanner)
	}

	_, _, stderrNoBanner := runCapturingOutput(t, []string{"--list-detectors", "--no-banner"})
	if strings.Contains(stderrNoBanner, "Reconnaissance and Enumeration for Agent Protocols") {
		t.Fatalf("expected --no-banner to suppress banner, got: %s", stderrNoBanner)
	}
}

func TestRun_VersionFlag(t *testing.T) {
	code, stdout, stderr := runCapturingOutput(t, []string{"--version"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout, "reap v"+Version) {
		t.Fatalf("expected stdout to contain version string, got: %s", stdout)
	}
	if strings.Contains(stderr, "Reconnaissance and Enumeration for Agent Protocols") {
		t.Fatalf("expected --version to skip the banner, got stderr: %s", stderr)
	}
}

func TestRun_ProtocolAutoUsesDiscovery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
				"serverInfo":      map[string]any{"name": "auto-test-gateway", "version": "9.9.9"},
				"capabilities":    map[string]any{},
			},
		})
	}))
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
		"-t", srv.URL,
		"--templates", "",
		"--fingerprints", fingerprintsDir,
		"--no-banner",
		"--output", "json",
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
	if rep.Target.Protocol != "mcp" {
		t.Fatalf("expected discovery to resolve protocol=mcp, got %q", rep.Target.Protocol)
	}
	if rep.Target.DiscoveryMethod != "mcp-http-streamable" {
		t.Fatalf("expected discovery_method=mcp-http-streamable, got %q", rep.Target.DiscoveryMethod)
	}
	if rep.Target.DiscoveryConfidence != "high" {
		t.Fatalf("expected discovery_confidence=high, got %q", rep.Target.DiscoveryConfidence)
	}
	if rep.Target.ServerName != "auto-test-gateway" {
		t.Fatalf("expected server_name populated from discovery/initialize, got %q", rep.Target.ServerName)
	}
}

func TestParseFlags_Verbose(t *testing.T) {
	opts, _, err := parseFlags([]string{"-v", "--target", "https://example.com/mcp"})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if opts == nil {
		t.Fatal("expected options, got nil")
	}
	if !opts.Verbose {
		t.Fatal("expected verbose enabled for -v")
	}
}
