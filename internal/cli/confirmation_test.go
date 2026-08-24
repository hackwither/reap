package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/hackwither/reap/internal/report"
)

// TestRun_UnconfirmedHTMLTargetDowngradesFindings reproduces the exact
// credibility bug this phase was written to fix: a target that isn't an MCP
// server at all (it answers every path with an HTML page, the way a
// catch-all web server or CDN does) must not be reported as if it were one.
// Before the confirmation gate, a plaintext-transport finding would fire at
// its normal MEDIUM severity purely because the target happens to be
// http://; after the gate, an unconfirmed target downgrades every finding
// to INFO/low-confidence instead.
func TestRun_UnconfirmedHTMLTargetDowngradesFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<!DOCTYPE html><html><body>not an MCP server</body></html>"))
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

	code := Run([]string{
		"-t", srv.URL,
		"--authorized",
		"--protocol", "mcp",
		"--templates", "",
		"--fingerprints", "",
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

	// Exit code 1 here is expected (the handshake itself is a reported
	// error) — this test is about what's IN the report, not the exit code.
	_ = code

	var rep report.Report
	if err := json.Unmarshal(outBuf.Bytes(), &rep); err != nil {
		t.Fatalf("failed to decode report JSON: %v; stdout: %s", err, outBuf.String())
	}

	if rep.Target.Confirmed {
		t.Fatalf("expected Target.Confirmed=false against an HTML-only server, got true")
	}
	if rep.Target.ConfirmReason == "" {
		t.Fatal("expected a non-empty ConfirmReason explaining why the target wasn't confirmed")
	}
	if len(rep.Errors) == 0 {
		t.Fatal("expected the initialize decode failure to surface in rep.Errors")
	}

	for _, f := range rep.Findings {
		if f.Severity == report.SeverityMedium || f.Severity == report.SeverityHigh {
			t.Fatalf("finding %q kept severity %q against an unconfirmed target; expected it capped at info", f.ID, f.Severity)
		}
		if f.Confidence != "low" {
			t.Fatalf("finding %q has confidence %q against an unconfirmed target; expected \"low\"", f.ID, f.Confidence)
		}
	}
}

// TestRun_AuthGatedMCPTargetConfirmed reproduces the api.x.com/mcp shape
// from the task: a real MCP server whose /mcp requires auth and answers
// initialize with 401 + application/problem+json. Discovery resolves /mcp
// via its low-confidence auth-gated fallback (fingerprint_test.go's
// TestHTTPStreamableFingerprint_AuthGatedFallback covers that stage in
// isolation); this test covers the actual scan session's initialize call
// against that resolved endpoint hitting the same 401, and asserts the
// confirmation gate now treats it as CONFIRMED (auth-gated) rather than
// UNCONFIRMED — no error, no downgrade, no generic-web-server warning.
func TestRun_AuthGatedMCPTargetConfirmed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // root is NOT an MCP endpoint
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"title":"Unauthorized","type":"about:blank","status":401,"detail":"Unauthorized"}`))
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
		"-t", srv.URL, // bare origin, so discovery must resolve /mcp itself
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
		t.Fatalf("expected exit code 0 (auth-gated is confirmed, not a scan error), got %d; stderr: %s", code, errBuf.String())
	}

	var rep report.Report
	if err := json.Unmarshal(outBuf.Bytes(), &rep); err != nil {
		t.Fatalf("failed to decode report JSON: %v; stdout: %s", err, outBuf.String())
	}

	if !rep.Target.Confirmed {
		t.Fatalf("expected Confirmed=true for an auth-gated MCP-consistent target, got false, reason=%q", rep.Target.ConfirmReason)
	}
	if rep.Target.ConfirmState != report.ConfirmStateAuthGated {
		t.Fatalf("expected ConfirmState=%q, got %q (reason=%q)", report.ConfirmStateAuthGated, rep.Target.ConfirmState, rep.Target.ConfirmReason)
	}
	if len(rep.Errors) != 0 {
		t.Fatalf("expected 0 errors for an auth-gated (not failed) handshake, got %v", rep.Errors)
	}
	for _, f := range rep.Findings {
		for _, tag := range f.Tags {
			if tag == "target-unconfirmed" {
				t.Fatalf("finding %q carries target-unconfirmed tag on a confirmed (auth-gated) target", f.ID)
			}
		}
	}
}
