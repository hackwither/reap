package transport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hackwither/reap/internal/httpx"
	"github.com/hackwither/reap/internal/probe"
	"github.com/hackwither/reap/internal/probe/generic"
	"github.com/hackwither/reap/internal/report"
	"github.com/hackwither/reap/internal/version"
)

func testClient(t *testing.T) *httpx.Client {
	t.Helper()
	c, err := httpx.New(httpx.Config{Timeout: 5 * time.Second}, version.UserAgent())
	if err != nil {
		t.Fatalf("httpx.New: %v", err)
	}
	return c
}

// session builds a generic (non-MCP) session, which is the point of this
// package: these checks must work without any protocol support at all.
func session(t *testing.T, url string) probe.Session {
	t.Helper()
	return generic.NewSession(url, "", testClient(t))
}

func TestProbesAreProtocolNeutral(t *testing.T) {
	for _, p := range BuiltinProbes(testClient(t)) {
		if p.Protocol() != "*" {
			t.Errorf("%s reports protocol %q, want \"*\" so it runs against every protocol", p.ID(), p.Protocol())
		}
	}
}

func TestPlaintextProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	rep := report.New(srv.URL, srv.URL, "a2a") // deliberately not mcp
	if err := (&plaintextProbe{}).Run(context.Background(), session(t, srv.URL), rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].ID != "transport-plaintext" {
		t.Fatalf("expected transport-plaintext finding, got %v", rep.Findings)
	}
	if rep.Findings[0].Protocol != "*" {
		t.Fatalf("expected a protocol-neutral finding, got %q", rep.Findings[0].Protocol)
	}
}

func TestTLSProbesNotApplicableOverPlaintext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	client := testClient(t)
	for _, p := range []probe.Probe{
		&tlsCertHealthProbe{client: client},
		&downgradeProbe{client: client},
	} {
		rep := report.New(srv.URL, srv.URL, "mcp")
		err := p.Run(context.Background(), session(t, srv.URL), rep)
		if !errors.Is(err, probe.ErrNotApplicable) {
			t.Errorf("%s: expected ErrNotApplicable over http, got %v", p.ID(), err)
		}
		if len(rep.Findings) != 0 {
			t.Errorf("%s: expected no findings, got %v", p.ID(), rep.Findings)
		}
	}
}

func TestTLSCertHealthProbe_ReportsSelfSignedCert(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	rep := report.New(ts.URL, ts.URL, "mcp")
	if err := (&tlsCertHealthProbe{client: testClient(t)}).Run(context.Background(), session(t, ts.URL), rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].ID != "tls-cert-health" {
		t.Fatalf("expected tls-cert-health finding, got %v", rep.Findings)
	}
}

// TestCORSProbeUsesPreflight covers a real gap in the old MCP-coupled version:
// it piggybacked an Origin header onto a tools/list POST, so servers that only
// emit permissive CORS headers in response to an OPTIONS preflight were missed
// entirely.
func TestCORSProbeUsesPreflight(t *testing.T) {
	var sawPreflight bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			sawPreflight = true
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rep := report.New(srv.URL, srv.URL, "mcp")
	if err := (&corsWildcardProbe{client: testClient(t)}).Run(context.Background(), session(t, srv.URL), rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sawPreflight {
		t.Fatal("expected the probe to send an OPTIONS preflight")
	}
	if len(rep.Findings) != 1 || rep.Findings[0].ID != "http-cors-wildcard" {
		t.Fatalf("expected http-cors-wildcard finding, got %v", rep.Findings)
	}
	if rep.Findings[0].Severity != report.SeverityHigh {
		t.Fatalf("wildcard + credentials must be high, got %s", rep.Findings[0].Severity)
	}
}

func TestCORSProbe_ReflectedOriginIsHigh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflecting the caller's Origin is strictly worse than "*", because
		// browsers allow credentials with a reflected origin.
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rep := report.New(srv.URL, srv.URL, "mcp")
	if err := (&corsWildcardProbe{client: testClient(t)}).Run(context.Background(), session(t, srv.URL), rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("expected a finding for a reflected Origin, got %v", rep.Findings)
	}
	if rep.Findings[0].Severity != report.SeverityHigh {
		t.Fatalf("expected high severity for a reflected Origin, got %s", rep.Findings[0].Severity)
	}
}

func TestCORSProbe_SilentWhenScoped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://first-party.example")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rep := report.New(srv.URL, srv.URL, "mcp")
	if err := (&corsWildcardProbe{client: testClient(t)}).Run(context.Background(), session(t, srv.URL), rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("a scoped ACAO must not produce a finding, got %v", rep.Findings)
	}
}

func TestRateLimitProbe(t *testing.T) {
	t.Run("headers present: silent", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		rep := report.New(srv.URL, srv.URL, "mcp")
		if err := (&rateLimitProbe{client: testClient(t)}).Run(context.Background(), session(t, srv.URL), rep); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rep.Findings) != 0 {
			t.Fatalf("expected no finding when rate-limit headers exist, got %v", rep.Findings)
		}
	})

	t.Run("headers absent: reports at ASI06", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		rep := report.New(srv.URL, srv.URL, "mcp")
		if err := (&rateLimitProbe{client: testClient(t)}).Run(context.Background(), session(t, srv.URL), rep); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rep.Findings) != 1 {
			t.Fatalf("expected 1 finding, got %v", rep.Findings)
		}
		// ASI08 (Supply Chain) was simply the wrong category for missing rate
		// limiting; it is a cascading-failure concern.
		if got := rep.Findings[0].ASI; len(got) != 1 || got[0] != "ASI06" {
			t.Fatalf("expected ASI06, got %v", got)
		}
	})
}
