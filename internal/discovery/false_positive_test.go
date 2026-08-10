package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// TestDetectors_NoFalsePositiveOnAdjacentButNotMCP is the false-positive
// discipline suite the project's own plan called for but never built: a
// scanner is trusted on its false-positive rate, not its finding count
// (see the review that prompted this phase — REAP once reported five
// MCP/OAuth findings against x.com because the "initialize" handshake got
// back an HTML page and nothing downstream treated that as disqualifying).
// Every fixture here looks MCP-adjacent in some narrow way but isn't MCP;
// the full detector set (built-in + shipped fingerprints) must never call
// any of them a high-confidence match.
func TestDetectors_NoFalsePositiveOnAdjacentButNotMCP(t *testing.T) {
	fixtures := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "catch-all HTML server (the x.com case)",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=UTF-8")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("<!DOCTYPE html><html><body>hello</body></html>"))
			},
		},
		{
			name: "generic non-MCP JSON-RPC server (e.g. a blockchain node)",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"blockNumber":"0x10d4f"}}`))
			},
		},
		{
			name: "GraphQL introspection response",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":{"__schema":{"types":[{"name":"Query"}]}}}`))
			},
		},
		{
			name: "plain REST 404",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"not found"}`))
			},
		},
	}

	fingerprints, errs := LoadFingerprintDir(filepath.Join("..", "..", "fingerprints"))
	if len(errs) != 0 {
		t.Fatalf("unexpected errors loading fingerprints/: %v", errs)
	}
	reg := NewRegistry()
	for _, d := range BuiltinDetectors() {
		reg.Register(d)
	}
	for _, fpt := range fingerprints {
		reg.Register(fpt.AsDetector())
	}

	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			srv := httptest.NewServer(fx.handler)
			defer srv.Close()

			fp := Run(context.Background(), reg, Candidate{Kind: KindURL, URL: srv.URL}, DetectOptions{Timeout: 5 * time.Second})
			if fp != nil && fp.Confidence == "high" {
				t.Fatalf("expected no high-confidence match against %s, got %+v", fx.name, fp)
			}
		})
	}
}
