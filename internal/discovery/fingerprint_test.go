package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFingerprintFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadFingerprintDir_GoodMalformedAndMissingFields(t *testing.T) {
	dir := t.TempDir()
	writeFingerprintFile(t, dir, "good.json", `{
		"id": "test-good",
		"protocol": "mcp",
		"transport": "http-streamable",
		"kinds": ["url"],
		"request": {"http_method": "GET"},
		"matchers": [{"type": "status_code", "equals": 200}],
		"on_match_confidence": "high"
	}`)
	writeFingerprintFile(t, dir, "malformed.json", `{not valid json`)
	writeFingerprintFile(t, dir, "missing-fields.json", `{"protocol": "mcp"}`) // no id, no kinds

	loaded, errs := LoadFingerprintDir(dir)
	if len(loaded) != 1 {
		t.Fatalf("expected exactly 1 successfully loaded fingerprint, got %d", len(loaded))
	}
	if loaded[0].ID != "test-good" {
		t.Fatalf("expected loaded fingerprint id 'test-good', got %q", loaded[0].ID)
	}
	if len(errs) != 2 {
		t.Fatalf("expected 2 load errors (malformed + missing fields), got %d: %v", len(errs), errs)
	}
}

func TestLoadFingerprintDir_MissingDirIsNotFatal(t *testing.T) {
	loaded, errs := LoadFingerprintDir(filepath.Join(t.TempDir(), "does-not-exist"))
	if len(loaded) != 0 || len(errs) != 0 {
		t.Fatalf("expected no fingerprints and no errors for a missing directory, got %d loaded, %d errs", len(loaded), len(errs))
	}
}

// mockInitializeServer serves a minimal MCP streamable-HTTP initialize
// response, mirroring scripts/mock_mcp_server.py closely enough for the
// http-streamable fingerprint to confirm a match against it.
func mockInitializeServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Method string `json:"method"`
			ID     int    `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      body.ID,
			"result": map[string]any{
				"protocolVersion": "2025-06-18",
				"serverInfo":      map[string]any{"name": "test-gateway", "version": "1.2.3"},
			},
		})
	}))
}

func loadBuiltinFingerprint(t *testing.T, id string) *FingerprintTemplate {
	t.Helper()
	loaded, errs := LoadFingerprintDir(filepath.Join("..", "..", "fingerprints"))
	if len(errs) != 0 {
		t.Fatalf("unexpected errors loading fingerprints/: %v", errs)
	}
	for _, fpt := range loaded {
		if fpt.ID == id {
			return fpt
		}
	}
	t.Fatalf("fingerprint %q not found among loaded fingerprints", id)
	return nil
}

func TestHTTPStreamableFingerprint_MatchesJSONRPCInitialize(t *testing.T) {
	srv := mockInitializeServer()
	defer srv.Close()

	fpt := loadBuiltinFingerprint(t, "mcp-http-streamable")
	det := fpt.AsDetector()

	fp, err := det.Detect(context.Background(), Candidate{Kind: KindURL, URL: srv.URL}, DetectOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp == nil {
		t.Fatal("expected a fingerprint match, got nil")
	}
	if fp.Confidence != "high" {
		t.Fatalf("expected high confidence, got %q", fp.Confidence)
	}
	if fp.ServerName != "test-gateway" || fp.ServerVer != "1.2.3" || fp.ProtocolVer != "2025-06-18" {
		t.Fatalf("expected extracted server fields to populate Fingerprint, got %+v", fp)
	}
}

func TestHTTPSSELegacyFingerprint_MatchesRealSSEFraming(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("event: endpoint\ndata: /messages?session=abc123\n\n"))
	}))
	defer srv.Close()

	fpt := loadBuiltinFingerprint(t, "mcp-http-sse-legacy")
	det := fpt.AsDetector()

	fp, err := det.Detect(context.Background(), Candidate{Kind: KindURL, URL: srv.URL}, DetectOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp == nil {
		t.Fatal("expected a fingerprint match against real SSE framing, got nil")
	}
	if fp.Confidence != "medium" {
		t.Fatalf("expected medium confidence (declarative single-request signal only, no chained follow-up), got %q", fp.Confidence)
	}
}

// TestHTTPSSELegacyFingerprint_NoFalsePositiveOnPlainJSON is the false-positive
// discipline check the plan calls for: a plain JSON-RPC server (no SSE
// framing at all) must not be mistaken for legacy-SSE MCP.
func TestHTTPSSELegacyFingerprint_NoFalsePositiveOnPlainJSON(t *testing.T) {
	srv := mockInitializeServer()
	defer srv.Close()

	fpt := loadBuiltinFingerprint(t, "mcp-http-sse-legacy")
	det := fpt.AsDetector()

	fp, err := det.Detect(context.Background(), Candidate{Kind: KindURL, URL: srv.URL}, DetectOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp != nil {
		t.Fatalf("expected no match against a plain JSON-RPC server, got %+v", fp)
	}
}
