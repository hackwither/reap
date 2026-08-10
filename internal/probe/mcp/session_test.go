package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestInitializeSession_RejectsNonOKStatus is a regression test for a real
// false-positive: a 401 response whose body happens to be valid JSON but
// isn't JSON-RPC shaped (e.g. {"title":"Unauthorized",...}, no "result" or
// "error" key) used to decode into an empty-but-error-free envelope and get
// reported as a confirmed MCP handshake. HTTP status must be checked
// before anything else.
func TestInitializeSession_RejectsNonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"title":"Unauthorized","type":"about:blank","status":401,"detail":"Unauthorized"}`))
	}))
	defer srv.Close()

	sess := NewSession(srv.URL, "", 5*time.Second)
	init, raw, err := InitializeSession(context.Background(), sess)
	if err == nil {
		t.Fatalf("expected an error for a 401 response, got success: init=%+v", init)
	}
	if init != nil {
		t.Fatalf("expected nil InitializeResult on failure, got %+v", init)
	}
	if raw == nil || raw.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected the raw 401 response to be returned alongside the error, got %+v", raw)
	}
}

// TestInitializeSession_RejectsOKWithUnrecognizableBody guards the other
// half of the same gap: even a 200, if the body has neither protocolVersion
// nor serverInfo.name, isn't a real MCP handshake result.
func TestInitializeSession_RejectsOKWithUnrecognizableBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`)) // valid JSON, not an MCP result
	}))
	defer srv.Close()

	sess := NewSession(srv.URL, "", 5*time.Second)
	init, _, err := InitializeSession(context.Background(), sess)
	if err == nil {
		t.Fatalf("expected an error for a 200 body with no protocolVersion/serverInfo, got success: init=%+v", init)
	}
}

// TestInitializeSession_AcceptsRealHandshake is the positive control for
// both regression tests above.
func TestInitializeSession_AcceptsRealHandshake(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"real-gateway","version":"1.0"}}}`))
	}))
	defer srv.Close()

	sess := NewSession(srv.URL, "", 5*time.Second)
	init, _, err := InitializeSession(context.Background(), sess)
	if err != nil {
		t.Fatalf("unexpected error for a real handshake: %v", err)
	}
	if init.ServerInfo.Name != "real-gateway" {
		t.Fatalf("expected server name real-gateway, got %q", init.ServerInfo.Name)
	}
}
