package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/hackwither/reap/internal/probe"
)

// recordedRequest is one thing reap sent, for asserting on protocol
// conformance rather than only on responses.
type recordedRequest struct {
	Method    string
	Version   string // protocolVersion in params, for initialize
	ProtoHdr  string // MCP-Protocol-Version header
	HasID     bool   // notifications must not carry an id
	UserAgent string
}

// strictServer models the reference-SDK behaviour reap has to satisfy: it
// speaks only older protocol revisions, refuses requests before
// notifications/initialized, and requires the MCP-Protocol-Version header.
type strictServer struct {
	mu          sync.Mutex
	requests    []recordedRequest
	initialized bool
	supported   map[string]bool
	requireHdr  bool
	requireInit bool
}

func (s *strictServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID     *int           `json:"id"`
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)

		ver, _ := body.Params["protocolVersion"].(string)
		s.mu.Lock()
		s.requests = append(s.requests, recordedRequest{
			Method:    body.Method,
			Version:   ver,
			ProtoHdr:  r.Header.Get("MCP-Protocol-Version"),
			HasID:     body.ID != nil,
			UserAgent: r.Header.Get("User-Agent"),
		})
		initialized := s.initialized
		s.mu.Unlock()

		reply := func(status int, payload map[string]any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(payload)
		}
		rpcErr := func(status int, msg string) {
			reply(status, map[string]any{
				"jsonrpc": "2.0", "id": body.ID,
				"error": map[string]any{"code": -32602, "message": msg},
			})
		}

		switch body.Method {
		case "initialize":
			if !s.supported[ver] {
				rpcErr(http.StatusBadRequest, "Unsupported protocol version: "+ver)
				return
			}
			w.Header().Set("Mcp-Session-Id", "abcdef0123456789abcdef0123456789")
			reply(http.StatusOK, map[string]any{
				"jsonrpc": "2.0", "id": body.ID,
				"result": map[string]any{
					"protocolVersion": ver,
					"serverInfo":      map[string]any{"name": "strict", "version": "1.0"},
					"capabilities":    map[string]any{"tools": map[string]any{}},
				},
			})
		case "notifications/initialized":
			s.mu.Lock()
			s.initialized = true
			s.mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
		default:
			if s.requireInit && !initialized {
				rpcErr(http.StatusBadRequest, "Received request before initialization was complete")
				return
			}
			if s.requireHdr && r.Header.Get("MCP-Protocol-Version") == "" {
				rpcErr(http.StatusBadRequest, "Missing MCP-Protocol-Version header")
				return
			}
			reply(http.StatusOK, map[string]any{
				"jsonrpc": "2.0", "id": body.ID,
				"result": map[string]any{"tools": []map[string]any{{"name": "exec_shell"}}},
			})
		}
	}
}

func (s *strictServer) sent() []recordedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedRequest(nil), s.requests...)
}

// TestInitializeNegotiatesDownTheLadder covers the failure that made reap
// report "clean" on servers it never spoke to: it sent one hardcoded protocol
// version and treated a rejection as a dead target.
func TestInitializeNegotiatesDownTheLadder(t *testing.T) {
	srv := &strictServer{
		supported:   map[string]bool{"2024-11-05": true},
		requireHdr:  true,
		requireInit: true,
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	sess := testSession(t, ts.URL)
	init, _, err := sess.Initialize(context.Background())
	if err != nil {
		t.Fatalf("expected negotiation to succeed, got %v", err)
	}
	if init.ServerInfo.Name != "strict" {
		t.Fatalf("unexpected server name %q", init.ServerInfo.Name)
	}
	if got := sess.NegotiatedVersion(); got != "2024-11-05" {
		t.Fatalf("expected negotiated version 2024-11-05, got %q", got)
	}

	// Every rung above the supported one should have been attempted, in order.
	var attempted []string
	for _, r := range srv.sent() {
		if r.Method == "initialize" {
			attempted = append(attempted, r.Version)
		}
	}
	if len(attempted) != len(SupportedProtocolVersions) {
		t.Fatalf("expected the full ladder to be walked, got %v", attempted)
	}
	if attempted[0] != SupportedProtocolVersions[0] {
		t.Fatalf("ladder must start at the newest version, got %v", attempted)
	}
}

// TestInitializeSendsInitializedNotification covers the two spec-required
// steps reap omitted entirely, either of which makes a strict server reject
// every post-handshake request.
func TestInitializeSendsInitializedNotification(t *testing.T) {
	srv := &strictServer{
		supported:   map[string]bool{"2025-06-18": true},
		requireHdr:  true,
		requireInit: true,
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	sess := testSession(t, ts.URL)
	if _, _, err := sess.Initialize(context.Background()); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	res, err := listAll(context.Background(), sess, "tools/list", "tools")
	if err != nil {
		t.Fatalf("tools/list failed: %v", err)
	}
	if !res.OK() || len(res.Items) != 1 {
		t.Fatalf("expected tools/list to succeed against a strict server, got status=%d items=%d", res.FirstStatus, len(res.Items))
	}

	var sawNotification bool
	for _, r := range srv.sent() {
		if r.Method == "notifications/initialized" {
			sawNotification = true
			if r.HasID {
				t.Fatal("notifications/initialized must not carry a JSON-RPC id")
			}
		}
		if r.Method == "tools/list" && r.ProtoHdr == "" {
			t.Fatal("post-handshake requests must carry MCP-Protocol-Version")
		}
	}
	if !sawNotification {
		t.Fatal("expected reap to send notifications/initialized after a successful handshake")
	}
}

// TestSessionIdentifiesItself keeps reap from shipping Go's default agent
// string, which WAFs block and which gives a defender reading their logs no
// way to attribute the traffic.
func TestSessionIdentifiesItself(t *testing.T) {
	srv := &strictServer{supported: map[string]bool{"2025-06-18": true}}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	sess := testSession(t, ts.URL)
	if _, _, err := sess.Initialize(context.Background()); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	for _, r := range srv.sent() {
		if r.UserAgent == "" || r.UserAgent == "Go-http-client/1.1" {
			t.Fatalf("expected an identifiable User-Agent, got %q", r.UserAgent)
		}
	}
}

// TestDoCachesIdenticalReads guards the request-volume fix. Distinct auth and
// header variants must still be fetched separately, or the unauthenticated and
// CORS probes would read each other's responses.
func TestDoCachesIdenticalReads(t *testing.T) {
	srv := &strictServer{supported: map[string]bool{"2025-06-18": true}}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	sess := NewSession(ts.URL, "Bearer token", testClient(t))
	ctx := context.Background()
	if _, _, err := sess.Initialize(ctx); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	countToolsList := func() int {
		n := 0
		for _, r := range srv.sent() {
			if r.Method == "tools/list" {
				n++
			}
		}
		return n
	}

	for i := 0; i < 3; i++ {
		if _, err := sess.Do(ctx, "tools/list", map[string]any{}); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	if got := countToolsList(); got != 1 {
		t.Fatalf("expected identical reads to be served from cache, got %d requests", got)
	}

	if _, err := sess.Do(ctx, "tools/list", map[string]any{}, probe.WithNoAuth()); err != nil {
		t.Fatalf("Do (no auth): %v", err)
	}
	if got := countToolsList(); got != 2 {
		t.Fatalf("an unauthenticated read must not be served from the authenticated cache entry, got %d requests", got)
	}
}

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

	sess := NewSession(srv.URL, "", testClient(t))
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

	sess := NewSession(srv.URL, "", testClient(t))
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

	sess := NewSession(srv.URL, "", testClient(t))
	init, _, err := InitializeSession(context.Background(), sess)
	if err != nil {
		t.Fatalf("unexpected error for a real handshake: %v", err)
	}
	if init.ServerInfo.Name != "real-gateway" {
		t.Fatalf("expected server name real-gateway, got %q", init.ServerInfo.Name)
	}
}

// TestInitializeSessionRecordsStateOnStreamableSession is a regression test
// for a merge bug: InitializeSession used to negotiate the handshake directly
// instead of delegating to (*Session).Initialize, so the session never learned
// its negotiated version or session ID and never sent
// notifications/initialized. Every later request then omitted the
// MCP-Protocol-Version header and a strict server rejected the whole scan,
// while the report still claimed the handshake had succeeded.
func TestInitializeSessionRecordsStateOnStreamableSession(t *testing.T) {
	srv := &strictServer{
		supported:   map[string]bool{"2024-11-05": true},
		requireHdr:  true,
		requireInit: true,
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	sess := testSession(t, ts.URL)
	if _, _, err := InitializeSession(context.Background(), sess); err != nil {
		t.Fatalf("InitializeSession: %v", err)
	}
	if got := sess.NegotiatedVersion(); got != "2024-11-05" {
		t.Fatalf("session did not record the negotiated version, got %q", got)
	}
	if sess.SessionID() == "" {
		t.Fatal("session did not capture Mcp-Session-Id from the handshake")
	}

	// The real proof: a follow-up request must be accepted by a server that
	// enforces both spec requirements.
	res, err := listAll(context.Background(), sess, "tools/list", "tools")
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	if !res.OK() {
		t.Fatalf("post-handshake request rejected (HTTP %d) — session state was not recorded", res.FirstStatus)
	}
}
