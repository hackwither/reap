package mcp

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hackwither/reap/internal/probe"
	"github.com/hackwither/reap/internal/probe/common"
	"github.com/hackwither/reap/internal/report"
)

func authRequiredWSServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		key := r.Header.Get("Sec-WebSocket-Key")
		hj, _ := w.(http.Hijacker)
		conn, buf, err := hj.Hijack()
		if err != nil { return }
		defer conn.Close()
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + common.ExpectedWebSocketAccept(key) + "\r\n\r\n")
		_ = buf.Flush()
		reader := bufio.NewReader(buf)
		for {
			fin, opcode, payload, err := readWSFrame(reader)
			if err != nil { return }
			if !fin || opcode != wsOpText { continue }
			var req struct { ID int `json:"id"`; Method string `json:"method"` }
			if json.Unmarshal(payload, &req) != nil { continue }
			result := map[string]any{}
			switch req.Method {
			case "initialize":
				result = map[string]any{"protocolVersion": mcpProtocolVersion, "serverInfo": map[string]any{"name": "auth-ws"}, "capabilities": map[string]any{}}
			case "tools/list":
				result = map[string]any{"tools": []map[string]any{{"name": "secret_tool"}}}
			}
			resp, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
			if writeServerWSFrame(conn, wsOpText, resp) != nil { return }
		}
	}))
}

func TestUnauthToolsListProbeDoesNotReuseAuthenticatedWebSocket(t *testing.T) {
	srv := authRequiredWSServer(t)
	defer srv.Close()
	wsURL := "ws" + srv.URL[len("http"):]
	sess, err := NewWSSession(wsURL, "Bearer secret", 5*time.Second)
	if err != nil { t.Fatalf("authenticated websocket handshake failed: %v", err) }
	defer sess.conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	init, _, err := InitializeSession(ctx, sess)
	if err != nil || init == nil { t.Fatalf("authenticated initialize failed: %v", err) }
	raw, err := sess.Do(ctx, "tools/list", map[string]any{})
	if err != nil || raw.StatusCode != http.StatusOK { t.Fatalf("authenticated tools/list failed: status=%d err=%v", raw.StatusCode, err) }

	rep := &report.Report{Target: report.Target{URL: wsURL, Protocol: "mcp"}}
	if err := (&unauthToolsListProbe{}).Run(ctx, sess, rep); err != nil { t.Fatalf("probe failed: %v", err) }
	if len(rep.Findings) != 0 { t.Fatalf("authenticated websocket response was incorrectly reported as anonymous exposure: %+v", rep.Findings) }
}

type fakeSession struct {
	responses map[string]*probe.RawResult
	lastHost  string
}

func (f *fakeSession) TargetURL() string { return "https://example.com/mcp" }

func (f *fakeSession) Do(ctx context.Context, method string, params any, opts ...probe.ReqOption) (*probe.RawResult, error) {
	o := &probe.ReqOpts{}
	for _, opt := range opts {
		opt(o)
	}
	if host, ok := o.ExtraHeaders["Host"]; ok {
		f.lastHost = host
	}
	if raw, ok := f.responses[method]; ok {
		return raw, nil
	}
	return nil, fmt.Errorf("unexpected method: %s", method)
}

func newFakeSession(responses map[string]*probe.RawResult) *fakeSession {
	return &fakeSession{responses: responses}
}

func TestDynamicDispatchProbe(t *testing.T) {
	tests := []struct {
		name              string
		fixture           []byte
		wantFinding       bool
		wantSeverity      report.Severity
		wantSearchTools   []string
		wantDispatchTools []string
	}{
		{
			name: "sentry search + executor triggers high severity",
			fixture: []byte(`{
				"result": {
					"tools": [
						{
							"name": "search_sentry_tools",
							"description": "Search the available Sentry MCP tool catalog by name and description. Many Sentry operations are intentionally not exposed as top-level tools.",
							"inputSchema": {
								"type": "object",
								"required": ["query"],
								"properties": {
									"query": {"type": "string"}
								}
							}
						},
						{
							"name": "execute_sentry_tool",
							"annotations": {"destructiveHint": true, "readOnlyHint": false},
							"inputSchema": {
								"type": "object",
								"required": ["name"],
								"properties": {
									"name": {"type": "string"},
									"arguments": {"type": "object", "additionalProperties": {}}
								}
							}
						}
					]
				}
			}`),
			wantFinding:       true,
			wantSeverity:      report.SeverityHigh,
			wantSearchTools:   []string{"search_sentry_tools"},
			wantDispatchTools: []string{"execute_sentry_tool"},
		},
		{
			name: "generic executor without search tool fires low severity",
			fixture: []byte(`{
				"result": {
					"tools": [
						{
							"name": "run_any_tool",
							"description": "Execute a named tool by passing its arguments.",
							"inputSchema": {
								"type": "object",
								"required": ["name"],
								"properties": {
									"name": {"type": "string"},
									"args": {"type": "object", "additionalProperties": true}
								}
							}
						}
					]
				}
			}`),
			wantFinding:       true,
			wantSeverity:      report.SeverityLow,
			wantDispatchTools: []string{"run_any_tool"},
		},
		{
			name: "ordinary CRUD tools do not trigger dynamic dispatch",
			fixture: []byte(`{
				"result": {
					"tools": [
						{
							"name": "create_user",
							"description": "Create a new user.",
							"inputSchema": {
								"type": "object",
								"required": ["username", "email"],
								"properties": {
									"username": {"type": "string"},
									"email": {"type": "string"}
								}
							}
						},
						{
							"name": "delete_user",
							"description": "Delete a user by ID.",
							"inputSchema": {
								"type": "object",
								"required": ["id"],
								"properties": {
									"id": {"type": "string"}
								}
							}
						}
					]
				}
			}`),
			wantFinding: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := &report.Report{Tool: "reap", Version: "0.1.0", StartedAt: report.Report{}.StartedAt, Target: report.Target{URL: "https://example.com/mcp", Protocol: "mcp"}}
			testProbe := &dynamicDispatchProbe{}
			if err := testProbe.Run(context.Background(), newFakeSession(map[string]*probe.RawResult{"tools/list": &probe.RawResult{StatusCode: 200, Body: tc.fixture, Headers: http.Header{}}}), rep); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantFinding {
				if len(rep.Findings) != 1 {
					t.Fatalf("expected 1 finding, got %d", len(rep.Findings))
				}
				f := rep.Findings[0]
				if f.ID != "mcp-dynamic-dispatch" {
					t.Fatalf("unexpected finding ID: %s", f.ID)
				}
				if f.Severity != tc.wantSeverity {
					t.Fatalf("expected severity %s, got %s", tc.wantSeverity, f.Severity)
				}
				if len(tc.wantSearchTools) > 0 {
					searchTools, ok := f.Evidence["search_tools"].([]string)
					if !ok {
						var got []string
						for _, item := range f.Evidence["search_tools"].([]any) {
							got = append(got, item.(string))
						}
						searchTools = got
					}
					if !equalStringSlices(searchTools, tc.wantSearchTools) {
						t.Fatalf("expected search_tools %v, got %v", tc.wantSearchTools, searchTools)
					}
				}
				if len(tc.wantDispatchTools) > 0 {
					dispatchTools, ok := f.Evidence["dispatch_tools"].([]string)
					if !ok {
						var got []string
						for _, item := range f.Evidence["dispatch_tools"].([]any) {
							got = append(got, item.(string))
						}
						dispatchTools = got
					}
					if !equalStringSlices(dispatchTools, tc.wantDispatchTools) {
						t.Fatalf("expected dispatch_tools %v, got %v", tc.wantDispatchTools, dispatchTools)
					}
				}
			} else {
				if len(rep.Findings) != 0 {
					t.Fatalf("expected no findings, got %d", len(rep.Findings))
				}
			}
		})
	}
}

func TestHostHeaderValidationProbe(t *testing.T) {
	rep := &report.Report{Tool: "reap", Version: "0.1.0", StartedAt: report.Report{}.StartedAt, Target: report.Target{URL: "https://example.com/mcp", Protocol: "mcp"}}
	sess := newFakeSession(map[string]*probe.RawResult{
		"initialize": {
			StatusCode: 200,
			Body:       []byte(`{"result":{"serverInfo":{"name":"test","version":"1.0"},"protocolVersion":"2025-06-18","capabilities":{}}}`),
			Headers:    http.Header{},
		},
	})
	probe := &hostHeaderValidationProbe{}
	if err := probe.Run(context.Background(), sess, rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(rep.Findings))
	}
	if sess.lastHost != "host-header-validation.invalid" {
		t.Fatalf("expected Host header to be set, got %q", sess.lastHost)
	}
}

func TestRateLimitAbsenceProbe(t *testing.T) {
	rep := &report.Report{Tool: "reap", Version: "0.1.0", StartedAt: report.Report{}.StartedAt, Target: report.Target{URL: "https://example.com/mcp", Protocol: "mcp"}}
	sess := newFakeSession(map[string]*probe.RawResult{
		"tools/list": {
			StatusCode: 200,
			Body:       []byte(`{"result":{"tools":[]}}`),
			Headers:    http.Header{},
		},
		"initialize": {
			StatusCode: 200,
			Body:       []byte(`{"result":{"serverInfo":{"name":"test","version":"1.0"},"protocolVersion":"2025-06-18","capabilities":{}}}`),
			Headers:    http.Header{},
		},
	})
	probe := &rateLimitAbsenceProbe{}
	if err := probe.Run(context.Background(), sess, rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(rep.Findings))
	}
}

func TestSessionIDEntropyProbe(t *testing.T) {
	rep := &report.Report{Tool: "reap", Version: "0.1.0", StartedAt: report.Report{}.StartedAt, Target: report.Target{URL: "https://example.com/mcp", Protocol: "mcp"}}
	probe := &sessionIDEntropyProbe{}
	sess := &Session{sessionID: "1234567890"}
	if err := probe.Run(context.Background(), sess, rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(rep.Findings))
	}
}

func TestOAuthMetadataPostureProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/oauth-protected-resource" || r.URL.Path == "/.well-known/oauth-authorization-server" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"issuer":"https://auth.example.com","authorization_endpoint":"https://auth.example.com/oauth/authorize"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	rep := &report.Report{Tool: "reap", Version: "0.1.0", StartedAt: report.Report{}.StartedAt, Target: report.Target{URL: srv.URL, Protocol: "mcp"}}
	probe := &oauthMetadataPostureProbe{}
	// NewSession, not a bare &Session{url: ...} literal: the probe now also
	// checks for a Bearer challenge via a real s.Do call (RFC 9728 — see
	// package comment on oauthMetadataPostureProbe), which needs a real
	// http.Client under the hood.
	sess := NewSession(srv.URL, "", 5*time.Second)
	if err := probe.Run(context.Background(), sess, rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("expected 1 finding (PKCE not advertised; no 401 observed so no bearer-challenge finding), got %d: %+v", len(rep.Findings), rep.Findings)
	}
	if rep.Findings[0].ID != "mcp-oauth-metadata-posture" {
		t.Fatalf("expected the PKCE finding (mcp-oauth-metadata-posture), got %q", rep.Findings[0].ID)
	}
}

// TestOAuthMetadataPostureProbe_404DoesNotClaimPublished is a regression
// test for a real false positive: the probe used to treat ANY non-zero
// HTTP status (including 404) from a .well-known path as "reachable," so it
// reported "metadata published but missing PKCE" against a target that
// never published metadata at all — a finding that contradicted its own
// 404 evidence. Only a 200 with parseable JSON counts as "published."
func TestOAuthMetadataPostureProbe_404DoesNotClaimPublished(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Both well-known paths 404 (nothing published). tools/list
		// returns 401 WITH a correct Bearer challenge (healthy case), so
		// the only remaining way this test could produce a finding is the
		// bug this test guards against.
		if r.Method == http.MethodPost {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mcp"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	rep := &report.Report{Target: report.Target{URL: srv.URL, Protocol: "mcp"}}
	probe := &oauthMetadataPostureProbe{}
	sess := NewSession(srv.URL, "", 5*time.Second)
	if err := probe.Run(context.Background(), sess, rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("expected no findings when metadata 404s and the Bearer challenge is present, got %d: %+v", len(rep.Findings), rep.Findings)
	}
}

// TestOAuthMetadataPostureProbe_BearerCheckedOnProtectedResource is a
// regression test for the second real bug: the Bearer challenge (RFC 9728)
// must be read from the protected resource's own 401 (here, tools/list),
// not from the .well-known metadata response's headers — checking the
// wrong response means every correctly-configured server gets flagged.
func TestOAuthMetadataPostureProbe_BearerCheckedOnProtectedResource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// The protected resource's 401 has NO Bearer challenge — this
			// must fire mcp-oauth-bearer-challenge-missing.
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// The metadata document DOES advertise PKCE, and (pre-fix) also
		// happened to carry an unrelated WWW-Authenticate header — proving
		// the probe no longer reads Bearer status from here.
		w.Header().Set("WWW-Authenticate", `Bearer realm="decoy, must not be read from here"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"code_challenge_methods_supported":["S256"]}`))
	}))
	defer srv.Close()

	rep := &report.Report{Target: report.Target{URL: srv.URL, Protocol: "mcp"}}
	probe := &oauthMetadataPostureProbe{}
	sess := NewSession(srv.URL, "", 5*time.Second)
	if err := probe.Run(context.Background(), sess, rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].ID != "mcp-oauth-bearer-challenge-missing" {
		t.Fatalf("expected exactly the bearer-challenge-missing finding, got %d: %+v", len(rep.Findings), rep.Findings)
	}
}

func TestTlsCertHealthProbe(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	rep := &report.Report{Tool: "reap", Version: "0.1.0", StartedAt: report.Report{}.StartedAt, Target: report.Target{URL: ts.URL, Protocol: "mcp"}}
	probe := &tlsCertHealthProbe{}
	if err := probe.Run(context.Background(), &Session{url: ts.URL}, rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(rep.Findings))
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
