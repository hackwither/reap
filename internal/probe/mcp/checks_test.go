package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hackwither/reap/internal/httpx"
	"github.com/hackwither/reap/internal/probe"
	"github.com/hackwither/reap/internal/report"
	"github.com/hackwither/reap/internal/version"
)

// testClient builds the shared HTTP client the way cli.Run does.
func testClient(t *testing.T) *httpx.Client {
	t.Helper()
	c, err := httpx.New(httpx.Config{Timeout: 5 * time.Second}, version.UserAgent())
	if err != nil {
		t.Fatalf("httpx.New: %v", err)
	}
	return c
}

func testSession(t *testing.T, url string) *Session {
	t.Helper()
	return NewSession(url, "", testClient(t))
}

func newReport(url string) *report.Report {
	return report.New(url, url, "mcp")
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
			rep := newReport("https://example.com/mcp")
			testProbe := &dynamicDispatchProbe{}
			sess := newFakeSession(map[string]*probe.RawResult{
				"tools/list": {StatusCode: 200, Body: tc.fixture, Headers: http.Header{}},
			})
			if err := testProbe.Run(context.Background(), sess, rep); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.wantFinding {
				if len(rep.Findings) != 0 {
					t.Fatalf("expected no findings, got %d", len(rep.Findings))
				}
				return
			}
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
				assertEvidenceStrings(t, f.Evidence, "search_tools", tc.wantSearchTools)
			}
			if len(tc.wantDispatchTools) > 0 {
				assertEvidenceStrings(t, f.Evidence, "dispatch_tools", tc.wantDispatchTools)
			}
		})
	}
}

func assertEvidenceStrings(t *testing.T, evidence map[string]any, key string, want []string) {
	t.Helper()
	got, ok := evidence[key].([]string)
	if !ok {
		t.Fatalf("evidence[%q] is %T, want []string", key, evidence[key])
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("evidence[%q]: got %v, want %v", key, got, want)
	}
}

// --- pagination ---------------------------------------------------------

// TestListAllFollowsCursor is the regression test for reap's silent
// undercounting: MCP list methods are cursor-paginated and reap used to read
// only the first page while presenting the result as a full inventory.
func TestListAllFollowsCursor(t *testing.T) {
	var pages int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID     int            `json:"id"`
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")

		if body.Method == "initialize" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": body.ID,
				"result": map[string]any{
					"protocolVersion": "2025-06-18",
					"serverInfo":      map[string]any{"name": "paged", "version": "1.0"},
				},
			})
			return
		}

		pages++
		cursor, _ := body.Params["cursor"].(string)
		result := map[string]any{"tools": []map[string]any{{"name": "page2_tool"}}}
		if cursor == "" {
			result = map[string]any{
				"tools":      []map[string]any{{"name": "page1_a"}, {"name": "page1_b"}},
				"nextCursor": "cursor-2",
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": body.ID, "result": result})
	}))
	defer srv.Close()

	sess := testSession(t, srv.URL)
	res, err := listAll(context.Background(), sess, "tools/list", "tools")
	if err != nil {
		t.Fatalf("listAll: %v", err)
	}
	if pages != 2 {
		t.Fatalf("expected 2 pages fetched, got %d", pages)
	}
	if len(res.Items) != 3 {
		t.Fatalf("expected 3 tools across pages, got %d (%v)", len(res.Items), toolNames(res.Items))
	}
	if res.Truncated {
		t.Fatal("expected Truncated=false when the cursor chain ended naturally")
	}
}

// --- host header --------------------------------------------------------

func TestHostHeaderValidationProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID int `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": body.ID,
			"result": map[string]any{
				"protocolVersion": "2025-06-18",
				"serverInfo":      map[string]any{"name": "test", "version": "1.0"},
			},
		})
	}))
	defer srv.Close()

	rep := newReport(srv.URL)
	sess := testSession(t, srv.URL)
	if err := (&hostHeaderValidationProbe{}).Run(context.Background(), sess, rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(rep.Findings))
	}
	// httptest binds loopback, where DNS rebinding is directly exploitable.
	if rep.Findings[0].Severity != report.SeverityHigh {
		t.Fatalf("expected high severity for a loopback target, got %s", rep.Findings[0].Severity)
	}
}

// TestIsLoopbackTarget pins the severity split for host-header validation.
// Rating every non-validating server HIGH made this check a permanent noise
// floor, since almost nothing behind an ingress or load balancer sees the
// original Host; HIGH is reserved for loopback, where a browser-driven
// rebinding attack reaches a local agent directly.
func TestIsLoopbackTarget(t *testing.T) {
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"http://localhost:8080/mcp", true},
		{"http://127.0.0.1:8080/mcp", true},
		{"http://[::1]:8080/mcp", true},
		{"https://example.com/mcp", false},
		{"https://10.0.0.5/mcp", false},
		{"not a url", false},
	} {
		if got := isLoopbackTarget(tc.url); got != tc.want {
			t.Errorf("isLoopbackTarget(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

// --- session ID redaction ----------------------------------------------

// TestSessionIDEntropyProbe_RedactsValue guards a data-handling rule, not a
// heuristic: reports get uploaded to code-scanning dashboards and pasted into
// tickets, so a live session ID must never appear in evidence.
func TestSessionIDEntropyProbe_RedactsValue(t *testing.T) {
	rep := newReport("https://example.com/mcp")
	sess := &Session{sessionID: "sess001"}
	if err := (&sessionIDEntropyProbe{}).Run(context.Background(), sess, rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(rep.Findings))
	}
	evidence := fmt.Sprintf("%v", rep.Findings[0].Evidence)
	if strings.Contains(evidence, "sess001") {
		t.Fatalf("session ID leaked into evidence: %s", evidence)
	}
	if got := rep.Findings[0].Evidence["session_id_shape"]; got != "aaaa999" {
		t.Fatalf("expected shape skeleton aaaa999, got %v", got)
	}
}

func TestSessionIDEntropyProbe_NotApplicableWithoutSessionID(t *testing.T) {
	rep := newReport("https://example.com/mcp")
	err := (&sessionIDEntropyProbe{}).Run(context.Background(), &Session{}, rep)
	if err == nil || !isNotApplicable(err) {
		t.Fatalf("expected ErrNotApplicable, got %v", err)
	}
}

func isNotApplicable(err error) bool {
	type is interface{ Is(error) bool }
	if v, ok := err.(is); ok {
		return v.Is(probe.ErrNotApplicable)
	}
	return err == probe.ErrNotApplicable
}

// --- OAuth --------------------------------------------------------------

// oauthRangeServer models the two postures reap has to tell apart: metadata
// published at the well-known path, and a challenge (or its absence) on the
// protected resource's own 401.
func oauthRangeServer(t *testing.T, pkce bool, challenge string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/") {
			doc := map[string]any{"issuer": "https://auth.example.com"}
			if pkce {
				doc["code_challenge_methods_supported"] = []string{"S256"}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(doc)
			return
		}
		if challenge != "" {
			w.Header().Set("WWW-Authenticate", challenge)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": 1,
			"error": map[string]any{"code": -32001, "message": "authentication required"},
		})
	}))
}

// TestOAuthMetadataPostureProbe_PKCEOnly is the regression test for reap's
// most damaging false positive: the check used to read WWW-Authenticate off
// the well-known GET, where it never appears, so a correctly-configured server
// was reported as deficient on every scan.
func TestOAuthMetadataPostureProbe_PKCEOnly(t *testing.T) {
	t.Run("advertises PKCE: silent", func(t *testing.T) {
		srv := oauthRangeServer(t, true, `Bearer resource_metadata="x"`)
		defer srv.Close()
		rep := newReport(srv.URL)
		if err := (&oauthMetadataPostureProbe{}).Run(context.Background(), testSession(t, srv.URL), rep); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rep.Findings) != 0 {
			t.Fatalf("expected no finding when PKCE is advertised, got %v", rep.Findings[0].ID)
		}
	})

	t.Run("no PKCE: reports", func(t *testing.T) {
		srv := oauthRangeServer(t, false, `Bearer resource_metadata="x"`)
		defer srv.Close()
		rep := newReport(srv.URL)
		if err := (&oauthMetadataPostureProbe{}).Run(context.Background(), testSession(t, srv.URL), rep); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rep.Findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(rep.Findings))
		}
	})
}

// --- auth posture -------------------------------------------------------

// TestAuthPostureProbe_GatedEndpointIsAResultNotAnError covers the semantic
// fix: an endpoint that correctly requires credentials is a recon result, so
// it must not land in the report's error list or trip a nonzero exit code.
func TestAuthPostureProbe_GatedEndpointIsAResultNotAnError(t *testing.T) {
	srv := oauthRangeServer(t, true, "")
	defer srv.Close()

	rep := newReport(srv.URL)
	if err := (&authPostureProbe{}).Run(context.Background(), testSession(t, srv.URL), rep); err != nil {
		t.Fatalf("gated endpoint must not produce a probe error, got %v", err)
	}
	if rep.Target.AuthState != report.AuthStateGated {
		t.Fatalf("expected auth_state=%s, got %q", report.AuthStateGated, rep.Target.AuthState)
	}
	// The mcp-enumeration-blocked finding is emitted by
	// toolCapabilitySurfaceProbe, which carries the reproduction exchange;
	// this probe only establishes the auth state.
	if len(rep.Findings) != 0 {
		t.Fatalf("auth posture should not duplicate the enumeration-blocked finding, got %v", rep.Findings)
	}
	if len(rep.Errors) != 0 {
		t.Fatalf("expected no errors for a gated endpoint, got %v", rep.Errors)
	}
}

func TestAuthPostureProbe_OpenEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID int `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": body.ID,
			"result": map[string]any{"tools": []map[string]any{{"name": "exec_shell"}}},
		})
	}))
	defer srv.Close()

	rep := newReport(srv.URL)
	if err := (&authPostureProbe{}).Run(context.Background(), testSession(t, srv.URL), rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rep.Target.AuthState != report.AuthStateOpen {
		t.Fatalf("expected auth_state=open, got %q", rep.Target.AuthState)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("auth posture should not emit a finding for an open endpoint, got %v", rep.Findings)
	}
}

// TestAnalyzeSessionID pins the entropy heuristic against real-world ID shapes.
// The previous version counted distinct characters present, which flagged every
// hex identifier as weak: a random 32-char hex string carries 128 bits but
// contains only about 14 of the 16 possible digits.
func TestAnalyzeSessionID(t *testing.T) {
	for _, tc := range []struct {
		name      string
		id        string
		wantIssue bool
	}{
		{"predictable counter", "sess001", true},
		{"short numeric", "1234567890", true},
		{"single repeated char", strings.Repeat("a", 32), true},
		{"32-char hex is strong", "9f2c4d8e1a7b3f5c9e2d4a8b6c1f3e5d", false},
		{"uuid v4 is strong", "3f8a1c2e-5b7d-4e9f-8a1b-2c3d4e5f6a7b", false},
		{"base64url token is strong", "xJ8-kQ2mR7vL0nP4tY6wZ1aB3cD5eF9gH2iJ4kL6mN8", false},
	} {
		issues, entropy := analyzeSessionID(tc.id)
		if got := len(issues) > 0; got != tc.wantIssue {
			t.Errorf("%s: issues=%v (entropy %.0f bits), want issue=%v", tc.name, issues, entropy, tc.wantIssue)
		}
	}
}
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
	sess := NewSession(srv.URL, "", testClient(t))
	if err := probe.Run(context.Background(), sess, rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("expected no findings when metadata 404s and the Bearer challenge is present, got %d: %+v", len(rep.Findings), rep.Findings)
	}
}
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
	sess := NewSession(srv.URL, "", testClient(t))
	if err := probe.Run(context.Background(), sess, rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].ID != "mcp-oauth-bearer-challenge-missing" {
		t.Fatalf("expected exactly the bearer-challenge-missing finding, got %d: %+v", len(rep.Findings), rep.Findings)
	}
}
