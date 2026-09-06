package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/hackwither/reap/internal/probe"
	"github.com/hackwither/reap/internal/report"
)

// BuiltinProbes returns every MCP-specific probe.
//
// Transport-level checks (TLS health, plaintext, downgrade, CORS, rate-limit
// headers) used to live here with mcp- IDs even though none of them read a
// byte of MCP. They now live in internal/probe/transport with
// Protocol() == "*", so they apply to every protocol reap can identify —
// including A2A and OpenAPI, which have no enumeration probes yet.
func BuiltinProbes() []probe.Probe {
	return []probe.Probe{
		&authPostureProbe{},
		&unauthToolsListProbe{},
		&toolCapabilitySurfaceProbe{},
		&hostHeaderValidationProbe{},
		&oauthMetadataPostureProbe{},
		&redirectUriLaxityProbe{},
		&sessionIDEntropyProbe{},
		&instructionsExposureProbe{},
		&resourcesPromptsExposureProbe{},
		&dynamicDispatchProbe{},
		&serverHeaderFingerprintProbe{},
	}
}

// reproBody renders the exact JSON-RPC request body a probe sent, for the
// HTTPExchange repro line — matches the envelope mcp.Session.Do builds (see
// session.go's rpcRequest), with a fixed id since reproduction doesn't
// depend on which request number this was in the session.
func reproBody(method string, params any) string {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return ""
	}
	return string(body)
}

// httpOnlyTransports is returned by probes whose check is inherently about
// HTTP mechanics (headers, TLS, CORS, well-known metadata endpoints) and
// therefore can't run meaningfully over a non-HTTP transport like stdio or
// a raw WebSocket. anyTransport is returned by probes that only inspect
// JSON-RPC payload shape and don't care which transport carried it.
var httpOnlyTransports = []string{"http-streamable", "http-sse-legacy"}
var anyTransport = []string{"*"}

// anonymousSessionProvider is implemented by session types that can hand back
// a separate, credential-free connection. WithNoAuth only omits a per-request
// Authorization header; it cannot undo authenticated transport state that is
// established out-of-band (a WebSocket upgrade authenticated at handshake, a
// captured Mcp-Session-Id, a long-lived authenticated SSE stream). Probes that
// report "unauthenticated exposure" must observe it over one of these fresh
// sessions, never over the authenticated session with the header suppressed.
type anonymousSessionProvider interface {
	AnonymousSession() (probe.Session, error)
}

func anonymousSession(s probe.Session) (probe.Session, error) {
	provider, ok := s.(anonymousSessionProvider)
	if !ok {
		return nil, fmt.Errorf("session does not support a separate anonymous connection")
	}
	return provider.AnonymousSession()
}

// closeSession releases persistent transport state when a probe created a
// separate anonymous session. Streamable HTTP needs no explicit cleanup;
// WebSocket and legacy-SSE sessions keep a connection or goroutine open.
func closeSession(s probe.Session) {
	if closer, ok := s.(io.Closer); ok {
		_ = closer.Close()
	}
}

// anonymousInitializedSession returns a fresh anonymous session that has
// completed the MCP initialize handshake, so an "unauthenticated exposure"
// finding is observed exactly as a real anonymous client would: connect,
// initialize, then enumerate. ok is false when an anonymous caller cannot get
// that far — the transport can't present an anonymous connection, or the
// anonymous handshake was rejected — in which case the surface is NOT reachable
// anonymously and the caller must emit no finding. Spec-compliant
// streamable-HTTP and legacy-SSE servers gate enumeration behind initialize
// (and an Mcp-Session-Id the fresh session captures during that handshake),
// so skipping it would under-report a genuinely open server. The caller owns
// the returned session and must closeSession it.
func anonymousInitializedSession(ctx context.Context, s probe.Session) (probe.Session, bool) {
	unauthSess, err := anonymousSession(s)
	if err != nil {
		return nil, false
	}
	if _, _, err := InitializeSession(ctx, unauthSess); err != nil {
		closeSession(unauthSess)
		return nil, false
	}
	return unauthSess, true
}

// streamableHTTPOnly is for probes that depend on a mechanism specific to
// the streamable-HTTP session implementation (e.g. the Mcp-Session-Id
// response header it captures) that has no equivalent in legacy-SSE or
// WebSocket sessions.
var streamableHTTPOnly = []string{"http-streamable"}

// --- host-header-validation -------------------------------------------

type hostHeaderValidationProbe struct{}

func (p *hostHeaderValidationProbe) ID() string           { return "mcp-host-header-validation" }
func (p *hostHeaderValidationProbe) Protocol() string     { return "mcp" }
func (p *hostHeaderValidationProbe) Transports() []string { return httpOnlyTransports }

func (p *hostHeaderValidationProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	foreignHost := "host-header-validation.invalid"
	params := initializeParams(negotiatedOr(s, SupportedProtocolVersions[0]))
	raw, err := s.Do(ctx, "initialize", params, probe.WithHeader("Host", foreignHost))
	if err != nil {
		return fmt.Errorf("initialize with foreign Host failed: %w", err)
	}
	if raw.StatusCode != 200 {
		return nil // server refused the mismatched Host — correct behaviour
	}

	var envelope struct {
		Result InitializeResult `json:"result"`
		Error  *rpcError        `json:"error"`
	}
	if err := json.Unmarshal(raw.Body, &envelope); err != nil || envelope.Error != nil {
		return nil
	}

	r.AddFinding(report.Finding{
		ID:          p.ID(),
		Title:       "MCP accepted initialize with a mismatched Host header",
		Severity:    hostHeaderSeverity(s.TargetURL()),
		Confidence:  "high",
		Protocol:    "mcp",
		ASI:         []string{"ASI03"},
		References:  []string{"MCP specification: DNS rebinding protection"},
		Description: fmt.Sprintf("The server processed an initialize request even though the Host header was set to %q, so it does not validate the requested host name before handling MCP traffic. This is the condition DNS-rebinding protection prevents; it is rated high only for loopback endpoints, where a browser-driven rebinding attack reaches a local agent directly.", foreignHost),
		Evidence: map[string]any{
			"tested_host_header": foreignHost,
			"server_name":        envelope.Result.ServerInfo.Name,
			"server_version":     envelope.Result.ServerInfo.Version,
		},
		Request: &report.HTTPExchange{
			Method:      "POST",
			URL:         s.TargetURL(),
			Headers:     map[string]string{"Host": foreignHost, "Content-Type": "application/json"},
			Body:        reproBody("initialize", params),
			StatusCode:  raw.StatusCode,
			ContentType: raw.Headers.Get("Content-Type"),
			BodySize:    len(raw.Body),
			Expected:    "request rejected (4xx) for a Host header that doesn't match the configured endpoint",
		},
		Remediation: "Validate the Host header or equivalent request target before accepting MCP requests, and refuse requests whose host name does not match the configured endpoint.",
		Source:      "builtin:mcp",
		Tags:        []string{"transport", "host-header"},
	})
	return nil
}

// --- oauth-metadata-posture --------------------------------------------

type oauthMetadataPostureProbe struct{}

func (p *oauthMetadataPostureProbe) ID() string           { return "mcp-oauth-metadata-posture" }
func (p *oauthMetadataPostureProbe) Protocol() string     { return "mcp" }
func (p *oauthMetadataPostureProbe) Transports() []string { return httpOnlyTransports }

// oauthMetadataPostureProbe checks two independent RFC-defined signals and
// deliberately does NOT conflate them into one finding, because they live
// in different places and a 404 on one says nothing about the other:
//
//   - The Bearer challenge (RFC 9728 §5.1) belongs on the 401 response from
//     the protected resource itself (the MCP endpoint), not on any
//     .well-known metadata document. Checking the metadata response's
//     headers for it — as an earlier version of this probe did — means the
//     probe reports "missing" on every correctly-configured server, since
//     the metadata endpoint was never the right place to look.
//   - PKCE advertisement (RFC 8414) is a property of a published
//     authorization-server metadata document. It can only be "missing" if
//     that document was actually reachable (HTTP 200 + valid JSON) — a 404
//     means "not published," a materially different, less actionable
//     signal that must not be reported as "published but incomplete."
func (p *oauthMetadataPostureProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	// --- Bearer challenge: observed on the resource's own 401, not metadata. ---
	// A fresh anonymous connection, not WithNoAuth on the authenticated
	// session — the whole point is the challenge an unauthenticated caller
	// gets, and reused transport state (a WebSocket authenticated at its
	// upgrade) would mask it. Deliberately no initialize handshake here: we
	// want the server's raw 401 challenge on an unauthenticated tools/list.
	// This probe only runs on HTTP transports, so a missing anonymous session
	// just means "skip the challenge check," not a WS anonymous-dial failure.
	var unauthRaw *probe.RawResult
	if unauthSess, sessErr := anonymousSession(s); sessErr == nil {
		defer closeSession(unauthSess)
		unauthRaw, _ = unauthSess.Do(ctx, "tools/list", map[string]any{})
	}
	sawChallenge := unauthRaw != nil && unauthRaw.StatusCode == http.StatusUnauthorized
	if sawChallenge {
		wwwAuth := unauthRaw.Headers.Get("WWW-Authenticate")
		if !strings.Contains(strings.ToLower(wwwAuth), "bearer") {
			r.AddFinding(report.Finding{
				ID:          "mcp-oauth-bearer-challenge-missing",
				Title:       "Protected resource does not send a Bearer WWW-Authenticate challenge",
				Severity:    report.SeverityMedium,
				Confidence:  "high", // directly observed on the actual protected-resource response
				Protocol:    "mcp",
				ASI:         []string{"ASI03"},
				References:  []string{"RFC 9728 (Protected Resource Metadata)", "RFC 6750 (Bearer Token Usage)"},
				Description: fmt.Sprintf("An unauthenticated tools/list request returned %d, but its WWW-Authenticate header did not include a Bearer challenge (got %q).", unauthRaw.StatusCode, wwwAuth),
				Evidence:    map[string]any{"www_authenticate": wwwAuth},
				Request: &report.HTTPExchange{
					Method:      "POST",
					URL:         s.TargetURL(),
					Body:        reproBody("tools/list", map[string]any{}),
					StatusCode:  unauthRaw.StatusCode,
					ContentType: unauthRaw.Headers.Get("Content-Type"),
					BodySize:    len(unauthRaw.Body),
					Expected:    `WWW-Authenticate header containing "Bearer"`,
				},
				Remediation: "Send a WWW-Authenticate: Bearer challenge (optionally with a resource_metadata parameter per RFC 9728) on unauthenticated requests to protected MCP endpoints.",
				Source:      "builtin:mcp",
				Tags:        []string{"oauth", "authn"},
			})
		}
	}

	// --- PKCE advertisement: only claimed against metadata that actually published (200). ---
	u, err := url.Parse(s.TargetURL())
	if err != nil {
		return nil
	}
	baseURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	paths := []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server"}
	pkceAdvertised := false
	published := false
	var publishedPath string
	var publishedStatus int
	var publishedContentType string

	for _, pth := range paths {
		metadata, headers, status, err := fetchWellKnownJSON(ctx, baseURL, pth)
		if err != nil || status != http.StatusOK || metadata == nil {
			continue // 404 (or any non-200) means "not published," not "published but incomplete"
		}
		published = true
		publishedPath, publishedStatus, publishedContentType = pth, status, headers.Get("Content-Type")
		if supportsPKCE(metadata) {
			pkceAdvertised = true
		}
	}

	if published && !pkceAdvertised {
		r.AddFinding(report.Finding{
			ID:          p.ID(),
			Title:       "Published OAuth metadata does not advertise PKCE",
			Severity:    report.SeverityLow,
			Confidence:  "high", // directly read from a metadata document that actually returned 200
			Protocol:    "mcp",
			ASI:         []string{"ASI03"},
			References:  []string{"RFC 8414 (Authorization Server Metadata)", "RFC 7636 (PKCE)"},
			Description: fmt.Sprintf("OAuth metadata was published at %s, but it does not advertise PKCE (code_challenge_methods_supported) support.", publishedPath),
			Evidence:    map[string]any{"published_path": publishedPath},
			Request: &report.HTTPExchange{
				Method:      "GET",
				URL:         baseURL + publishedPath,
				StatusCode:  publishedStatus,
				ContentType: publishedContentType,
				Expected:    `code_challenge_methods_supported: ["S256"]`,
			},
			Remediation: "Advertise PKCE support (code_challenge_methods_supported: [\"S256\"]) in published OAuth authorization-server metadata.",
			Source:      "builtin:mcp",
			Tags:        []string{"oauth", "authz"},
		})
	}
	return nil
}

func fetchWellKnownJSON(ctx context.Context, baseURL, path string) (map[string]any, http.Header, int, error) {
	url := baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, 0, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, nil, resp.StatusCode, err
	}
	var parsed map[string]any
	if len(data) > 0 {
		if json.Unmarshal(data, &parsed) != nil {
			parsed = nil
		}
	}
	return parsed, resp.Header, resp.StatusCode, nil
}

func supportsPKCE(metadata map[string]any) bool {
	if metadata == nil {
		return false
	}
	if v, ok := metadata["code_challenge_methods_supported"]; ok {
		return containsStringValue(v, "S256")
	}
	if v, ok := metadata["code_challenge_method"]; ok {
		return containsStringValue(v, "S256")
	}
	if v, ok := metadata["pkce"]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func containsStringValue(value any, expected string) bool {
	switch v := value.(type) {
	case string:
		return strings.EqualFold(v, expected)
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && strings.EqualFold(s, expected) {
				return true
			}
		}
	case []string:
		for _, item := range v {
			if strings.EqualFold(item, expected) {
				return true
			}
		}
	}
	return false
}

// --- redirect-uri-laxity ------------------------------------------------

type redirectUriLaxityProbe struct{}

func (p *redirectUriLaxityProbe) ID() string           { return "mcp-redirect-uri-laxity" }
func (p *redirectUriLaxityProbe) Protocol() string     { return "mcp" }
func (p *redirectUriLaxityProbe) Transports() []string { return httpOnlyTransports }

func (p *redirectUriLaxityProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	u, err := url.Parse(s.TargetURL())
	if err != nil {
		return nil
	}
	baseURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	paths := []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server"}
	redirectURIs := []string{}
	var lastPath string
	var lastStatus int
	for _, pth := range paths {
		metadata, _, status, err := fetchWellKnownJSON(ctx, baseURL, pth)
		if err != nil || status != http.StatusOK || metadata == nil {
			continue // 404 (or any non-200) is "not published," not parseable metadata
		}
		lastPath, lastStatus = pth, status
		redirectURIs = append(redirectURIs, findRedirectURIs(metadata)...)
	}
	if len(redirectURIs) == 0 {
		return nil
	}
	broad := []string{}
	for _, uri := range redirectURIs {
		if isBroadRedirectURI(uri) {
			broad = append(broad, uri)
		}
	}
	if len(broad) == 0 {
		return nil
	}
	r.AddFinding(report.Finding{
		ID:          p.ID(),
		Title:       "OAuth redirect URI registration appears overly broad",
		Severity:    report.SeverityMedium,
		Confidence:  "medium",
		Protocol:    "mcp",
		ASI:         []string{"ASI03"},
		References:  []string{"RFC 6749 §3.1.2 (Redirection Endpoint)", "RFC 8252 (OAuth for Native Apps)"},
		Description: "The discovered OAuth metadata includes redirect URIs that are broad or wildcarded, which increases the risk of confused-deputy or open redirect abuse.",
		Evidence: map[string]any{
			"redirect_uris": broad,
		},
		Request: &report.HTTPExchange{
			Method:     "GET",
			URL:        baseURL + lastPath,
			StatusCode: lastStatus,
			Expected:   "redirect_uris scoped to exact origins/paths, no wildcards",
		},
		Remediation: "Restrict registered redirect URIs to exact allowed origins and paths, and avoid wildcards or overly permissive URL patterns.",
		Source:      "builtin:mcp",
		Tags:        []string{"oauth", "redirect-uri"},
	})
	return nil
}

const maxRedirectURIDepth = 10

func findRedirectURIs(value any) []string {
	return findRedirectURIsAt(value, 0)
}

func findRedirectURIsAt(value any, depth int) []string {
	if depth > maxRedirectURIDepth {
		return nil
	}
	out := []string{}
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if strings.Contains(strings.ToLower(key), "redirect") {
				if s, ok := child.(string); ok {
					out = append(out, s)
				}
				if arr, ok := child.([]any); ok {
					for _, item := range arr {
						if s, ok := item.(string); ok {
							out = append(out, s)
						}
					}
				}
			}
			out = append(out, findRedirectURIsAt(child, depth+1)...)
		}
	case []any:
		for _, item := range v {
			out = append(out, findRedirectURIsAt(item, depth+1)...)
		}
	}
	return out
}

func isBroadRedirectURI(target string) bool {
	if strings.Contains(target, "*") {
		return true
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return true
	}
	switch parsed.Scheme {
	case "https":
		// Require a non-empty host and a path deeper than "/".
		return parsed.Host == "" || parsed.Path == "" || parsed.Path == "/"
	case "http":
		// RFC 8252 §8.3 permits http://localhost (and 127.0.0.1/::1) for
		// loopback redirect URIs in native apps. Flag everything else.
		h := parsed.Hostname()
		if h == "localhost" || h == "127.0.0.1" || h == "::1" {
			return false
		}
		return true
	default:
		// Any other scheme (myapp://callback, urn:ietf:...) is a native-app
		// custom URI scheme, which RFC 8252 explicitly allows. Empty scheme
		// means a relative or malformed URI — flag it.
		return parsed.Scheme == ""
	}
}

// --- session-id-entropy -------------------------------------------------

type sessionIDEntropyProbe struct{}

func (p *sessionIDEntropyProbe) ID() string           { return "mcp-session-id-entropy" }
func (p *sessionIDEntropyProbe) Protocol() string     { return "mcp" }
func (p *sessionIDEntropyProbe) Transports() []string { return streamableHTTPOnly }

func (p *sessionIDEntropyProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	ms, err := asSession(s)
	if err != nil {
		return err
	}
	if ms.SessionID() == "" {
		return probe.NotApplicable("server issued no Mcp-Session-Id")
	}

	issues, entropy := analyzeSessionID(ms.SessionID())
	if len(issues) == 0 {
		return nil
	}
	severity := report.SeverityLow
	if entropy < 80 {
		severity = report.SeverityMedium
	}
	r.AddFinding(report.Finding{
		ID:          p.ID(),
		Title:       "MCP session ID entropy looks weak or predictable",
		Severity:    severity,
		Confidence:  "high", // directly measured against the ID string itself, not a heuristic guess
		Protocol:    "mcp",
		ASI:         []string{"ASI03"},
		References:  []string{"NIST SP 800-63B §5.1.1 (session identifier entropy)"},
		Description: fmt.Sprintf("The MCP session ID returned by the server appears to have low entropy or a predictable format: %s", strings.Join(issues, ", ")),
		Evidence: map[string]any{
			"session_id_shape":       describeSessionIDShape(ms.SessionID()),
			"session_id_length":      len(ms.SessionID()),
			"estimated_entropy_bits": entropy,
			"issues":                 issues,
		},
		// No HTTPExchange: the session ID was captured from the
		// Mcp-Session-Id response header on an earlier, arbitrary call, not
		// a single request this probe made itself.
		Remediation: "Use a cryptographically random, high-entropy session identifier for MCP sessions and avoid sequential or human-readable formats.",
		Source:      "builtin:mcp",
		Tags:        []string{"session", "auth"},
	})
	return nil
}

// analyzeSessionID estimates how guessable a session ID is.
//
// Entropy is computed against the *inferred alphabet*, not the count of
// distinct characters actually present. Counting distinct characters
// systematically misjudges good identifiers: a random 32-character hex string
// carries 128 bits, but by the birthday problem it contains only ~14 of the 16
// hex digits, so a "fewer than 16 distinct characters" rule flagged it as
// weak. The same rule fired on every hex, base32 and UUID identifier reap saw.
func analyzeSessionID(id string) ([]string, float64) {
	issues := []string{}
	if len(id) == 0 {
		return []string{"session ID is empty"}, 0
	}

	unique := map[rune]struct{}{}
	for _, r := range id {
		unique[r] = struct{}{}
	}
	entropy := estimateEntropy(id, unique)

	if len(id) < 16 {
		issues = append(issues, "session ID is shorter than 16 characters")
	}
	if len(unique) < 2 {
		issues = append(issues, "session ID repeats a single character")
	}
	// 64 bits is the floor at which guessing stops being a practical attack.
	if entropy < 64 {
		issues = append(issues, fmt.Sprintf("estimated entropy is low (%.0f bits)", entropy))
	}
	return issues, entropy
}

// estimateEntropy returns length x log2(alphabet size), inferring the alphabet
// from the character classes present rather than from the sample.
func estimateEntropy(id string, unique map[rune]struct{}) float64 {
	if len(id) == 0 || len(unique) < 2 {
		return 0
	}
	return float64(len(id)) * math.Log2(float64(inferAlphabetSize(id, unique)))
}

// inferAlphabetSize guesses the alphabet an identifier was drawn from. When the
// characters don't fit a known encoding, the observed distinct count is used as
// a conservative floor.
func inferAlphabetSize(id string, unique map[rune]struct{}) int {
	var hasLower, hasUpper, hasDigit, hasURLSafe, hasOther bool
	hexOnly := true
	for _, r := range id {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r >= 'a' && r <= 'z':
			hasLower = true
			if r > 'f' {
				hexOnly = false
			}
		case r >= 'A' && r <= 'Z':
			hasUpper = true
			hexOnly = false
		case r == '-' || r == '_':
			hasURLSafe = true
		default:
			hasOther = true
			hexOnly = false
		}
	}

	switch {
	case hasOther:
		// Unknown encoding: don't credit more than what was observed.
		return len(unique)
	case hexOnly && (hasDigit || hasLower):
		return 16 // hex, with or without UUID separators
	case hasURLSafe || (hasLower && hasUpper && hasDigit):
		return 64 // base64url / base62-with-separators
	case hasLower && hasUpper:
		return 52
	case (hasLower || hasUpper) && hasDigit:
		return 36
	case hasLower || hasUpper:
		return 26
	case hasDigit:
		return 10
	default:
		return len(unique)
	}
}

func asSession(s probe.Session) (*Session, error) {
	ms, ok := s.(*Session)
	if !ok {
		return nil, fmt.Errorf("mcp probe received non-MCP session")
	}
	return ms, nil
}

// --- unauth-tools-list ------------------------------------------------

type unauthToolsListProbe struct{}

func (p *unauthToolsListProbe) ID() string           { return "mcp-unauth-tools-list" }
func (p *unauthToolsListProbe) Protocol() string     { return "mcp" }
func (p *unauthToolsListProbe) Transports() []string { return anyTransport }

func (p *unauthToolsListProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	// Answer the specific question "can an anonymous caller enumerate tools?"
	// over a fresh, unauthenticated connection — never by suppressing the
	// header on the authenticated session. WithNoAuth cannot undo transport
	// state established out-of-band (a WebSocket authenticated at its upgrade,
	// a captured Mcp-Session-Id), which would let an authenticated tool list
	// be reported as anonymous exposure.
	unauthSess, ok := anonymousInitializedSession(ctx, s)
	if !ok {
		return nil // no anonymous connection possible / handshake rejected — nothing exposed
	}
	defer closeSession(unauthSess)
	raw, err := unauthSess.Do(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil // network failure is not a finding; leave silent, CLI logs errors separately
	}
	if raw.StatusCode != 200 {
		return nil // server rejected the anonymous call — good, nothing to report
	}

	var envelope struct {
		Result struct {
			Tools []map[string]any `json:"tools"`
		} `json:"result"`
		Error *rpcError `json:"error"`
	}
	if err := json.Unmarshal(raw.Body, &envelope); err != nil {
		return nil
	}
	if envelope.Error != nil {
		return nil // server correctly refused at the protocol level
	}
	if len(envelope.Result.Tools) == 0 {
		return nil
	}

	names := make([]string, 0, len(envelope.Result.Tools))
	for _, t := range envelope.Result.Tools {
		if n, ok := t["name"].(string); ok {
			names = append(names, n)
		}
	}

	sev := report.SeverityMedium
	if hasHighRiskTool(names) {
		sev = report.SeverityHigh
	}

	r.AddFinding(report.Finding{
		ID:          p.ID(),
		Title:       "MCP tool listing accessible without authentication",
		Severity:    sev,
		Confidence:  "high",
		Protocol:    "mcp",
		ASI:         []string{"ASI02", "ASI03"},
		Description: fmt.Sprintf("tools/list returned %d tool(s) to an unauthenticated caller: %s", len(names), strings.Join(names, ", ")),
		Evidence:    map[string]any{"tool_count": len(names), "tool_names": names},
		Request: &report.HTTPExchange{
			Method:      "POST",
			URL:         s.TargetURL(),
			Body:        reproBody("tools/list", map[string]any{}),
			StatusCode:  raw.StatusCode,
			ContentType: raw.Headers.Get("Content-Type"),
			BodySize:    len(raw.Body),
			Expected:    "401/403 for an anonymous (no Authorization header) tools/list call",
		},
		Remediation: "Require authentication before tools/list, or scope the response so anonymous callers see nothing.",
		Source:      "builtin:mcp",
		Tags:        []string{"auth", "enumeration"},
	})
	return nil
}

var highRiskToolHints = []string{"exec", "shell", "eval", "run_command", "read_file", "write_file", "sql", "browser", "fetch_url", "http_request"}

func hasHighRiskTool(names []string) bool {
	for _, n := range names {
		lower := strings.ToLower(n)
		for _, hint := range highRiskToolHints {
			if strings.Contains(lower, hint) {
				return true
			}
		}
	}
	return false
}

// dangerousToolCategories maps a capability category to name/description
// keyword hints suggesting a tool has it — the agent-native equivalent of
// nmap flagging port 22 open. A security engineer looking at a tool
// inventory wants "which of these touch the filesystem, spawn a shell,
// reach out to the network, or handle secrets" without reading every
// inputSchema by hand.
var dangerousToolCategories = map[string][]string{
	"filesystem":       {"read_file", "write_file", "readfile", "writefile", "delete_file", "list_dir", "list_directory"},
	"shell_exec":       {"exec", "shell", "eval", "run_command", "subprocess", "bash", "powershell"},
	"network_egress":   {"fetch_url", "http_request", "curl", "download", "webhook", "fetch"},
	"database":         {"sql", "query_db", "database"},
	"browser_control":  {"browser", "puppeteer", "playwright"},
	"secrets_handling": {"api_key", "credential", "password", "secret", "token"},
}

// dangerousTools inspects a tools/list result and returns, per tool name,
// which dangerous-capability categories it appears to fall into by name or
// description — same keyword-heuristic ceiling as hasHighRiskTool above,
// but surfaced as first-class inventory (every match, not just "any match
// found") rather than folded into a single severity bump.
func dangerousTools(tools []map[string]any) map[string][]string {
	out := map[string][]string{}
	for _, t := range tools {
		name, _ := t["name"].(string)
		desc, _ := t["description"].(string)
		text := strings.ToLower(name + " " + desc)
		var cats []string
		for cat, hints := range dangerousToolCategories {
			for _, h := range hints {
				if strings.Contains(text, h) {
					cats = append(cats, cat)
					break
				}
			}
		}
		if len(cats) > 0 {
			sort.Strings(cats)
			out[name] = cats
		}
	}
	return out
}

// --- tool-capability-surface -------------------------------------------

// This probe doesn't flag a vulnerability by itself — it records the full
// tool surface as an informational finding so the JSON report is a useful
// asset inventory even when nothing else fires.
type toolCapabilitySurfaceProbe struct{}

func (p *toolCapabilitySurfaceProbe) ID() string           { return "mcp-tool-capability-surface" }
func (p *toolCapabilitySurfaceProbe) Protocol() string     { return "mcp" }
func (p *toolCapabilitySurfaceProbe) Transports() []string { return anyTransport }

func (p *toolCapabilitySurfaceProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	tools, listErr := listAll(ctx, s, "tools/list", "tools")
	if listErr != nil {
		return fmt.Errorf("tools/list failed: %w", listErr)
	}
	raw := &probe.RawResult{StatusCode: tools.FirstStatus, Headers: tools.FirstHeaders}
	if raw.Headers == nil {
		raw.Headers = http.Header{}
	}
	if raw.StatusCode == http.StatusUnauthorized || raw.StatusCode == http.StatusForbidden {
		// REAP's whole pitch is enumerating the agent surface — going
		// silent when that's blocked reads as "the feature isn't there."
		// A server correctly gating tools/list behind auth is a legitimate,
		// informative outcome; say so instead of just returning nothing.
		r.AddFinding(report.Finding{
			ID:          "mcp-enumeration-blocked",
			Title:       "Tool enumeration blocked by authentication",
			Severity:    report.SeverityInfo,
			Confidence:  "high",
			Protocol:    "mcp",
			ASI:         []string{"ASI09"},
			Description: fmt.Sprintf("tools/list returned %d without credentials — the server correctly gates enumeration behind authentication, so no tool inventory is available from this vantage point.", raw.StatusCode),
			Evidence:    map[string]any{"status_code": raw.StatusCode},
			Request: &report.HTTPExchange{
				Method:      "POST",
				URL:         s.TargetURL(),
				Body:        reproBody("tools/list", map[string]any{}),
				StatusCode:  raw.StatusCode,
				ContentType: raw.Headers.Get("Content-Type"),
				BodySize:    len(raw.Body),
			},
			Source: "builtin:mcp",
			Tags:   []string{"inventory", "auth"},
		})
		return nil
	}
	if !tools.OK() {
		return probe.NotApplicable("tools/list did not return an enumerable listing (HTTP %d)", tools.FirstStatus)
	}

	// Record the surface size even when it is zero: "this endpoint exposes no
	// tools" is a real recon result, and the identification block should say
	// so rather than omitting the line.
	summary := &report.CapabilitySummary{Tools: len(tools.Items), Truncated: tools.Truncated}
	for _, spec := range []struct {
		method string
		field  string
		count  *int
	}{
		{"resources/list", "resources", &summary.Resources},
		{"prompts/list", "prompts", &summary.Prompts},
	} {
		res, err := listAll(ctx, s, spec.method, spec.field)
		if err != nil || !res.OK() {
			continue // capability simply not offered; not an error
		}
		*spec.count = len(res.Items)
		if res.Truncated {
			summary.Truncated = true
		}
	}
	r.Target.Capabilities = summary

	if len(tools.Items) == 0 {
		return nil
	}

	r.AddFinding(report.Finding{
		ID:          p.ID(),
		Title:       fmt.Sprintf("Tool capability inventory (%d tools)", len(tools.Items)),
		Severity:    report.SeverityInfo,
		Confidence:  "high",
		Protocol:    "mcp",
		ASI:         []string{"ASI09"},
		Description: "Full tool surface exposed by this endpoint, for asset-inventory and diffing purposes.",
		Evidence:    map[string]any{"tools": tools.Items, "dangerous_tools": dangerousTools(tools.Items), "pages": tools.Pages, "truncated": tools.Truncated},
		Request: &report.HTTPExchange{
			Method:      "POST",
			URL:         s.TargetURL(),
			Body:        reproBody("tools/list", map[string]any{}),
			StatusCode:  raw.StatusCode,
			ContentType: raw.Headers.Get("Content-Type"),
			BodySize:    len(raw.Body),
		},
		Source: "builtin:mcp",
		Tags:   []string{"inventory"},
	})
	return nil
}

// --- instructions-exposure --------------------------------------------

// The MCP initialize response has an optional free-text "instructions"
// field servers may use to steer client models. If it contains material
// that reads like an internal system prompt (not just usage docs), that's
// worth surfacing — an unauthenticated caller doesn't need to guess a
// prompt if the server hands it over during the handshake.
type instructionsExposureProbe struct{}

func (p *instructionsExposureProbe) ID() string           { return "mcp-instructions-exposure" }
func (p *instructionsExposureProbe) Protocol() string     { return "mcp" }
func (p *instructionsExposureProbe) Transports() []string { return anyTransport }

func (p *instructionsExposureProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	init, raw, err := InitializeSession(ctx, s)
	if err != nil || raw == nil || raw.StatusCode != 200 || init == nil {
		return nil
	}
	if strings.TrimSpace(init.Instructions) == "" {
		return nil
	}
	// Heuristic only — flag length/keyword signals a human should review,
	// don't claim to have extracted a "system prompt".
	lower := strings.ToLower(init.Instructions)
	suspicious := len(init.Instructions) > 400 ||
		strings.Contains(lower, "never reveal") ||
		strings.Contains(lower, "do not tell the user") ||
		strings.Contains(lower, "internal") ||
		strings.Contains(lower, "api key") ||
		strings.Contains(lower, "secret")
	if !suspicious {
		return nil
	}
	r.AddFinding(report.Finding{
		ID:          p.ID(),
		Title:       "MCP handshake returns lengthy or sensitive-flavored instructions",
		Severity:    report.SeverityLow,
		Confidence:  "medium", // keyword/length heuristic on free text, explicitly not a confirmed leak
		Protocol:    "mcp",
		ASI:         []string{"ASI09"},
		Description: "The initialize response's 'instructions' field is long and/or contains language patterns (secrecy directives, 'internal', credential-related terms) worth a human review to confirm it isn't leaking operational or internal detail to any caller.",
		Evidence:    map[string]any{"instructions_length": len(init.Instructions), "instructions_excerpt": excerpt(init.Instructions, 200)},
		Request: &report.HTTPExchange{
			Method:      "POST",
			URL:         s.TargetURL(),
			Body:        reproBody("initialize", initializeParams(negotiatedOr(s, SupportedProtocolVersions[0]))),
			StatusCode:  raw.StatusCode,
			ContentType: raw.Headers.Get("Content-Type"),
			BodySize:    len(raw.Body),
		},
		Remediation: "Keep client-facing instructions limited to usage guidance; keep anything sensitive out of fields returned pre-authentication.",
		Source:      "builtin:mcp",
		Tags:        []string{"information-disclosure"},
	})
	return nil
}

func excerpt(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// --- resources-prompts-exposure ---------------------------------------

type resourcesPromptsExposureProbe struct{}

func (p *resourcesPromptsExposureProbe) ID() string           { return "mcp-resources-prompts-exposure" }
func (p *resourcesPromptsExposureProbe) Protocol() string     { return "mcp" }
func (p *resourcesPromptsExposureProbe) Transports() []string { return anyTransport }

func (p *resourcesPromptsExposureProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	// A fresh anonymous session (not WithNoAuth on the authenticated one) so
	// no credential or inherited transport state can make an authenticated
	// listing look anonymous. On transports that gate enumeration behind
	// initialize, the shared helper runs that handshake first.
	unauthSess, ok := anonymousInitializedSession(ctx, s)
	if !ok {
		return nil
	}
	defer closeSession(unauthSess)
	for _, method := range []string{"resources/list", "prompts/list"} {
		raw, err := unauthSess.Do(ctx, method, map[string]any{})
		if err != nil || raw.StatusCode != 200 {
			continue
		}
		var envelope struct {
			Result map[string]json.RawMessage `json:"result"`
			Error  *rpcError                  `json:"error"`
		}
		if err := json.Unmarshal(raw.Body, &envelope); err != nil || envelope.Error != nil {
			continue
		}
		var count int
		for _, v := range envelope.Result {
			var arr []json.RawMessage
			if json.Unmarshal(v, &arr) == nil {
				count += len(arr)
			}
		}
		if count == 0 {
			continue
		}
		r.AddFinding(report.Finding{
			ID:          p.ID() + "-" + strings.ReplaceAll(method, "/", "-"),
			Title:       fmt.Sprintf("Unauthenticated %s returns %d item(s)", method, count),
			Severity:    report.SeverityLow,
			Confidence:  "high",
			Protocol:    "mcp",
			ASI:         []string{"ASI02"},
			Description: fmt.Sprintf("%s succeeded without credentials and returned %d item(s) to an anonymous caller.", method, count),
			Evidence:    map[string]any{"method": method, "item_count": count},
			Request: &report.HTTPExchange{
				Method:      "POST",
				URL:         s.TargetURL(),
				Body:        reproBody(method, map[string]any{}),
				StatusCode:  raw.StatusCode,
				ContentType: raw.Headers.Get("Content-Type"),
				BodySize:    len(raw.Body),
				Expected:    "401/403 for an anonymous " + method + " call",
			},
			Remediation: "Gate resource/prompt listings behind authentication if their contents aren't meant to be public.",
			Source:      "builtin:mcp",
			Tags:        []string{"auth", "enumeration"},
		})
	}
	return nil
}

// --- dynamic-dispatch ---------------------------------------------------

// This probe detects the dynamic-dispatch pattern in MCP tool listings.
// The implementation must not invoke any tool; it only inspects the declared
// tools/list response.
//
// The previous logic was too narrow: it only emitted when one exact search tool
// and one exact dispatcher were both found, and it matched dispatcher schemas by
// a small set of field names. That missed valid patterns such as name variants
// like toolName/action, and it failed to treat a generic dispatcher alone as
// suspicious.
//
// The current heuristic looks for two independent signals across the full tool
// list:
//   - Signal A: a catalog/search tool whose name or description signals discovery
//     of OTHER tools/operations.
//   - Signal B: a generic executor whose inputSchema declares a required string
//     identifier plus a permissive/freeform object arguments field.
//
// If both signals are present, this is a strong indicator that tools/list
// undercounts the real capability surface. If only the executor signal exists,
// it is still suspicious and raises a lower-severity finding.
//
// This is pattern-matching on conventions and can be evaded by operators who
// deliberately avoid these naming/schema signals.
type dynamicDispatchProbe struct{}

func (p *dynamicDispatchProbe) ID() string           { return "mcp-dynamic-dispatch" }
func (p *dynamicDispatchProbe) Protocol() string     { return "mcp" }
func (p *dynamicDispatchProbe) Transports() []string { return anyTransport }

func (p *dynamicDispatchProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	raw, err := s.Do(ctx, "tools/list", map[string]any{})
	if err != nil || raw.StatusCode != 200 {
		return nil
	}

	var envelope struct {
		Result struct {
			Tools []map[string]any `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw.Body, &envelope); err != nil {
		return nil
	}

	tools := envelope.Result.Tools
	if len(tools) == 0 {
		return nil
	}

	var searchTools []string
	var dispatcherTools []string
	var highRisk bool

	for _, tool := range tools {
		name, ok := tool["name"].(string)
		if !ok {
			continue
		}
		if isSearchTool(tool) {
			searchTools = append(searchTools, name)
		}
		if isDispatcherTool(tool) {
			dispatcherTools = append(dispatcherTools, name)
			if hasHighRiskDispatcherAnnotations(tool) {
				highRisk = true
			}
		}
	}

	if len(dispatcherTools) == 0 {
		return nil
	}

	severity := report.SeverityLow
	if len(searchTools) > 0 {
		severity = report.SeverityMedium
		if highRisk {
			severity = report.SeverityHigh
		}
	}

	description := fmt.Sprintf(
		"A generic executor tool was detected: %s. This suggests the true callable surface may exceed the static tools/list inventory.",
		joinNames(dispatcherTools),
	)
	if len(searchTools) > 0 {
		description = fmt.Sprintf(
			"Discovery tool(s) %s and executor tool(s) %s were detected. This indicates tools/list likely undercounts the real capability surface because callable tools can be reached through search + dispatch.",
			joinNames(searchTools),
			joinNames(dispatcherTools),
		)
	}

	r.AddFinding(report.Finding{
		ID:          p.ID(),
		Title:       "Enumerated MCP tool surface is likely incomplete (dynamic dispatch detected)",
		Severity:    severity,
		Confidence:  "medium", // naming/schema-convention heuristic, deliberately evadable — see package comment above
		Protocol:    "mcp",
		ASI:         []string{"ASI09"},
		Description: description,
		Evidence: map[string]any{
			"search_tools":   searchTools,
			"dispatch_tools": dispatcherTools,
		},
		Request: &report.HTTPExchange{
			Method:      "POST",
			URL:         s.TargetURL(),
			Body:        reproBody("tools/list", map[string]any{}),
			StatusCode:  raw.StatusCode,
			ContentType: raw.Headers.Get("Content-Type"),
			BodySize:    len(raw.Body),
		},
		Remediation: "Expose a complete dispatchable tool manifest or provide a discoverable read-only tool inventory (for example, an extended list endpoint) so downstream security tooling can account for the full surface.",
		Source:      "builtin:mcp",
		Tags:        []string{"inventory", "capability-surface"},
	})

	return nil
}

func joinNames(names []string) string {
	return strings.Join(names, ", ")
}

// isDispatcherTool checks if a tool schema exhibits dispatcher characteristics:
// - has a required string identifier property for the target tool name
// - has a freeform object property for dispatched arguments
func isDispatcherTool(tool map[string]any) bool {
	inputSchema, ok := tool["inputSchema"].(map[string]any)
	if !ok {
		return false
	}

	properties, ok := inputSchema["properties"].(map[string]any)
	if !ok {
		return false
	}

	if !hasRequiredIdentifierProperty(inputSchema, properties) {
		return false
	}

	for _, argFieldCandidate := range []string{"arguments", "args", "params", "input", "options", "config"} {
		if prop, ok := properties[argFieldCandidate].(map[string]any); ok {
			if propType, ok := prop["type"].(string); ok && propType == "object" {
				if hasFreeformObjectShape(prop) {
					return true
				}
			}
		}
	}

	return false
}

func hasRequiredIdentifierProperty(inputSchema, properties map[string]any) bool {
	required, _ := inputSchema["required"].([]any)
	requiredSet := map[string]bool{}
	for _, item := range required {
		if s, ok := item.(string); ok {
			requiredSet[s] = true
		}
	}

	for _, idFieldCandidate := range []string{"name", "tool", "toolName", "tool_name", "operation", "action", "command"} {
		if !requiredSet[idFieldCandidate] {
			continue
		}
		if prop, ok := properties[idFieldCandidate].(map[string]any); ok {
			if propType, ok := prop["type"].(string); ok && propType == "string" {
				return true
			}
		}
	}
	return false
}

func hasFreeformObjectShape(prop map[string]any) bool {
	if addProps, ok := prop["additionalProperties"]; ok {
		if b, ok := addProps.(bool); ok && b {
			return true
		}
		if m, ok := addProps.(map[string]any); ok && len(m) == 0 {
			return true
		}
	}

	if innerProps, ok := prop["properties"].(map[string]any); !ok || len(innerProps) == 0 {
		return true
	}

	return false
}

func hasHighRiskDispatcherAnnotations(tool map[string]any) bool {
	annotations, ok := tool["annotations"].(map[string]any)
	if !ok {
		return false
	}
	if readOnly, ok := annotations["readOnlyHint"].(bool); ok && !readOnly {
		return true
	}
	if destructive, ok := annotations["destructiveHint"].(bool); ok && destructive {
		return true
	}
	return false
}

func isSearchTool(tool map[string]any) bool {
	name, _ := tool["name"].(string)
	description, _ := tool["description"].(string)
	text := strings.ToLower(name + " " + description)

	searchPhrases := []string{
		"not exposed as top-level tools",
		"find the right operation",
		"available tool catalog",
		"tool catalog",
		"discover catalog",
		"catalog tools",
	}
	for _, phrase := range searchPhrases {
		if strings.Contains(text, phrase) {
			return true
		}
	}

	searchHints := []string{"search", "discover", "find", "catalog", "lookup"}
	targetHints := []string{"tool", "tools", "operation", "capability"}
	if hasAny(text, searchHints) && hasAny(text, targetHints) {
		return hasQueryStringProperty(tool)
	}

	return false
}

func hasAny(text string, terms []string) bool {
	for _, term := range terms {
		if strings.Contains(text, term) {
			return true
		}
	}
	return false
}

func hasQueryStringProperty(tool map[string]any) bool {
	inputSchema, ok := tool["inputSchema"].(map[string]any)
	if !ok {
		return false
	}
	properties, ok := inputSchema["properties"].(map[string]any)
	if !ok {
		return false
	}
	for _, candidate := range []string{"query", "search", "term", "filter"} {
		if prop, ok := properties[candidate].(map[string]any); ok {
			if propType, ok := prop["type"].(string); ok && propType == "string" {
				return true
			}
		}
	}
	return false
}

// negotiatedOr returns the protocol version the session actually negotiated,
// falling back to fallback for sessions that aren't the streamable-HTTP
// implementation (or haven't handshaken yet).
func negotiatedOr(s probe.Session, fallback string) string {
	if ms, ok := s.(*Session); ok {
		if v := ms.NegotiatedVersion(); v != "" {
			return v
		}
	}
	return fallback
}

// hostHeaderSeverity rates missing Host validation.
//
// Almost nothing behind an ingress or load balancer sees, let alone validates,
// the original Host header, so a blanket HIGH made this check a permanent
// noise floor rather than a signal. HIGH is reserved for loopback targets,
// where a browser-driven DNS-rebinding attack reaches a local agent directly
// and the finding is genuinely actionable.
func hostHeaderSeverity(target string) report.Severity {
	if isLoopbackTarget(target) {
		return report.SeverityHigh
	}
	return report.SeverityMedium
}

func isLoopbackTarget(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// describeSessionIDShape summarises a session ID without disclosing it: a
// character-class skeleton such as "aaaa999" for "sess001".
func describeSessionIDShape(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case unicode.IsDigit(r):
			b.WriteRune('9')
		case unicode.IsLower(r):
			b.WriteRune('a')
		case unicode.IsUpper(r):
			b.WriteRune('A')
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}

// isAuthRejection reports whether a response is the server declining for lack
// of credentials, as opposed to any other failure. Both the HTTP status and
// the JSON-RPC error are checked because MCP servers signal this either way.
func isAuthRejection(status int, rpcErr *rpcError) bool {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return true
	}
	if rpcErr == nil {
		return false
	}
	m := strings.ToLower(rpcErr.Message)
	for _, hint := range []string{"unauthorized", "unauthenticated", "authentication", "auth required", "forbidden", "access denied", "permission", "invalid token", "missing token", "api key"} {
		if strings.Contains(m, hint) {
			return true
		}
	}
	return false
}

// IsAuthGated reports whether a raw response is the server declining for lack
// of credentials rather than failing. The CLI uses it to keep an auth-gated
// handshake out of the report's error list: a gated endpoint is a successful
// recon result, not a tool failure, and must not make the process exit nonzero.
func IsAuthGated(raw *probe.RawResult) bool {
	if raw == nil {
		return false
	}
	var envelope struct {
		Error *rpcError `json:"error"`
	}
	_ = json.Unmarshal(raw.Body, &envelope)
	return isAuthRejection(raw.StatusCode, envelope.Error)
}

// --- auth-posture -------------------------------------------------------

// authPostureProbe establishes the single most useful recon fact about an
// agent endpoint: does capability enumeration answer a stranger, does it
// require credentials, or does it not answer at all?
//
// This used to be implicit. An auth-gated endpoint produced an "initialize
// handshake failed" entry in the report's error list and a nonzero exit code,
// which framed correct behaviour as a tool failure and left the endpoint's
// actual posture to be inferred from an error string.
type authPostureProbe struct{}

func (p *authPostureProbe) ID() string           { return "mcp-auth-posture" }
func (p *authPostureProbe) Protocol() string     { return "mcp" }
func (p *authPostureProbe) Transports() []string { return anyTransport }

func (p *authPostureProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	// Determine anonymous reach over a fresh, unauthenticated connection.
	// WithNoAuth on the authenticated session cannot undo transport state
	// bound at connect time (a WebSocket authenticated during its upgrade),
	// which would otherwise report a credentialed tool listing as "open."
	unauthSess, sessErr := anonymousSession(s)
	if sessErr != nil {
		// No anonymous connection can be formed at all — e.g. a WebSocket
		// whose credentials are bound to the handshake refused an anonymous
		// upgrade. That is the answer: an anonymous caller cannot enumerate.
		r.Target.AuthState = report.AuthStateGated
		if authed, authErr := listAll(ctx, s, "tools/list", "tools"); authErr == nil && authed.OK() {
			r.Target.AuthState = report.AuthStateAuthed
		}
		return nil
	}
	defer closeSession(unauthSess)

	anon, err := listAll(ctx, unauthSess, "tools/list", "tools")
	if err != nil {
		r.Target.AuthState = report.AuthStateUnreached
		return fmt.Errorf("anonymous tools/list failed: %w", err)
	}

	if anon.OK() {
		r.Target.AuthState = report.AuthStateOpen
		return nil
	}
	if !isAuthRejection(anon.FirstStatus, anon.RPCError) {
		r.Target.AuthState = report.AuthStateUnknown
		return nil
	}

	// Enumeration is gated. If credentials were supplied and they work, say
	// so — "gated and we have keys" is a materially different recon result
	// from "gated and we're locked out".
	r.Target.AuthState = report.AuthStateGated
	if authed, authErr := listAll(ctx, s, "tools/list", "tools"); authErr == nil && authed.OK() {
		r.Target.AuthState = report.AuthStateAuthed
	}

	// The mcp-enumeration-blocked finding itself is emitted by
	// toolCapabilitySurfaceProbe, which has the reproduction exchange to
	// attach to it. This probe's job is the Target.AuthState field.
	return nil
}
