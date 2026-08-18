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
	"strings"
	"unicode"

	"github.com/hackwither/reap/internal/probe"
	"github.com/hackwither/reap/internal/report"
)

// BuiltinProbes returns every MCP-specific probe.
//
// Transport-level checks (TLS health, plaintext, downgrade, CORS, rate-limit
// headers) used to live here with mcp- IDs even though none of them look at a
// single byte of MCP. They now live in internal/probe/transport with
// Protocol() == "*", so they apply to any protocol reap can identify. See
// docs/ARCHITECTURE.md.
func BuiltinProbes() []probe.Probe {
	return []probe.Probe{
		&authPostureProbe{},
		&unauthToolsListProbe{},
		&toolCapabilitySurfaceProbe{},
		&hostHeaderValidationProbe{},
		&oauthMetadataPostureProbe{},
		&oauthBearerChallengeProbe{},
		&redirectUriLaxityProbe{},
		&sessionIDEntropyProbe{},
		&instructionsExposureProbe{},
		&resourcesPromptsExposureProbe{},
		&dynamicDispatchProbe{},
	}
}

func asSession(s probe.Session) (*Session, error) {
	ms, ok := s.(*Session)
	if !ok {
		return nil, probe.NotApplicable("probe requires an MCP session, got %T", s)
	}
	return ms, nil
}

// IsAuthGated reports whether a raw response is the server declining for lack
// of credentials rather than failing.
//
// The CLI uses this to decide whether a failed handshake belongs in the
// report's error list. An auth-gated endpoint is a successful recon result,
// not a tool failure, and must not make the process exit nonzero.
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

// --- auth-posture -------------------------------------------------------

// authPostureProbe establishes the single most useful recon fact about an
// agent endpoint: does capability enumeration answer a stranger, does it
// require credentials, or does it not answer at all?
//
// This used to be implicit. An auth-gated endpoint produced an "initialize
// handshake failed" entry in the report's error list and a nonzero exit code,
// which framed correct behaviour as a tool failure and made the endpoint's
// actual posture something the operator had to infer from an error string.
type authPostureProbe struct{}

func (p *authPostureProbe) ID() string       { return "mcp-auth-posture" }
func (p *authPostureProbe) Protocol() string { return "mcp" }

func (p *authPostureProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	anon, err := listAll(ctx, s, "tools/list", "tools", probe.WithNoAuth())
	if err != nil {
		r.Target.AuthState = report.AuthStateUnreached
		return fmt.Errorf("anonymous tools/list failed: %w", err)
	}

	if anon.OK() {
		r.Target.AuthState = report.AuthStateOpen
		return nil
	}

	gated := isAuthRejection(anon.FirstStatus, anon.RPCError)
	if !gated {
		r.Target.AuthState = report.AuthStateUnknown
		return nil
	}

	// Enumeration is gated. If credentials were supplied and they work, say
	// so — "gated and we have keys" is a materially different recon result
	// from "gated and we're locked out".
	r.Target.AuthState = report.AuthStateGated
	authed, authErr := listAll(ctx, s, "tools/list", "tools")
	if authErr == nil && authed.OK() {
		r.Target.AuthState = report.AuthStateAuthed
	}

	detail := fmt.Sprintf("HTTP %d", anon.FirstStatus)
	if anon.RPCError != nil {
		detail = fmt.Sprintf("%s, JSON-RPC error %d: %s", detail, anon.RPCError.Code, anon.RPCError.Message)
	}
	r.AddFinding(report.Finding{
		ID:          "mcp-enumeration-blocked",
		Title:       "MCP capability enumeration is gated behind authentication",
		Severity:    report.SeverityInfo,
		Protocol:    "mcp",
		Description: fmt.Sprintf("An anonymous tools/list was refused (%s). The endpoint is live and speaking MCP, but will not enumerate its capability surface without credentials. This is the expected posture for a non-public server, and is recorded so an empty finding list is not mistaken for an unreachable target.", detail),
		Evidence: map[string]any{
			"status":     anon.FirstStatus,
			"auth_state": r.Target.AuthState,
		},
		Source: "builtin:mcp",
		Tags:   []string{"auth", "enumeration", "recon"},
	})
	return nil
}

// --- unauth-tools-list ------------------------------------------------

type unauthToolsListProbe struct{}

func (p *unauthToolsListProbe) ID() string       { return "mcp-unauth-tools-list" }
func (p *unauthToolsListProbe) Protocol() string { return "mcp" }

func (p *unauthToolsListProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	// Re-issue tools/list explicitly WITHOUT the auth header, regardless of
	// whether the initial handshake used one. This answers the specific
	// question: "can an anonymous caller enumerate tools?"
	res, err := listAll(ctx, s, "tools/list", "tools", probe.WithNoAuth())
	if err != nil {
		return fmt.Errorf("anonymous tools/list failed: %w", err)
	}
	if !res.OK() {
		return nil // server rejected the anonymous call — good, nothing to report
	}
	if len(res.Items) == 0 {
		return nil
	}

	names := toolNames(res.Items)
	sev := report.SeverityMedium
	if hasHighRiskTool(names) {
		sev = report.SeverityHigh
	}

	desc := fmt.Sprintf("tools/list returned %d tool(s) to an unauthenticated caller: %s", len(names), strings.Join(names, ", "))
	if res.Truncated {
		desc += " (list was truncated at reap's pagination cap; the real count is higher)"
	}

	r.AddFinding(report.Finding{
		ID:          p.ID(),
		Title:       "MCP tool listing accessible without authentication",
		Severity:    sev,
		Protocol:    "mcp",
		ASI:         []string{"ASI02", "ASI03"},
		Description: desc,
		Evidence: map[string]any{
			"tool_count": len(names),
			"tool_names": names,
			"pages":      res.Pages,
			"truncated":  res.Truncated,
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

// --- tool-capability-surface -------------------------------------------

// This probe doesn't flag a vulnerability by itself — it records the full
// tool surface so the report is a useful asset inventory even when nothing
// else fires. It also populates report.Target.Capabilities, which is what the
// identification block at the top of the human output renders.
type toolCapabilitySurfaceProbe struct{}

func (p *toolCapabilitySurfaceProbe) ID() string       { return "mcp-tool-capability-surface" }
func (p *toolCapabilitySurfaceProbe) Protocol() string { return "mcp" }

func (p *toolCapabilitySurfaceProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	tools, err := listAll(ctx, s, "tools/list", "tools")
	if err != nil {
		return fmt.Errorf("tools/list failed: %w", err)
	}
	if !tools.OK() {
		return probe.NotApplicable("tools/list did not return an enumerable listing (HTTP %d)", tools.FirstStatus)
	}

	summary := &report.CapabilitySummary{Tools: len(tools.Items), Truncated: tools.Truncated}
	for _, spec := range []struct {
		method string
		field  string
		count  *int
	}{
		{"resources/list", "resources", &summary.Resources},
		{"prompts/list", "prompts", &summary.Prompts},
	} {
		res, listErr := listAll(ctx, s, spec.method, spec.field)
		if listErr != nil || !res.OK() {
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
		Protocol:    "mcp",
		ASI:         []string{"ASI09"},
		Description: "Full tool surface exposed by this endpoint, for asset-inventory and diffing purposes.",
		Evidence: map[string]any{
			"tools":     tools.Items,
			"pages":     tools.Pages,
			"truncated": tools.Truncated,
		},
		Source: "builtin:mcp",
		Tags:   []string{"inventory"},
	})
	return nil
}

// --- host-header-validation -------------------------------------------

// The MCP spec recommends validating the Host header to defend browser-based
// clients against DNS rebinding. Absence of that validation is worth
// reporting, but it is not the near-universal HIGH it was originally rated:
// most servers behind an ingress or load balancer never see, let alone
// validate, the original Host, so a blanket HIGH made this a permanent noise
// floor. It stays HIGH only for loopback targets, where rebinding is directly
// exploitable against a local agent.
type hostHeaderValidationProbe struct{}

func (p *hostHeaderValidationProbe) ID() string       { return "mcp-host-header-validation" }
func (p *hostHeaderValidationProbe) Protocol() string { return "mcp" }

func (p *hostHeaderValidationProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	ms, err := asSession(s)
	if err != nil {
		return err
	}
	version := ms.NegotiatedVersion()
	if version == "" {
		version = SupportedProtocolVersions[0]
	}

	foreignHost := "host-header-validation.invalid"
	raw, err := s.Do(ctx, "initialize", initializeParams(version), probe.WithHeader("Host", foreignHost))
	if err != nil {
		return fmt.Errorf("initialize with foreign Host failed: %w", err)
	}
	if raw.StatusCode != http.StatusOK {
		return nil // server refused the mismatched Host — correct behaviour
	}

	var envelope struct {
		Result InitializeResult `json:"result"`
		Error  *rpcError        `json:"error"`
	}
	if err := json.Unmarshal(raw.Body, &envelope); err != nil {
		return probe.NotApplicable("could not decode initialize response: %v", err)
	}
	if envelope.Error != nil {
		return nil
	}

	severity := report.SeverityMedium
	if isLoopbackTarget(ms.TargetURL()) {
		severity = report.SeverityHigh
	}

	r.AddFinding(report.Finding{
		ID:          p.ID(),
		Title:       "MCP accepted initialize with a mismatched Host header",
		Severity:    severity,
		Protocol:    "mcp",
		ASI:         []string{"ASI03"},
		Description: fmt.Sprintf("The server processed an initialize request even though the Host header was set to %q, so it does not validate the requested host name before handling MCP traffic. This is the condition DNS-rebinding protection is meant to prevent; it is rated high only for loopback endpoints, where a browser-based rebinding attack reaches a local agent directly.", foreignHost),
		Evidence: map[string]any{
			"tested_host_header": foreignHost,
			"server_name":        envelope.Result.ServerInfo.Name,
			"server_version":     envelope.Result.ServerInfo.Version,
			"loopback_target":    isLoopbackTarget(ms.TargetURL()),
		},
		Remediation: "Validate the Host header (or equivalent request target) before accepting MCP requests, and refuse requests whose host name does not match the configured endpoint.",
		Source:      "builtin:mcp",
		Tags:        []string{"transport", "host-header", "dns-rebinding"},
	})
	return nil
}

// isLoopbackTarget reports whether a URL points at the local machine.
func isLoopbackTarget(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// --- oauth metadata -----------------------------------------------------

// wellKnownPaths returns the OAuth metadata locations to try for a target.
//
// RFC 9728 makes protected-resource metadata path-aware: the document for
// resource https://host/mcp lives at /.well-known/oauth-protected-resource/mcp,
// not at the host root. reap only checked the root, so it missed the metadata
// on most real deployments — and then drew conclusions from the absence.
func wellKnownPaths(target *url.URL) []string {
	paths := []string{}
	if p := strings.Trim(target.Path, "/"); p != "" {
		paths = append(paths, "/.well-known/oauth-protected-resource/"+p)
	}
	return append(paths,
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-authorization-server",
	)
}

type oauthMetadataPostureProbe struct{}

func (p *oauthMetadataPostureProbe) ID() string       { return "mcp-oauth-metadata-posture" }
func (p *oauthMetadataPostureProbe) Protocol() string { return "mcp" }

func (p *oauthMetadataPostureProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	ms, err := asSession(s)
	if err != nil {
		return err
	}
	u, err := url.Parse(ms.TargetURL())
	if err != nil {
		return probe.NotApplicable("target URL is unparseable: %v", err)
	}

	baseURL := u.Scheme + "://" + u.Host
	observed := []string{}
	pkceAdvertised := false
	for _, pth := range wellKnownPaths(u) {
		metadata, _, status, err := fetchWellKnownJSON(ctx, ms, baseURL, pth)
		if err != nil || status != http.StatusOK {
			continue
		}
		observed = append(observed, pth)
		if supportsPKCE(metadata) {
			pkceAdvertised = true
		}
	}

	if len(observed) == 0 {
		return probe.NotApplicable("no OAuth metadata document was reachable")
	}
	if pkceAdvertised {
		return nil
	}

	r.AddFinding(report.Finding{
		ID:          p.ID(),
		Title:       "OAuth metadata does not advertise PKCE support",
		Severity:    report.SeverityLow,
		Protocol:    "mcp",
		ASI:         []string{"ASI03"},
		Description: fmt.Sprintf("OAuth metadata was published at %s, but none of the documents advertise PKCE (code_challenge_methods_supported containing S256). MCP clients are public clients, for which PKCE is required rather than optional.", strings.Join(observed, ", ")),
		Evidence:    map[string]any{"observed_paths": observed, "pkce_advertised": false},
		Remediation: "Advertise code_challenge_methods_supported: [\"S256\"] in the authorization server metadata and require PKCE for authorization code flows.",
		Source:      "builtin:mcp",
		Tags:        []string{"oauth", "authn", "pkce"},
	})
	return nil
}

// --- oauth bearer challenge --------------------------------------------

// oauthBearerChallengeProbe checks the place the challenge actually lives.
//
// This check previously read WWW-Authenticate off the /.well-known/* GET
// response, where it never appears — a 200 metadata document has no reason to
// carry an authentication challenge. The result was a finding that fired on
// every server publishing OAuth metadata, including correctly-configured ones.
// RFC 9728 and the MCP authorization spec put the challenge on the protected
// resource's own 401, so that is what reap now inspects.
type oauthBearerChallengeProbe struct{}

func (p *oauthBearerChallengeProbe) ID() string       { return "mcp-oauth-bearer-challenge-missing" }
func (p *oauthBearerChallengeProbe) Protocol() string { return "mcp" }

func (p *oauthBearerChallengeProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	res, err := listAll(ctx, s, "tools/list", "tools", probe.WithNoAuth())
	if err != nil {
		return fmt.Errorf("anonymous tools/list failed: %w", err)
	}
	if !isAuthRejection(res.FirstStatus, res.RPCError) {
		// Nothing was refused, so there is no challenge to be missing. An
		// open endpoint is reported by mcp-unauth-tools-list instead.
		return probe.NotApplicable("endpoint did not refuse the anonymous request, so no challenge is expected")
	}
	if res.FirstStatus != http.StatusUnauthorized {
		// A JSON-RPC-level refusal with a 200/400 is out of scope: WWW-Authenticate
		// is only meaningful alongside a 401.
		return probe.NotApplicable("refusal was not an HTTP 401 (got %d)", res.FirstStatus)
	}

	challenge := ""
	if res.FirstHeaders != nil {
		challenge = res.FirstHeaders.Get("WWW-Authenticate")
	}
	if strings.Contains(strings.ToLower(challenge), "bearer") {
		return nil
	}

	r.AddFinding(report.Finding{
		ID:          p.ID(),
		Title:       "MCP endpoint returns 401 without a Bearer WWW-Authenticate challenge",
		Severity:    report.SeverityMedium,
		Protocol:    "mcp",
		ASI:         []string{"ASI03"},
		Description: "An unauthenticated tools/list was refused with HTTP 401, but the response carried no 'WWW-Authenticate: Bearer' header. Clients cannot discover where to authenticate, so they cannot begin the OAuth flow the MCP authorization spec describes.",
		Evidence: map[string]any{
			"status":               res.FirstStatus,
			"www_authenticate":     challenge,
			"www_authenticate_set": challenge != "",
		},
		Remediation: "Return 'WWW-Authenticate: Bearer resource_metadata=\"<protected-resource-metadata-url>\"' alongside the 401, per RFC 9728 and the MCP authorization specification.",
		Source:      "builtin:mcp",
		Tags:        []string{"oauth", "authn", "discovery"},
	})
	return nil
}

func fetchWellKnownJSON(ctx context.Context, ms *Session, baseURL, path string) (map[string]any, http.Header, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+path, nil)
	if err != nil {
		return nil, nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := ms.client.HTTP().Do(req)
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, resp.Header, resp.StatusCode, err
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

func (p *redirectUriLaxityProbe) ID() string       { return "mcp-redirect-uri-laxity" }
func (p *redirectUriLaxityProbe) Protocol() string { return "mcp" }

func (p *redirectUriLaxityProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	ms, err := asSession(s)
	if err != nil {
		return err
	}
	u, err := url.Parse(ms.TargetURL())
	if err != nil {
		return probe.NotApplicable("target URL is unparseable: %v", err)
	}
	baseURL := u.Scheme + "://" + u.Host

	redirectURIs := []string{}
	found := false
	for _, pth := range wellKnownPaths(u) {
		metadata, _, status, err := fetchWellKnownJSON(ctx, ms, baseURL, pth)
		if err != nil || status != http.StatusOK || metadata == nil {
			continue
		}
		found = true
		redirectURIs = append(redirectURIs, findRedirectURIs(metadata)...)
	}
	if !found {
		return probe.NotApplicable("no OAuth metadata document was reachable")
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
		Protocol:    "mcp",
		ASI:         []string{"ASI03"},
		Description: "The discovered OAuth metadata includes redirect URIs that are broad or wildcarded, which increases the risk of confused-deputy or open redirect abuse.",
		Evidence:    map[string]any{"redirect_uris": broad},
		Remediation: "Restrict registered redirect URIs to exact allowed origins and paths, and avoid wildcards or overly permissive URL patterns.",
		Source:      "builtin:mcp",
		Tags:        []string{"oauth", "redirect-uri"},
	})
	return nil
}

func findRedirectURIs(value any) []string {
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
			out = append(out, findRedirectURIs(child)...)
		}
	case []any:
		for _, item := range v {
			out = append(out, findRedirectURIs(item)...)
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
	// Loopback redirects are how native MCP clients are supposed to work
	// (RFC 8252), so http://127.0.0.1/... is correct rather than lax.
	if parsed.Scheme == "http" && isBroadRedirectLoopback(parsed.Hostname()) {
		return false
	}
	if parsed.Scheme != "https" {
		return true
	}
	if parsed.Host == "" {
		return true
	}
	if parsed.Path == "" || parsed.Path == "/" {
		return true
	}
	return false
}

func isBroadRedirectLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// --- session-id-entropy -------------------------------------------------

type sessionIDEntropyProbe struct{}

func (p *sessionIDEntropyProbe) ID() string       { return "mcp-session-id-entropy" }
func (p *sessionIDEntropyProbe) Protocol() string { return "mcp" }

func (p *sessionIDEntropyProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	ms, err := asSession(s)
	if err != nil {
		return err
	}
	sessionID := ms.SessionID()
	if sessionID == "" {
		return probe.NotApplicable("server issued no Mcp-Session-Id")
	}

	issues, entropy := analyzeSessionID(sessionID)
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
		Protocol:    "mcp",
		ASI:         []string{"ASI03"},
		Description: fmt.Sprintf("The MCP session ID returned by the server appears to have low entropy or a predictable format: %s", strings.Join(issues, ", ")),
		// The session ID itself is deliberately NOT recorded. It is a live
		// credential, and reports get uploaded to code-scanning dashboards and
		// pasted into tickets. The shape is enough to justify the finding.
		Evidence: map[string]any{
			"session_id_shape":       describeSessionIDShape(sessionID),
			"session_id_length":      len(sessionID),
			"estimated_entropy_bits": entropy,
			"issues":                 issues,
		},
		Remediation: "Use a cryptographically random, high-entropy session identifier for MCP sessions and avoid sequential or human-readable formats.",
		Source:      "builtin:mcp",
		Tags:        []string{"session", "auth"},
	})
	return nil
}

// describeSessionIDShape summarises a session ID without disclosing it: a
// character-class skeleton such as "aaaa9999" for "sess0012".
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

// analyzeSessionID estimates how guessable a session ID is.
//
// Entropy is computed against the *inferred alphabet*, not the count of
// distinct characters actually present. Counting distinct characters
// systematically misjudges good identifiers: a random 32-character hex string
// carries 128 bits, but by the birthday problem it contains only ~14 of the 16
// hex digits, so a "fewer than 16 distinct characters" rule flagged it as weak.
// The same rule fired on every hex and base32 ID reap ever saw.
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
			hexOnly = false
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
		return 16 // hex
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

// --- instructions-exposure --------------------------------------------

// The MCP initialize response has an optional free-text "instructions"
// field servers may use to steer client models. If it contains material
// that reads like an internal system prompt (not just usage docs), that's
// worth surfacing — an unauthenticated caller doesn't need to guess a
// prompt if the server hands it over during the handshake.
type instructionsExposureProbe struct{}

func (p *instructionsExposureProbe) ID() string       { return "mcp-instructions-exposure" }
func (p *instructionsExposureProbe) Protocol() string { return "mcp" }

func (p *instructionsExposureProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	ms, err := asSession(s)
	if err != nil {
		return err
	}
	init, raw, err := ms.Initialize(ctx)
	if err != nil {
		return probe.NotApplicable("handshake did not succeed: %v", err)
	}
	if raw == nil || raw.StatusCode != http.StatusOK || init == nil {
		return probe.NotApplicable("no usable initialize response")
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
		Protocol:    "mcp",
		ASI:         []string{"ASI09"},
		Description: "The initialize response's 'instructions' field is long and/or contains language patterns (secrecy directives, 'internal', credential-related terms) worth a human review to confirm it isn't leaking operational or internal detail to any caller.",
		Evidence:    map[string]any{"instructions_length": len(init.Instructions), "instructions_excerpt": excerpt(init.Instructions, 200)},
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

func (p *resourcesPromptsExposureProbe) ID() string       { return "mcp-resources-prompts-exposure" }
func (p *resourcesPromptsExposureProbe) Protocol() string { return "mcp" }

func (p *resourcesPromptsExposureProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	applicable := false
	for _, spec := range []struct{ method, field string }{
		{"resources/list", "resources"},
		{"prompts/list", "prompts"},
	} {
		res, err := listAll(ctx, s, spec.method, spec.field, probe.WithNoAuth())
		if err != nil {
			return fmt.Errorf("anonymous %s failed: %w", spec.method, err)
		}
		if !res.OK() {
			continue
		}
		applicable = true
		if len(res.Items) == 0 {
			continue
		}
		r.AddFinding(report.Finding{
			ID:          p.ID() + "-" + strings.ReplaceAll(spec.method, "/", "-"),
			Title:       fmt.Sprintf("Unauthenticated %s returns %d item(s)", spec.method, len(res.Items)),
			Severity:    report.SeverityLow,
			Protocol:    "mcp",
			ASI:         []string{"ASI02"},
			Description: fmt.Sprintf("%s succeeded without credentials and returned %d item(s) to an anonymous caller.", spec.method, len(res.Items)),
			Evidence:    map[string]any{"method": spec.method, "item_count": len(res.Items), "truncated": res.Truncated},
			Remediation: "Gate resource/prompt listings behind authentication if their contents aren't meant to be public.",
			Source:      "builtin:mcp",
			Tags:        []string{"auth", "enumeration"},
		})
	}
	if !applicable {
		return probe.NotApplicable("neither resources/list nor prompts/list answered an anonymous caller")
	}
	return nil
}

// --- dynamic-dispatch ---------------------------------------------------

// This probe detects the dynamic-dispatch pattern in MCP tool listings.
// The implementation must not invoke any tool; it only inspects the declared
// tools/list response.
//
// The heuristic looks for two independent signals across the full tool list:
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

func (p *dynamicDispatchProbe) ID() string       { return "mcp-dynamic-dispatch" }
func (p *dynamicDispatchProbe) Protocol() string { return "mcp" }

func (p *dynamicDispatchProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	res, err := listAll(ctx, s, "tools/list", "tools")
	if err != nil {
		return fmt.Errorf("tools/list failed: %w", err)
	}
	if !res.OK() {
		return probe.NotApplicable("tools/list did not return an enumerable listing (HTTP %d)", res.FirstStatus)
	}
	if len(res.Items) == 0 {
		return nil
	}

	var searchTools []string
	var dispatcherTools []string
	var highRisk bool

	for _, tool := range res.Items {
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
		strings.Join(dispatcherTools, ", "),
	)
	if len(searchTools) > 0 {
		description = fmt.Sprintf(
			"Discovery tool(s) %s and executor tool(s) %s were detected. This indicates tools/list likely undercounts the real capability surface because callable tools can be reached through search + dispatch.",
			strings.Join(searchTools, ", "),
			strings.Join(dispatcherTools, ", "),
		)
	}

	r.AddFinding(report.Finding{
		ID:          p.ID(),
		Title:       "Enumerated MCP tool surface is likely incomplete (dynamic dispatch detected)",
		Severity:    severity,
		Protocol:    "mcp",
		ASI:         []string{"ASI09"},
		Description: description,
		Evidence: map[string]any{
			"search_tools":   searchTools,
			"dispatch_tools": dispatcherTools,
		},
		Remediation: "Expose a complete dispatchable tool manifest or provide a discoverable read-only tool inventory (for example, an extended list endpoint) so downstream security tooling can account for the full surface.",
		Source:      "builtin:mcp",
		Tags:        []string{"inventory", "capability-surface"},
	})

	return nil
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
