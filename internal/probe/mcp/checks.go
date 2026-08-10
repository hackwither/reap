package mcp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/hackwither/reap/internal/probe"
	"github.com/hackwither/reap/internal/probe/common"
	"github.com/hackwither/reap/internal/report"
)

// All built-in probes registered by this package.
func BuiltinProbes() []probe.Probe {
	return []probe.Probe{
		&unauthToolsListProbe{},
		&toolCapabilitySurfaceProbe{},
		&corsWildcardProbe{},
		&plaintextTransportProbe{},
		&tlsCertHealthProbe{},
		&hostHeaderValidationProbe{},
		&rateLimitAbsenceProbe{},
		&transportDowngradeProbe{},
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

// streamableHTTPOnly is for probes that depend on a mechanism specific to
// the streamable-HTTP session implementation (e.g. the Mcp-Session-Id
// response header it captures) that has no equivalent in legacy-SSE or
// WebSocket sessions.
var streamableHTTPOnly = []string{"http-streamable"}

func initializeParams() map[string]any {
	return map[string]any{
		"protocolVersion": mcpProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "reap",
			"version": "0.1.0",
		},
	}
}

// --- tls-cert-health -----------------------------------------------------

type tlsCertHealthProbe struct{}

func (p *tlsCertHealthProbe) ID() string           { return "mcp-tls-cert-health" }
func (p *tlsCertHealthProbe) Protocol() string     { return "mcp" }
func (p *tlsCertHealthProbe) Transports() []string { return httpOnlyTransports }

func (p *tlsCertHealthProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	u, err := url.Parse(s.TargetURL())
	if err != nil || u.Scheme != "https" {
		return nil
	}

	state, cert, err := common.InspectTLS(ctx, s.TargetURL())
	if err != nil {
		return nil
	}

	issues := []string{}
	severity := report.SeverityLow
	if time.Now().After(cert.NotAfter) {
		issues = append(issues, "certificate is expired")
		severity = report.SeverityHigh
	}
	if time.Now().Before(cert.NotBefore) {
		issues = append(issues, "certificate is not yet valid")
		severity = report.SeverityHigh
	}
	if cert.IsCA {
		if err := cert.CheckSignatureFrom(cert); err == nil {
			issues = append(issues, "certificate is self-signed")
			severity = report.SeverityHigh
		}
	}
	if err := cert.VerifyHostname(u.Hostname()); err != nil {
		issues = append(issues, fmt.Sprintf("hostname mismatch: %v", err))
		if severity < report.SeverityMedium {
			severity = report.SeverityMedium
		}
	}
	if state.Version < tls.VersionTLS12 {
		issues = append(issues, fmt.Sprintf("weak TLS protocol version %s", common.TLSVersionName(state.Version)))
		if severity < report.SeverityMedium {
			severity = report.SeverityMedium
		}
	}
	if common.IsWeakCipherSuite(state.CipherSuite) {
		issues = append(issues, fmt.Sprintf("weak cipher suite %s", tls.CipherSuiteName(state.CipherSuite)))
		if severity < report.SeverityMedium {
			severity = report.SeverityMedium
		}
	}
	if len(issues) == 0 {
		return nil
	}

	r.AddFinding(report.Finding{
		ID:         p.ID(),
		Title:      "MCP TLS certificate health issues detected",
		Severity:   severity,
		Confidence: "high", // direct TLS handshake inspection, not a heuristic
		Protocol:   "mcp",
		ASI:        []string{"ASI09"},
		References: []string{"RFC 8446 (TLS 1.3)", "RFC 5280 (X.509 certificates)"},
		Description: fmt.Sprintf(
			"The TLS certificate for %s has one or more issues: %s.",
			u.Host,
			strings.Join(issues, "; "),
		),
		Evidence: map[string]any{
			"server_name":         u.Hostname(),
			"not_before":          cert.NotBefore,
			"not_after":           cert.NotAfter,
			"tls_version":         common.TLSVersionName(state.Version),
			"cipher_suite":        tls.CipherSuiteName(state.CipherSuite),
			"certificate_issuer":  cert.Issuer.CommonName,
			"certificate_subject": cert.Subject.CommonName,
		},
		// No HTTPExchange: this is a TLS-layer observation (openssl
		// s_client territory), not a single HTTP request/response — doesn't
		// fit the repro shape the way an HTTP-level finding does.
		Remediation: "Use a valid TLS certificate from a trusted authority, ensure the certificate matches the host name, and retire weak TLS versions and cipher suites.",
		Source:      "builtin:mcp",
		Tags:        []string{"transport", "tls"},
	})
	return nil
}

// --- host-header-validation -------------------------------------------

type hostHeaderValidationProbe struct{}

func (p *hostHeaderValidationProbe) ID() string           { return "mcp-host-header-validation" }
func (p *hostHeaderValidationProbe) Protocol() string     { return "mcp" }
func (p *hostHeaderValidationProbe) Transports() []string { return httpOnlyTransports }

func (p *hostHeaderValidationProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	foreignHost := "host-header-validation.invalid"
	raw, err := s.Do(ctx, "initialize", initializeParams(), probe.WithHeader("Host", foreignHost))
	if err != nil || raw.StatusCode != 200 {
		return nil
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
		Severity:    report.SeverityHigh,
		Confidence:  "high",
		Protocol:    "mcp",
		ASI:         []string{"ASI05"},
		Description: fmt.Sprintf("The server processed an initialize request even though the Host header was set to %q. This indicates the server may not validate the requested host name before handling MCP traffic.", foreignHost),
		Evidence: map[string]any{
			"tested_host_header": foreignHost,
			"server_name":        envelope.Result.ServerInfo.Name,
			"server_version":     envelope.Result.ServerInfo.Version,
		},
		Request: &report.HTTPExchange{
			Method:      "POST",
			URL:         s.TargetURL(),
			Headers:     map[string]string{"Host": foreignHost, "Content-Type": "application/json"},
			Body:        reproBody("initialize", initializeParams()),
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

// --- rate-limit-absence -------------------------------------------------

type rateLimitAbsenceProbe struct{}

func (p *rateLimitAbsenceProbe) ID() string           { return "mcp-rate-limit-absence" }
func (p *rateLimitAbsenceProbe) Protocol() string     { return "mcp" }
func (p *rateLimitAbsenceProbe) Transports() []string { return httpOnlyTransports }

func (p *rateLimitAbsenceProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	candidates := []string{"tools/list", "initialize"}
	observedMethods := []string{}
	var lastRaw *probe.RawResult
	var lastMethod string
	var lastParams any

	for _, method := range candidates {
		params := map[string]any{}
		if method == "initialize" {
			params = initializeParams()
		}
		raw, err := s.Do(ctx, method, params)
		if err != nil || raw.StatusCode != 200 {
			continue
		}
		if common.HasRateLimitHeader(raw.Headers) {
			return nil
		}
		observedMethods = append(observedMethods, method)
		lastRaw, lastMethod, lastParams = raw, method, params
	}

	if len(observedMethods) == 0 {
		return nil
	}

	f := report.Finding{
		ID:          p.ID(),
		Title:       "No standard rate-limit headers observed on MCP endpoints",
		Severity:    report.SeverityInfo,
		Confidence:  "medium", // absence-of-evidence signal, not a positive confirmation
		Protocol:    "mcp",
		ASI:         []string{"ASI08"},
		Description: "Normal MCP requests succeeded, but no standard rate-limit response headers were present. This is a reconnaissance signal that the service may not be advertising rate limiting to clients.",
		Evidence: map[string]any{
			"methods": observedMethods,
		},
		Remediation: "Expose standard rate-limit headers such as Retry-After, RateLimit-Remaining, and X-RateLimit-Limit, or document the expected client behavior when limits are reached.",
		Source:      "builtin:mcp",
		Tags:        []string{"rate-limit", "dos"},
	}
	if lastRaw != nil {
		f.Request = &report.HTTPExchange{
			Method:      "POST",
			URL:         s.TargetURL(),
			Body:        reproBody(lastMethod, lastParams),
			StatusCode:  lastRaw.StatusCode,
			ContentType: lastRaw.Headers.Get("Content-Type"),
			BodySize:    len(lastRaw.Body),
			Expected:    fmt.Sprintf("a rate-limit header (Retry-After, RateLimit-Remaining, ...) on the %s response", lastMethod),
		}
	}
	r.AddFinding(f)
	return nil
}

// --- transport-downgrade -------------------------------------------------

type transportDowngradeProbe struct{}

func (p *transportDowngradeProbe) ID() string           { return "mcp-transport-downgrade" }
func (p *transportDowngradeProbe) Protocol() string     { return "mcp" }
func (p *transportDowngradeProbe) Transports() []string { return httpOnlyTransports }

func (p *transportDowngradeProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	u, err := url.Parse(s.TargetURL())
	if err != nil || u.Scheme != "https" {
		return nil
	}

	paths := []string{u.Path}
	if u.Path != "/sse" {
		paths = append(paths, "/sse")
	}

	fallbacks, err := common.DetectPlaintextListeners(ctx, s.TargetURL(), paths)
	if err != nil {
		return nil
	}
	if len(fallbacks) == 0 {
		return nil
	}

	evidence := []map[string]any{}
	for _, fallback := range fallbacks {
		evidence = append(evidence, map[string]any{"path": fallback.Path, "status": fallback.StatusCode, "content_type": fallback.ContentType})
	}

	first := fallbacks[0]
	r.AddFinding(report.Finding{
		ID:          p.ID(),
		Title:       "MCP endpoint also responds over plaintext HTTP",
		Severity:    report.SeverityMedium,
		Confidence:  "high",
		Protocol:    "mcp",
		ASI:         []string{"ASI09"},
		Description: "The target host also accepted at least one plaintext HTTP path for MCP-style traffic, which undermines TLS protections.",
		Evidence:    map[string]any{"fallbacks": evidence},
		Request: &report.HTTPExchange{
			Method:      "GET",
			URL:         fmt.Sprintf("http://%s%s", u.Host, first.Path),
			StatusCode:  first.StatusCode,
			ContentType: first.ContentType,
			Expected:    "connection refused or a redirect to https://, not a 200 over plaintext",
		},
		Remediation: "Disable plaintext HTTP listeners for MCP endpoints and accept MCP traffic only over TLS.",
		Source:      "builtin:mcp",
		Tags:        []string{"transport", "downgrade"},
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
	unauthRaw, unauthErr := s.Do(ctx, "tools/list", map[string]any{}, probe.WithNoAuth())
	sawChallenge := unauthErr == nil && unauthRaw != nil && unauthRaw.StatusCode == http.StatusUnauthorized
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
	if ms.sessionID == "" {
		return nil
	}

	issues, entropy := analyzeSessionID(ms.sessionID)
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
			"session_id":             ms.sessionID,
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

func analyzeSessionID(id string) ([]string, float64) {
	issues := []string{}
	if len(id) < 16 {
		issues = append(issues, "session ID is shorter than 16 characters")
	}
	unique := map[rune]int{}
	for _, r := range id {
		unique[r]++
	}
	charset := float64(len(unique))
	if charset < 2 {
		issues = append(issues, "session ID uses too few unique characters")
	}
	if charset < 16 {
		issues = append(issues, "session ID character set is small")
	}
	if len(id) > 0 {
		repeatFraction := float64(0)
		for _, count := range unique {
			if count > 1 {
				repeatFraction += float64(count - 1)
			}
		}
		repeatFraction /= float64(len(id))
		if repeatFraction > 0.4 {
			issues = append(issues, "session ID contains many repeated characters")
		}
	}
	entropy := estimateEntropy(id, unique)
	if entropy < 80 {
		issues = append(issues, fmt.Sprintf("estimated entropy is low (%.0f bits)", entropy))
	}
	return issues, entropy
}

func estimateEntropy(id string, unique map[rune]int) float64 {
	if len(id) == 0 {
		return 0
	}
	charset := float64(len(unique))
	if charset < 2 {
		return 0
	}
	return float64(len(id)) * math.Log2(charset)
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
	// Re-issue tools/list explicitly WITHOUT the auth header, regardless of
	// whether the initial handshake used one. This answers the specific
	// question: "can an anonymous caller enumerate tools?"
	raw, err := s.Do(ctx, "tools/list", map[string]any{}, probe.WithNoAuth())
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
	raw, err := s.Do(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil
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
	if raw.StatusCode != 200 {
		return nil
	}
	var envelope struct {
		Result struct {
			Tools []map[string]any `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw.Body, &envelope); err != nil || len(envelope.Result.Tools) == 0 {
		return nil
	}

	r.AddFinding(report.Finding{
		ID:          p.ID(),
		Title:       fmt.Sprintf("Tool capability inventory (%d tools)", len(envelope.Result.Tools)),
		Severity:    report.SeverityInfo,
		Confidence:  "high",
		Protocol:    "mcp",
		ASI:         []string{"ASI09"},
		Description: "Full tool surface exposed by this endpoint, for asset-inventory and diffing purposes.",
		Evidence:    map[string]any{"tools": envelope.Result.Tools, "dangerous_tools": dangerousTools(envelope.Result.Tools)},
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

// --- cors-wildcard -------------------------------------------------------

type corsWildcardProbe struct{}

func (p *corsWildcardProbe) ID() string           { return "mcp-cors-wildcard" }
func (p *corsWildcardProbe) Protocol() string     { return "mcp" }
func (p *corsWildcardProbe) Transports() []string { return httpOnlyTransports }

func (p *corsWildcardProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	raw, err := s.Do(ctx, "tools/list", map[string]any{}, probe.WithHeader("Origin", "https://reap-cors-probe.invalid"))
	if err != nil {
		return nil
	}
	wildcard, credentialed := common.IsCORSWildcard(raw.Headers)
	if !wildcard {
		return nil
	}
	sev := report.SeverityLow
	desc := "Server reflects Access-Control-Allow-Origin: * — any web origin can call this endpoint from a browser context."
	if credentialed {
		sev = report.SeverityHigh
		desc += " Combined with Access-Control-Allow-Credentials: true, this allows credentialed cross-origin requests, which browsers should normally block."
	}
	r.AddFinding(report.Finding{
		ID:          p.ID(),
		Title:       "Permissive CORS policy on MCP endpoint",
		Severity:    sev,
		Confidence:  "high",
		Protocol:    "mcp",
		ASI:         []string{"ASI03"},
		References:  []string{"Fetch (CORS) — WHATWG Living Standard"},
		Description: desc,
		Evidence:    map[string]any{"access_control_allow_origin": raw.Headers.Get("Access-Control-Allow-Origin"), "access_control_allow_credentials": raw.Headers.Get("Access-Control-Allow-Credentials")},
		Request: &report.HTTPExchange{
			Method:      "POST",
			URL:         s.TargetURL(),
			Headers:     map[string]string{"Origin": "https://reap-cors-probe.invalid"},
			Body:        reproBody("tools/list", map[string]any{}),
			StatusCode:  raw.StatusCode,
			ContentType: raw.Headers.Get("Content-Type"),
			Expected:    "Access-Control-Allow-Origin scoped to a known first-party origin, not *",
		},
		Remediation: "Scope Access-Control-Allow-Origin to known first-party origins; never combine * with credentialed requests.",
		Source:      "builtin:mcp",
		Tags:        []string{"cors", "browser-exposure"},
	})
	return nil
}

// --- plaintext-transport ---------------------------------------------

type plaintextTransportProbe struct{}

func (p *plaintextTransportProbe) ID() string           { return "mcp-plaintext-transport" }
func (p *plaintextTransportProbe) Protocol() string     { return "mcp" }
func (p *plaintextTransportProbe) Transports() []string { return httpOnlyTransports }

func (p *plaintextTransportProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	if !common.IsPlaintextURL(s.TargetURL()) {
		return nil
	}
	r.AddFinding(report.Finding{
		ID:          p.ID(),
		Title:       "MCP endpoint served over plaintext HTTP",
		Severity:    report.SeverityMedium,
		Confidence:  "high", // direct fact about the target URL's scheme, not inferred
		Protocol:    "mcp",
		ASI:         []string{"ASI04"},
		Description: "Target URL uses http:// rather than https://. Tool calls, arguments, and any auth tokens are visible to on-path observers.",
		Evidence:    map[string]any{"url": s.TargetURL()},
		Request: &report.HTTPExchange{
			Method:   "GET",
			URL:      s.TargetURL(),
			Expected: "https:// scheme",
		},
		Remediation: "Serve MCP endpoints over TLS only; redirect or refuse plaintext connections.",
		Source:      "builtin:mcp",
		Tags:        []string{"transport"},
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
			Body:        reproBody("initialize", initializeParams()),
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
	for _, method := range []string{"resources/list", "prompts/list"} {
		raw, err := s.Do(ctx, method, map[string]any{}, probe.WithNoAuth())
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
