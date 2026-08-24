// Package transport holds the checks that are about how an endpoint is
// served, not about which agent protocol it speaks.
//
// These five checks used to live in internal/probe/mcp with mcp- prefixed IDs
// and Protocol() == "mcp", even though not one of them reads a byte of MCP.
// That was the concrete reason reap's "designed to outlive MCP" claim didn't
// hold: identifying an A2A endpoint produced a fingerprint and nothing else,
// because every posture check was gated behind the MCP protocol string.
//
// They now report Protocol() == "*" and take their target from
// probe.Session.TargetURL(), so they run against any protocol reap can
// identify — including ones with no enumeration probes written yet.
package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hackwither/reap/internal/httpx"
	"github.com/hackwither/reap/internal/probe"
	"github.com/hackwither/reap/internal/probe/common"
	"github.com/hackwither/reap/internal/report"
)

// BuiltinProbes returns the protocol-neutral transport checks.
//
// The httpx client is injected rather than reached through probe.Session,
// which keeps probe.Session minimal — it is the type that structurally
// enforces reap's no-invoke boundary, so it should carry as little as
// possible.
func BuiltinProbes(client *httpx.Client) []probe.Probe {
	return []probe.Probe{
		&plaintextProbe{},
		&tlsCertHealthProbe{client: client},
		&downgradeProbe{client: client},
		&corsWildcardProbe{client: client},
		&rateLimitProbe{client: client},
	}
}

// httpTransports: these checks inspect HTTP mechanics (TLS, headers, CORS),
// so they can't run meaningfully over stdio or a raw WebSocket. The plaintext
// check only reads the URL scheme, so it is transport-agnostic.
var (
	httpTransports = []string{"http-streamable", "http-sse-legacy"}
	anyTransport   = []string{"*"}
)

// httpsTarget parses a session's target and requires https, since the TLS and
// downgrade checks have nothing to say about a plaintext endpoint.
func httpsTarget(s probe.Session) (*url.URL, error) {
	u, err := url.Parse(s.TargetURL())
	if err != nil {
		return nil, probe.NotApplicable("target URL is unparseable: %v", err)
	}
	if u.Scheme != "https" {
		return nil, probe.NotApplicable("target is not https, so there is no TLS posture to inspect")
	}
	return u, nil
}

// --- transport-plaintext -------------------------------------------------

type plaintextProbe struct{}

func (p *plaintextProbe) ID() string           { return "transport-plaintext" }
func (p *plaintextProbe) Protocol() string     { return "*" }
func (p *plaintextProbe) Transports() []string { return anyTransport }

func (p *plaintextProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	if !common.IsPlaintextURL(s.TargetURL()) {
		return nil
	}
	r.AddFinding(report.Finding{
		ID:          p.ID(),
		Title:       "Agent endpoint served over plaintext HTTP",
		Severity:    report.SeverityMedium,
		Protocol:    "*",
		ASI:         []string{"ASI04"},
		Description: "Target URL uses http:// rather than https://. Tool calls, arguments, and any auth tokens are visible to on-path observers.",
		Evidence:    map[string]any{"url": s.TargetURL()},
		Remediation: "Serve agent endpoints over TLS only; redirect or refuse plaintext connections.",
		Source:      "builtin:transport",
		Tags:        []string{"transport"},
	})
	return nil
}

// --- tls-cert-health -----------------------------------------------------

type tlsCertHealthProbe struct{ client *httpx.Client }

func (p *tlsCertHealthProbe) ID() string           { return "tls-cert-health" }
func (p *tlsCertHealthProbe) Protocol() string     { return "*" }
func (p *tlsCertHealthProbe) Transports() []string { return httpTransports }

func (p *tlsCertHealthProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	u, err := httpsTarget(s)
	if err != nil {
		return err
	}

	state, cert, err := common.InspectTLS(ctx, p.client, s.TargetURL())
	if err != nil {
		return fmt.Errorf("TLS inspection failed: %w", err)
	}

	issues := []string{}
	severity := report.SeverityLow
	raise := func(to report.Severity) {
		if severity.Rank() < to.Rank() {
			severity = to
		}
	}

	if time.Now().After(cert.NotAfter) {
		issues = append(issues, "certificate is expired")
		raise(report.SeverityHigh)
	}
	if time.Now().Before(cert.NotBefore) {
		issues = append(issues, "certificate is not yet valid")
		raise(report.SeverityHigh)
	}
	if cert.IsCA {
		if err := cert.CheckSignatureFrom(cert); err == nil {
			issues = append(issues, "certificate is self-signed")
			raise(report.SeverityHigh)
		}
	}
	if err := cert.VerifyHostname(u.Hostname()); err != nil {
		issues = append(issues, fmt.Sprintf("hostname mismatch: %v", err))
		raise(report.SeverityMedium)
	}
	if state.Version < tls.VersionTLS12 {
		issues = append(issues, fmt.Sprintf("weak TLS protocol version %s", common.TLSVersionName(state.Version)))
		raise(report.SeverityMedium)
	}
	if common.IsWeakCipherSuite(state.CipherSuite) {
		issues = append(issues, fmt.Sprintf("weak cipher suite %s", tls.CipherSuiteName(state.CipherSuite)))
		raise(report.SeverityMedium)
	}
	if len(issues) == 0 {
		return nil
	}

	r.AddFinding(report.Finding{
		ID:       p.ID(),
		Title:    "TLS certificate health issues detected",
		Severity: severity,
		Protocol: "*",
		ASI:      []string{"ASI09"},
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
		Remediation: "Use a valid TLS certificate from a trusted authority, ensure the certificate matches the host name, and retire weak TLS versions and cipher suites.",
		Source:      "builtin:transport",
		Tags:        []string{"transport", "tls"},
	})
	return nil
}

// --- transport-downgrade -------------------------------------------------

type downgradeProbe struct{ client *httpx.Client }

func (p *downgradeProbe) ID() string           { return "transport-downgrade" }
func (p *downgradeProbe) Protocol() string     { return "*" }
func (p *downgradeProbe) Transports() []string { return httpTransports }

func (p *downgradeProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	u, err := httpsTarget(s)
	if err != nil {
		return err
	}

	paths := []string{u.Path}
	if u.Path != "/sse" {
		paths = append(paths, "/sse")
	}

	fallbacks, err := common.DetectPlaintextListeners(ctx, p.client, s.TargetURL(), paths)
	if err != nil {
		return fmt.Errorf("plaintext listener sweep failed: %w", err)
	}
	if len(fallbacks) == 0 {
		return nil
	}

	evidence := []map[string]any{}
	for _, fallback := range fallbacks {
		evidence = append(evidence, map[string]any{"path": fallback.Path, "status": fallback.StatusCode, "content_type": fallback.ContentType})
	}

	r.AddFinding(report.Finding{
		ID:          p.ID(),
		Title:       "Endpoint also responds over plaintext HTTP",
		Severity:    report.SeverityMedium,
		Protocol:    "*",
		ASI:         []string{"ASI04"},
		Description: "The target host also accepted at least one plaintext HTTP path for agent traffic, which undermines TLS protections.",
		Evidence:    map[string]any{"fallbacks": evidence},
		Remediation: "Disable plaintext HTTP listeners for agent endpoints and accept traffic only over TLS.",
		Source:      "builtin:transport",
		Tags:        []string{"transport", "downgrade"},
	})
	return nil
}

// --- http-cors-wildcard --------------------------------------------------

// corsWildcardProbe issues a real CORS preflight.
//
// The MCP-era version of this check piggybacked an Origin header onto a
// tools/list POST and read the response headers. That both coupled a
// transport check to a protocol method and missed the case that actually
// matters: many servers only emit permissive CORS headers in response to an
// OPTIONS preflight, which reap never sent.
type corsWildcardProbe struct{ client *httpx.Client }

func (p *corsWildcardProbe) ID() string           { return "http-cors-wildcard" }
func (p *corsWildcardProbe) Protocol() string     { return "*" }
func (p *corsWildcardProbe) Transports() []string { return httpTransports }

const probeOrigin = "https://reap-cors-probe.invalid"

func (p *corsWildcardProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	headers, err := p.observeCORS(ctx, s.TargetURL())
	if err != nil {
		return fmt.Errorf("CORS observation failed: %w", err)
	}
	wildcard, credentialed := common.IsCORSWildcard(headers)
	reflected := strings.EqualFold(headers.Get("Access-Control-Allow-Origin"), probeOrigin)
	if !wildcard && !reflected {
		return nil
	}

	sev := report.SeverityLow
	desc := "Server returns Access-Control-Allow-Origin: * — any web origin can call this endpoint from a browser context."
	if reflected {
		// Reflecting an arbitrary origin is strictly worse than "*", because
		// browsers permit credentials with a reflected origin.
		desc = fmt.Sprintf("Server reflects an arbitrary request Origin (%s) back in Access-Control-Allow-Origin, which permits credentialed cross-origin access from any site.", probeOrigin)
		sev = report.SeverityHigh
	}
	if credentialed {
		sev = report.SeverityHigh
		desc += " Combined with Access-Control-Allow-Credentials: true, this allows credentialed cross-origin requests, which browsers should normally block."
	}
	r.AddFinding(report.Finding{
		ID:          p.ID(),
		Title:       "Permissive CORS policy on agent endpoint",
		Severity:    sev,
		Protocol:    "*",
		ASI:         []string{"ASI03"},
		Description: desc,
		Evidence: map[string]any{
			"access_control_allow_origin":      headers.Get("Access-Control-Allow-Origin"),
			"access_control_allow_credentials": headers.Get("Access-Control-Allow-Credentials"),
			"tested_origin":                    probeOrigin,
			"origin_reflected":                 reflected,
		},
		Remediation: "Scope Access-Control-Allow-Origin to known first-party origins; never reflect an arbitrary Origin, and never combine * with credentialed requests.",
		Source:      "builtin:transport",
		Tags:        []string{"cors", "browser-exposure"},
	})
	return nil
}

// observeCORS gathers CORS headers from a preflight, a cross-origin GET, and a
// cross-origin POST, returning the first response that actually carries an
// Access-Control-Allow-Origin.
//
// All three are needed. A preflight alone misses servers that only set CORS
// headers on the real request — which is most JSON-RPC agent endpoints, since
// they answer POST and 404 everything else. A GET alone (or the old
// implementation's piggybacked tools/call-shaped POST) misses the servers that
// only answer a preflight. Because this probe is protocol-neutral it cannot
// know which verb the endpoint services, so it asks in all three shapes.
func (p *corsWildcardProbe) observeCORS(ctx context.Context, target string) (http.Header, error) {
	attempts := []struct {
		method  string
		headers map[string]string
		body    bool
	}{
		{http.MethodOptions, map[string]string{
			"Origin":                         probeOrigin,
			"Access-Control-Request-Method":  http.MethodPost,
			"Access-Control-Request-Headers": "content-type",
		}, false},
		{http.MethodPost, map[string]string{"Origin": probeOrigin, "Content-Type": "application/json"}, true},
		{http.MethodGet, map[string]string{"Origin": probeOrigin}, false},
	}

	var first http.Header
	var firstErr error
	for _, a := range attempts {
		headers, err := p.request(ctx, a.method, target, a.headers, a.body)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if first == nil {
			first = headers
		}
		if headers.Get("Access-Control-Allow-Origin") != "" {
			return headers, nil
		}
	}
	if first != nil {
		return first, nil
	}
	return nil, firstErr
}

func (p *corsWildcardProbe) request(ctx context.Context, method, target string, headers map[string]string, withBody bool) (http.Header, error) {
	var body io.Reader
	if withBody {
		// An empty JSON object: enough for a JSON-RPC endpoint to answer with
		// its normal response headers, and it invokes nothing.
		body = strings.NewReader("{}")
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := p.client.HTTP().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.Header, nil
}

// --- http-rate-limit-absence --------------------------------------------

type rateLimitProbe struct{ client *httpx.Client }

func (p *rateLimitProbe) ID() string           { return "http-rate-limit-absence" }
func (p *rateLimitProbe) Protocol() string     { return "*" }
func (p *rateLimitProbe) Transports() []string { return httpTransports }

func (p *rateLimitProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	// Ask in both shapes and stay silent if either answer advertises limiting.
	// A JSON-RPC agent endpoint typically only services POST and 404s a GET,
	// and a 404's headers say nothing about the endpoint's real policy — so a
	// GET-only check reports missing rate limiting on servers that advertise
	// it correctly.
	observed := []map[string]any{}
	var reached bool
	for _, attempt := range []struct {
		method string
		body   bool
	}{
		{http.MethodPost, true},
		{http.MethodGet, false},
	} {
		var body io.Reader
		if attempt.body {
			body = strings.NewReader("{}")
		}
		req, err := http.NewRequestWithContext(ctx, attempt.method, s.TargetURL(), body)
		if err != nil {
			return probe.NotApplicable("target URL is unusable: %v", err)
		}
		if attempt.body {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := p.client.HTTP().Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		reached = true

		if common.HasRateLimitHeader(resp.Header) {
			return nil
		}
		observed = append(observed, map[string]any{"method": attempt.method, "status": resp.StatusCode})
	}
	if !reached {
		return fmt.Errorf("endpoint did not answer either a POST or a GET")
	}

	r.AddFinding(report.Finding{
		ID:       p.ID(),
		Title:    "No standard rate-limit headers observed",
		Severity: report.SeverityLow,
		Protocol: "*",
		// ASI06 (Cascading Failures) rather than ASI08 (Supply Chain), which
		// this has nothing to do with. Missing rate limiting is a
		// cascading-failure and availability concern.
		ASI:         []string{"ASI06"},
		Description: "The endpoint answered requests but sent no standard rate-limit response headers. This is a reconnaissance signal that the service may not be advertising rate limiting to clients; it is not proof that no limiting exists.",
		Evidence:    map[string]any{"observations": observed},
		Remediation: "Expose standard rate-limit headers such as Retry-After, RateLimit-Remaining, and RateLimit-Limit, or document the expected client behavior when limits are reached.",
		Source:      "builtin:transport",
		Tags:        []string{"rate-limit", "availability"},
	})
	return nil
}
