package mcp

import (
	"context"
	"strings"

	"github.com/hackwither/reap/internal/probe"
	"github.com/hackwither/reap/internal/report"
)

// edgeServerTokens lists Server-header software that's almost always a
// CDN/edge/reverse-proxy layer rather than the origin application itself. A
// match here is already surfaced verbatim in the report's fingerprint block
// (Target.EdgeServer, captured from the same header during initialize) —
// firing a second, separate finding for it is duplicate noise, not new
// signal. Kept intentionally small: this is a suppression allowlist, not a
// classifier, so an unrecognized token still fires (better to occasionally
// name a CDN than to silently hide an origin application's identity).
var edgeServerTokens = []string{"cloudflare", "envoy", "nginx", "cloudfront", "varnish", "akamai", "fastly"}

func isEdgeServerToken(value string) bool {
	lower := strings.ToLower(value)
	for _, tok := range edgeServerTokens {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return false
}

// serverHeaderFingerprintProbe used to be a declarative JSON template, but
// suppressing on an edge-token allowlist is exclusion logic the generic
// matcher engine (internal/template) deliberately doesn't support — see
// docs/WRITING_PROBES.md's "if your check needs branching, it's not a
// template" rule. Kept as a hand-written probe with the original ID so
// --include/--exclude and saved reports referencing it keep working.
type serverHeaderFingerprintProbe struct{}

func (p *serverHeaderFingerprintProbe) ID() string       { return "mcp-tmpl-server-header-fingerprint" }
func (p *serverHeaderFingerprintProbe) Protocol() string { return "mcp" }
func (p *serverHeaderFingerprintProbe) Transports() []string {
	return []string{"http-streamable", "http-sse-legacy", "websocket"}
}

func (p *serverHeaderFingerprintProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	raw, err := s.Do(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil // connection-level failure isn't a probe match failure
	}

	server := raw.Headers.Get("Server")
	poweredBy := raw.Headers.Get("X-Powered-By")
	// X-Powered-By almost never names CDN/edge software (it names the app
	// framework: PHP, Express, ASP.NET), so it keeps firing on presence
	// alone — only the Server header gets the edge-token exclusion, since
	// that's the one duplicating the fingerprint block's Edge line.
	serverFires := server != "" && !isEdgeServerToken(server)
	if !serverFires && poweredBy == "" {
		return nil
	}

	var matchEvidence []map[string]any
	if serverFires {
		matchEvidence = append(matchEvidence, map[string]any{"type": "header", "header": "Server", "got": server})
	}
	if poweredBy != "" {
		matchEvidence = append(matchEvidence, map[string]any{"type": "header", "header": "X-Powered-By", "got": poweredBy})
	}

	r.AddFinding(report.Finding{
		ID:          p.ID(),
		Title:       "Server response header discloses backend/edge software",
		Severity:    report.SeverityInfo,
		Confidence:  "medium",
		Protocol:    "mcp",
		ASI:         []string{"ASI09"},
		Description: "The response includes a Server or X-Powered-By header identifying backend software that appears to be the origin application, not a CDN/edge layer (which is already surfaced separately in the target fingerprint's Edge line). Not a vulnerability by itself, but useful fingerprinting context worth trimming in production.",
		Evidence:    map[string]any{"matchers": matchEvidence, "rpc_method": "tools/list"},
		Request: &report.HTTPExchange{
			Method:      "POST",
			URL:         s.TargetURL(),
			Body:        reproBody("tools/list", map[string]any{}),
			StatusCode:  raw.StatusCode,
			ContentType: raw.Headers.Get("Content-Type"),
			BodySize:    len(raw.Body),
		},
		Remediation: "Suppress or genericize identifying response headers in production deployments where they name the origin application.",
		Source:      "builtin:mcp",
		Tags:        []string{"fingerprint", "information-disclosure"},
	})
	return nil
}
