package discovery

import (
	"context"
	"net"

	"github.com/hackwither/reap/internal/probe/common"
)

// mcpWebSocketDetector confirms a raw WebSocket upgrade handshake succeeds.
// This is not part of the official MCP spec — some community gateways/proxies
// speak JSON-RPC over a plain WebSocket anyway, so it's worth detecting, but
// it's flagged non-standard and capped at medium confidence.
//
// A socket upgrade handshake has no meaningful mapping onto "one HTTP
// request + matchers over the response" the way fingerprints/*.json
// expresses other detectors, so this stays hand-written Go rather than
// becoming a fingerprint. It only confirms the upgrade itself; a full
// JSON-RPC round trip over the resulting connection is session_ws.go's job
// (a later milestone), not discovery's.
type mcpWebSocketDetector struct{}

func (d *mcpWebSocketDetector) ID() string { return "mcp-websocket" }

func (d *mcpWebSocketDetector) Kinds() []CandidateKind {
	return []CandidateKind{KindURL, KindHostPort}
}

func (d *mcpWebSocketDetector) Detect(ctx context.Context, c Candidate, opts DetectOptions) (*Fingerprint, error) {
	if c.URL == "" {
		return nil, nil
	}
	dialer := &net.Dialer{Timeout: opts.Timeout}
	var headers map[string]string
	if opts.AuthHeader != "" {
		headers = map[string]string{"Authorization": opts.AuthHeader}
	}
	conn, _, err := common.DialWebSocket(dialer, c.URL, headers)
	if err != nil {
		return nil, nil // unreachable candidate, or not a conformant WebSocket server — not a Detector failure
	}
	defer conn.Close()

	return &Fingerprint{
		Candidate:  c,
		Protocol:   "mcp",
		Transport:  "websocket",
		Confidence: "medium", // capped: non-standard transport, upgrade-only confirmation, no JSON-RPC round trip yet
		Evidence: map[string]any{
			"upgrade_confirmed": true,
			"note":              "WebSocket is not part of the official MCP spec; this only confirms a conformant upgrade handshake, not an MCP JSON-RPC round trip",
		},
		DetectorID: d.ID(),
	}, nil
}
