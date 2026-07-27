package discovery

// BuiltinDetectors returns every hand-written Go Detector — reserved for
// checks that genuinely need more than "one request, matched declaratively"
// (e.g. a WebSocket upgrade handshake, or a chained follow-up request).
// mcp-http-streamable used to live here; it's now fingerprints/mcp/http-streamable.json,
// since a single JSON-RPC initialize + json_path matchers on
// result.serverInfo/result.protocolVersion covers it exactly, without Go.
// Data-driven detectors loaded from fingerprints/*.json are registered
// separately by the CLI, the same way template-defined probes are
// registered alongside mcp.BuiltinProbes().
func BuiltinDetectors() []Detector {
	return []Detector{
		&mcpWebSocketDetector{},
	}
}
