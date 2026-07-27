package discovery

import "fmt"

// MCPWellKnownPaths is the set of paths tried against a bare host:port
// candidate (KindHostPort) when the caller didn't specify a path — the
// fuzzing nmap/nuclei both do for service identification. Exported and
// data-only so later milestones (range scanning, non-MCP detectors) can
// extend it, e.g. with A2A's "/.well-known/agent.json".
var MCPWellKnownPaths = []string{
	"/", "/mcp", "/mcp/", "/sse", "/messages",
	"/rpc", "/api/mcp", "/v1/mcp", "/.well-known/mcp",
}

// ExpandHostPort turns a bare host:port into one candidate URL per
// well-known path, for detectors that operate on KindHostPort candidates.
func ExpandHostPort(host string, port int, scheme string) []string {
	base := fmt.Sprintf("%s://%s:%d", scheme, host, port)
	urls := make([]string, 0, len(MCPWellKnownPaths))
	for _, p := range MCPWellKnownPaths {
		urls = append(urls, base+p)
	}
	return urls
}
