// Package version holds the single source of truth for reap's version
// string.
//
// This is a leaf package with no imports on purpose. The version is needed by
// internal/cli (banner, --version), internal/report (report metadata), and
// internal/probe/mcp (the clientInfo.version sent in the MCP handshake).
// internal/cli already imports internal/probe/mcp, so the const cannot live
// in cli without creating an import cycle.
package version

// Version is the tool version printed in the banner and --version output,
// recorded in every report, and sent as clientInfo.version during protocol
// handshakes.
const Version = "0.1.0"

// UserAgent is the default User-Agent sent on every request reap makes.
//
// Go's default ("Go-http-client/1.1") is worth replacing for two reasons:
// WAFs routinely block it, and a defender looking at their logs should be
// able to tell that the traffic came from an identifiable recon tool rather
// than an anonymous script. Overridable via --user-agent.
const UserAgent = "reap/" + Version + " (+https://github.com/hackwither/reap)"
