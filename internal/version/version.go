// Package version holds the single source of truth for reap's version
// string.
//
// This is a leaf package with no imports beyond the standard library, on
// purpose. The version is needed by internal/cli (banner, --version),
// internal/report (report metadata), and internal/probe/mcp (the
// clientInfo.version sent in the MCP handshake). internal/cli already imports
// internal/probe/mcp, so the value cannot live in cli without creating an
// import cycle.
package version

import (
	"runtime/debug"
	"strings"
)

// Version is the reap version reported by --version and embedded in every
// report. It resolves via three paths, in priority order, so it's accurate
// regardless of how the binary was built:
//
//  1. Release builds inject the git tag at link time via
//     -ldflags "-X github.com/hackwither/reap/internal/version.Version=...";
//     -X overrides this literal before init() below ever runs.
//  2. `go install .../reap@vX.Y.Z` doesn't pass ldflags, but Go has stamped
//     the resolved module version into the binary's build info since 1.18 —
//     init() reads it via debug.ReadBuildInfo() when ldflags didn't already
//     override the "dev" sentinel.
//  3. A plain local `go build`/`go run` falls through and keeps "dev".
//
// This must stay a var: -X cannot write to a const, and a const would make
// every release binary silently report the wrong version.
var Version = "dev"

func init() {
	if Version != "dev" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return
	}
	Version = strings.TrimPrefix(info.Main.Version, "v")
}

// UserAgent is the default User-Agent sent on every request reap makes.
//
// Go's default ("Go-http-client/1.1") is worth replacing for two reasons:
// WAFs routinely block it, and a defender looking at their logs should be
// able to tell that the traffic came from an identifiable recon tool rather
// than an anonymous script. Overridable via --user-agent.
//
// It's a function rather than a const because Version is only final after
// init() has run.
func UserAgent() string {
	return "reap/" + Version + " (+https://github.com/hackwither/reap)"
}
