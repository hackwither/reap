package cli

import (
	"fmt"
	"io"
	"runtime/debug"
	"strings"
)

// Version is the reap version reported by --version and embedded in every
// report. It resolves via three paths, in priority order, so it's accurate
// regardless of how the binary was built:
//
//  1. Release builds inject the git tag at link time via
//     -ldflags "-X github.com/hackwither/reap/internal/cli.Version=...";
//     -X overrides this literal before init() below ever runs.
//  2. `go install .../reap@vX.Y.Z` doesn't pass ldflags, but Go has stamped
//     the resolved module version into the binary's build info since 1.18 —
//     init() reads it via debug.ReadBuildInfo() when ldflags didn't already
//     override the "dev" sentinel.
//  3. A plain local `go build`/`go run` falls through and keeps "dev".
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

const asciiArt = `
 ██▀███  ▓█████ ▄▄▄       ██▓███
▓██ ▒ ██▒▓█   ▀▒████▄    ▓██░  ██▒
▓██ ░▄█ ▒▒███  ▒██  ▀█▄  ▓██░ ██▓▒
▒██▀▀█▄  ▒▓█  ▄░██▄▄▄▄██ ▒██▄█▓▒ ▒
░██▓ ▒██▒░▒████▒▓█   ▓██▒▒██▒ ░  ░
░ ▒▓ ░▒▓░░░ ▒░ ░▒▒   ▓▒█░▒▓▒░ ░  ░
  ░▒ ░ ▒░ ░ ░  ░ ▒   ▒▒ ░░▒ ░
  ░░   ░    ░    ░   ▒   ░░
   ░        ░  ░     ░  ░
`

// PrintBanner writes the ASCII banner to w. Keep it small and on stderr
// so it doesn't pollute stdout output formats.
func PrintBanner(w io.Writer) {
	fmt.Fprint(w, asciiArt)
	// Reuse the package-level banner constant defined in cli.go
	fmt.Fprint(w, banner)
	fmt.Fprintf(w, "\n        Reconnaissance and Enumeration for Agent Protocols\n                        by @hackwither\n                            v%s\n\n", Version)
}
