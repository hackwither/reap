package cli

import (
	"fmt"
	"io"

	"github.com/hackwither/reap/internal/version"
)

// Version is re-exported from internal/version so existing callers and tests
// keep working.
//
// internal/version is the single source of truth, including the
// ldflags/build-info resolution chain. The value can't live here because
// internal/probe/mcp and internal/report both need it and cli already imports
// mcp — so release builds must stamp
// -X github.com/hackwither/reap/internal/version.Version, not this package.
func Version() string { return version.Version }

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
	fmt.Fprintf(w, "\n        Reconnaissance and Enumeration for Agent Protocols\n                        by @hackwither\n                            v%s\n\n", version.Version)
}
