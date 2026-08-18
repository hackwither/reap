package cli

import (
	"fmt"
	"io"

	"github.com/hackwither/reap/internal/version"
)

// Version is re-exported from internal/version so existing callers and tests
// keep working. internal/version is the single source of truth — the const
// can't live here because internal/probe/mcp needs it too and cli already
// imports mcp.
const Version = version.Version

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
