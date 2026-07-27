package cli

import (
    "fmt"
    "io"
)

// Version is the tool version printed in the banner and --version output.
const Version = "0.1.0"

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
