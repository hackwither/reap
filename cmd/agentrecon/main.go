// Command agentrecon is a single-target, active reconnaissance tool for AI
// agent endpoints — think nmap/whatweb for MCP (and, as protocol coverage
// grows, A2A and other agent-facing protocols), rather than an internet-wide
// scanner. See README.md for the ethics/authorization requirements before
// use.
package main

import (
	"os"

	"github.com/hackwither/agentrecon/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
