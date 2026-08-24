package mcp

import (
	"encoding/json"
	"strings"

	"github.com/hackwither/reap/internal/probe"
)

// AuthGateSignal records which MCP-consistent signal(s) a 401/403 response
// to `initialize` carried. This is what lets cli.go's confirmation gate
// distinguish "a real MCP server that requires auth" from "some unrelated
// host that also happens to 401 everything" — the former should be reported
// as confirmed, the latter should not.
type AuthGateSignal struct {
	ProblemJSON     bool // Content-Type: application/problem+json (RFC 7807)
	JSONRPCError    bool // body decodes as a {"error": ...} JSON-RPC envelope
	BearerChallenge bool // WWW-Authenticate names the Bearer scheme (RFC 9728 §5.1)
}

// Any reports whether at least one MCP-consistent signal was observed.
func (s AuthGateSignal) Any() bool {
	return s.ProblemJSON || s.JSONRPCError || s.BearerChallenge
}

// String renders the matched signal(s) for use in a ConfirmReason/log line.
func (s AuthGateSignal) String() string {
	var parts []string
	if s.ProblemJSON {
		parts = append(parts, "application/problem+json")
	}
	if s.JSONRPCError {
		parts = append(parts, "JSON-RPC error envelope")
	}
	if s.BearerChallenge {
		parts = append(parts, "WWW-Authenticate: Bearer")
	}
	return strings.Join(parts, ", ")
}

// ClassifyAuthGate inspects a 401/403 response to `initialize` for signals
// consistent with a real MCP server gating the handshake behind auth. Only
// meaningful when the caller has already confirmed the status code is
// 401/403 — this does not re-check status itself.
func ClassifyAuthGate(raw *probe.RawResult) AuthGateSignal {
	var sig AuthGateSignal
	if raw == nil {
		return sig
	}
	if strings.Contains(strings.ToLower(raw.Headers.Get("Content-Type")), "application/problem+json") {
		sig.ProblemJSON = true
	}
	if strings.Contains(strings.ToLower(raw.Headers.Get("WWW-Authenticate")), "bearer") {
		sig.BearerChallenge = true
	}
	var envelope struct {
		Error json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(raw.Body, &envelope); err == nil && len(envelope.Error) > 0 && string(envelope.Error) != "null" {
		sig.JSONRPCError = true
	}
	return sig
}
