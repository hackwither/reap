# Architecture

```
                         ┌──────────────────┐
   CLI flags/scope ─────▶│   internal/cli    │  authorization gate lives here 
                         │  (orchestration)   │  nothing below this line runs
                         └─────────┬─────────┘  without --authorized
                                   │
                    ┌──────────────┼───────────────┐
                    ▼                               ▼
          ┌──────────────────┐            ┌──────────────────────┐
          │ internal/probe/mcp│            │  internal/template     │
          │  (built-in Go     │            │  (JSON-template loader │
          │   probes + the    │            │   → generic Probe      │
          │   MCP Session/    │            │   adapter)              │
          │   transport)      │            └───────────┬──────────┘
          └─────────┬────────┘                          │
                    │                                    │
                    └─────────────────┬──────────────────┘
                                      ▼
                          ┌──────────────────────┐
                          │   internal/probe      │  shared Probe interface +
                          │  (Registry, Session    │  Registry; this is the only
                          │   interface, contract) │  contract new protocols must
                          └───────────┬───────────┘  implement
                                      ▼
                          ┌──────────────────────┐
                          │   internal/report      │  Finding/Report model,
                          │  (ASI mapping, JSON/    │  ASI01–ASI10 reference table,
                          │   human renderers)      │  JSON + text output
                          └──────────────────────┘
```

## Safety boundary

The single most important design constraint in this codebase: **a Probe only ever receives a `Session`, and `Session` only exposes read-only protocol operations.**

```go
type Session interface {
    TargetURL() string
    Do(ctx context.Context, method string, params any, opts ...ReqOption) (*RawResult, error)
}
```

There is no `InvokeTool(name, args)` method anywhere in this interface, and there never should be. A probe (Go or JSON template) can ask "what tools exist" but cannot call one. This is what keeps `agentrecon` a reconnaissance tool rather than turning into an exploitation framework as protocol coverage grows, the constraint is structural, not a linting rule someone can forget.

If a future contribution genuinely needs to distinguish "tool exists" from "tool is actually callable" (a real and useful distinction), the right design is a narrowly-scoped `DryRunCapabilityCheck` that validates a tool's declared JSON schema without invoking it — not a general invoke path. Open an issue before building this so we can agree on the boundary.

Note: `mcp-dynamic-dispatch` relies on naming and schema conventions rather than a semantic proof of dispatch. An operator can evade it by avoiding the expected search/catalog wording and by defining a generic executor schema without the common field names or freeform object shape.

## Adding a new protocol

1. Create `internal/probe/<protocol>/` with a `Session` implementation (see `internal/probe/mcp/session.go` for the MCP reference implementation over streamable HTTP).
2. Implement the handshake/negotiation step your protocol needs (MCP: `initialize`; A2A: agent card discovery; etc.) as a method on your session, mirroring `Session.Initialize`.
3. Write built-in probes in `<protocol>/checks.go` implementing `probe.Probe`.
4. Register them from `cli.Run` alongside the existing `mcp.BuiltinProbes()` call.
5. Templates automatically work against your protocol once `Template.Protocol` matches — the loader and matcher engine are protocol-agnostic.

## Why JSON templates instead of YAML (for now)

Nuclei-style YAML templates were the original plan (see the project plan in the repo history / README roadmap), but this codebase was bootstrapped in a sandboxed build environment without access to a Go module proxy, so no third-party YAML library could be vendored. JSON needs zero dependencies via `encoding/json` in the standard library. The `Template` struct and matcher engine in `internal/template/template.go` don't care what the outer serialization format is — swapping in `gopkg.in/yaml.v3` and changing `LoadDir` to unmarshal YAML instead of JSON is a small, isolated PR. Good first-contribution material if you want to pick it up.
