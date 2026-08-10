# Architecture

```
                         ┌──────────────────┐
   CLI flags/scope ─────▶│   internal/cli    │  authorization gate lives here 
                         │  (orchestration)   │  nothing below this line runs
                         └─────────┬─────────┘  without --authorized
                                   │
                    ┌──────────────┼──────────────────────────┐
                    ▼                                          ▼
          ┌──────────────────┐                      ┌──────────────────────┐
          │ internal/discovery│  "is there an agent   │  internal/template     │
          │  (Candidate →      │  here, and what is    │  (JSON-template loader │
          │   Fingerprint,     │  it" — runs before     │   → generic Probe      │
          │   Detector/Registry│  any Session exists    │   adapter)              │
          │   mirror below)    │                        └───────────┬──────────┘
          └─────────┬─────────┘                                     │
                    │ resolves protocol + transport                 │
                    ▼                                                │
          ┌──────────────────┐                                      │
          │ internal/probe/mcp│                                      │
          │  (built-in Go     │◀─────────────────────────────────────┘
          │   probes + Session │
          │   implementations: │
          │   streamable-HTTP, │
          │   legacy-SSE, WS)  │
          └─────────┬────────┘
                    │
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

There is no `InvokeTool(name, args)` method anywhere in this interface, and there never should be. A probe (Go or JSON template) can ask "what tools exist" but cannot call one. This is what keeps `reap` a reconnaissance tool rather than turning into an exploitation framework as protocol coverage grows, the constraint is structural, not a linting rule someone can forget.

If a future contribution genuinely needs to distinguish "tool exists" from "tool is actually callable" (a real and useful distinction), the right design is a narrowly-scoped `DryRunCapabilityCheck` that validates a tool's declared JSON schema without invoking it — not a general invoke path. Open an issue before building this so we can agree on the boundary.

Note: `mcp-dynamic-dispatch` relies on naming and schema conventions rather than a semantic proof of dispatch. An operator can evade it by avoiding the expected search/catalog wording and by defining a generic executor schema without the common field names or freeform object shape.

## Discovery layer

Enumeration and Assessment (the `Probe`/`Session` pipeline described above) both assume the protocol is already known — you hand `reap` `-t https://host/mcp` and it does `initialize`. `internal/discovery` answers the question that comes first: **is there an agent here at all, and what is it?**

`Detector` is the discovery-time equivalent of `probe.Probe` — same mental model, one stage earlier:

```go
type Detector interface {
    ID() string
    Kinds() []CandidateKind
    Detect(ctx context.Context, c Candidate, opts DetectOptions) (*Fingerprint, error)
}
```

It runs before any `Session` exists, so it gets a raw `Candidate` (a URL, host:port, or stdio spec — see `discovery.go`), not a `Session`. A `Detector` returning `(nil, nil)` means "ran fine, found nothing"; an error means the check itself couldn't run (network error), not that it found something negative — same convention `probe.Registry.Run` already uses.

Most detectors are **data-driven** rather than hand-written Go: a `FingerprintTemplate` (`fingerprints/*.json`, loaded by `internal/discovery/fingerprint.go`) declares one request plus matchers reused verbatim from `internal/template`'s matcher engine — the same "one request, no chaining, no branching" ceiling templates already enforce for Assessment, applied to "what protocol is this" instead of "what security condition exists." `fingerprints/mcp/http-streamable.json` and `http-sse-legacy.json` are both fingerprints, not Go code. Only checks that genuinely need more than one request stay hand-written (`internal/discovery/websocket_detector.go` — a raw WebSocket upgrade handshake has no "one HTTP request + matchers" shape).

`--protocol=auto` runs Discovery, then feeds the resolved protocol *and transport* into the existing Enumeration/Assessment pipeline unmodified — see "Transports" below for how the transport half of that resolution reaches the probes.

### Adding a Detector

Prefer a fingerprint (`fingerprints/<protocol>/your-check.json`) over Go — same tradeoff as templates vs. hand-written probes. Only reach for a Go `Detector` (registered in `internal/discovery/*.go`'s `BuiltinDetectors()`) when the check needs more than one request or a non-HTTP handshake (see `websocket_detector.go` for the reference shape). Either way, set `Confidence` honestly: **false-positive discipline matters more here than anywhere else in the codebase** — a scanner that confidently mislabels a plain web server as an MCP endpoint loses trust immediately (see `internal/discovery/false_positive_test.go` and `internal/report/report.go`'s `ApplyConfidenceDowngrade`, which exists specifically to blunt the damage when a target never actually confirms the protocol being scanned).

## Transports

`probe.Session` has exactly one implementation's worth of transport logic baked into it only in spirit — in practice there are three, all satisfying the same interface: `mcp.Session` (streamable-HTTP, `session.go`), `mcp.SSESession` (legacy pre-2025-03-26 HTTP+SSE, `session_sse.go`), and `mcp.WSSession` (a non-standard but observed-in-the-wild raw WebSocket transport, `session_ws.go`). `internal/cli/cli.go`'s `newSessionForTransport` is the one place that picks which concrete type to construct, based on what Discovery resolved (or `"http-streamable"` by default for the static `--protocol=mcp` path — this preserves every existing invocation's behavior exactly).

The legacy-SSE and WebSocket sessions are structurally different from streamable-HTTP's simple request/response: both are persistent, asynchronous connections where a response can arrive on a different read than the one that sent the request. Each runs a background goroutine that dispatches inbound frames/events to whichever `Do()` call is waiting on that JSON-RPC id, via a `map[int]chan *probe.RawResult` guarded by a mutex — read `session_sse.go` or `session_ws.go`'s package doc comment before touching either; the concurrency shape is the whole point.

Not every probe makes sense over every transport (TLS cert inspection has no meaning over a raw WebSocket; a `tools/list` schema check doesn't care what carried it). `Probe.Transports() []string` declares which transports a probe supports (`["*"]` for transport-agnostic checks), and `probe.Registry.ForProtocolAndTransport` filters accordingly — probes filtered out this way count toward `Report.Coverage.Skipped`, not silently disappear.

## Adding a new protocol

1. Create `internal/probe/<protocol>/` with a `Session` implementation (see `internal/probe/mcp/session.go` for the MCP reference implementation over streamable HTTP).
2. Implement the handshake/negotiation step your protocol needs (MCP: `initialize`; A2A: agent card discovery; etc.) as a method on your session, mirroring `Session.Initialize`.
3. Write built-in probes in `<protocol>/checks.go` implementing `probe.Probe`, including `Transports()` — return `["*"]` unless the check genuinely depends on transport-specific mechanics (see "Transports" above).
4. Register them from `cli.Run` alongside the existing `mcp.BuiltinProbes()` call.
5. Templates automatically work against your protocol once `Template.Protocol` matches — the loader and matcher engine are protocol-agnostic.

## Why JSON templates instead of YAML (for now)

Nuclei-style YAML templates were the original plan (see the project plan in the repo history / README roadmap), but this codebase was bootstrapped in a sandboxed build environment without access to a Go module proxy, so no third-party YAML library could be vendored. JSON needs zero dependencies via `encoding/json` in the standard library. The `Template` struct and matcher engine in `internal/template/template.go` don't care what the outer serialization format is — swapping in `gopkg.in/yaml.v3` and changing `LoadDir` to unmarshal YAML instead of JSON is a small, isolated PR. Good first-contribution material if you want to pick it up.
