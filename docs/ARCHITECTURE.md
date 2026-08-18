# Architecture

```
                          ┌────────────────────┐
    CLI flags / targets ──▶│   internal/cli      │  flag validation, target
                          │  (orchestration)    │  collection, session
                          └──────────┬──────────┘  selection, exit codes
                                     │
              ┌──────────────────────┼──────────────────────┐
              ▼                      ▼                      ▼
   ┌───────────────────┐  ┌────────────────────┐  ┌───────────────────┐
   │ internal/discovery │  │ internal/probe/... │  │  internal/httpx    │
   │  Detectors +       │  │  mcp   (protocol)  │  │  one client for    │
   │  JSON fingerprints │  │  transport ("*")   │  │  every request:    │
   │  "what is this?"   │  │  generic (session) │  │  proxy, TLS, UA,   │
   └─────────┬─────────┘  └─────────┬──────────┘  │  retries, rate cap │
             │                       │             └───────────────────┘
             │            ┌──────────┴──────────┐
             │            │  internal/template   │
             │            │  JSON → Probe        │
             │            └──────────┬──────────┘
             │                       │
             └───────────┬───────────┘
                         ▼
              ┌────────────────────┐
              │   internal/probe    │  Probe + Session contracts,
              │  (Registry,         │  Registry, ErrNotApplicable.
              │   Session, sentinel)│  The safety boundary lives here.
              └──────────┬─────────┘
                         ▼
              ┌────────────────────┐
              │   internal/report   │  Finding, ProbeRun, Target,
              │  (model + writers)  │  ASI table, text/JSON/SARIF
              └────────────────────┘
```

`internal/version` is a leaf holding the version string and default User-Agent; everything else depends on it.

## Safety boundary

The single most important design constraint in this codebase: **a Probe only ever receives a `Session`, and `Session` only exposes read-only protocol operations.**

```go
type Session interface {
    TargetURL() string
    Do(ctx context.Context, method string, params any, opts ...ReqOption) (*RawResult, error)
}
```

There is no `InvokeTool(name, args)` method anywhere in this interface, and there never should be. A probe (Go or JSON template) can ask "what tools exist" but cannot call one. This is what keeps `reap` a reconnaissance tool rather than turning into an exploitation framework as protocol coverage grows — the constraint is structural, not a linting rule someone can forget.

Two consequences worth being explicit about:

- **Notifications are not on the interface.** MCP requires the client to send `notifications/initialized` after a handshake. That is implemented as an unexported `Session.notify` method, called only from `Session.Initialize`. Sending an unanswered message to a target is handshake bookkeeping, not something a check needs, and the narrower the probe-facing interface stays the harder it is to widen accidentally.
- **Pagination is a helper, not a method.** Following `nextCursor` across pages lives in an unexported `listAll` function in the `mcp` package rather than on `Session`, for the same reason: it is a convenience over `Do`, and `Do` is the whole vocabulary.

If a future contribution genuinely needs to distinguish "tool exists" from "tool is actually callable" (a real and useful distinction), the right design is a narrowly-scoped `DryRunCapabilityCheck` that validates a tool's declared JSON schema without invoking it — not a general invoke path. Open an issue before building this so we can agree on the boundary.

### What `--authorized` is and isn't

It is an acknowledgement, printed as a warning when absent. It is **not** an access control, and it never was: anyone can pass the flag. Earlier versions of this document claimed nothing below the CLI layer runs without it, which was never true in the code. Treating a self-asserted boolean as a safety mechanism would be worse than treating it as what it is — a prompt to think before scanning.

## Evidence integrity

A recon tool's negative results are only worth as much as its ability to tell them apart from failures. Every probe returns one of three things:

| Return | Meaning | Recorded as |
|---|---|---|
| `nil` | Ran and reached a conclusion | `ran` — absent findings are a real negative |
| `probe.ErrNotApplicable` | Correctly declined (TLS check on `http://`, no session ID issued) | `not-applicable` |
| any other error | Could not complete | `error`, and the report becomes `incomplete` |

`report.Report.Probes` carries one `ProbeRun` per probe, and `Report.Status` is `complete` or `incomplete`. A scan that hit its deadline, or whose handshake failed for transport reasons, can never be mistaken for a clean target — the human output says so in a banner, the JSON says so in a field, and the process exits 3.

An auth-gated endpoint is explicitly *not* a failure. It produces `auth_state: auth-gated`, an info-level `mcp-enumeration-blocked` finding, an empty error list, and exit 0.

## Protocol neutrality

Checks split along one axis: does this check read the protocol, or only the transport?

- `internal/probe/mcp` — needs MCP semantics. `Protocol() == "mcp"`.
- `internal/probe/transport` — needs a URL and an HTTP client. `Protocol() == "*"`, so `probe.Registry.ForProtocol` hands them to every target regardless of protocol.
- `internal/probe/generic` — a `probe.Session` that performs plain HTTP requests, used when discovery identifies a protocol REAP can't enumerate yet.

Together these mean an A2A agent card or an OpenAPI service produces a real report — identification, plus TLS, plaintext, downgrade, CORS and rate-limit posture — with no protocol-specific probe written. `cli.newSession` selects the implementation; nothing hardcodes `mcp.NewSession`.

## Adding a new protocol

1. Create `internal/probe/<protocol>/` with a `Session` implementation (see `internal/probe/mcp/session.go` for the MCP reference over streamable HTTP, or `internal/probe/generic/session.go` for the minimal shape).
2. Implement the handshake/negotiation step your protocol needs as a method on your session, mirroring `Session.Initialize`. Keep anything that writes to the target unexported.
3. Add a fingerprint so discovery can identify it: usually a JSON file in `fingerprints/<protocol>/`, no Go required. Declare `paths` explicitly — a fingerprint without them only tries `/`.
4. Write built-in probes in `<protocol>/checks.go` implementing `probe.Probe`. Only write ones that genuinely need protocol semantics; transport-level checks already run via `internal/probe/transport`.
5. Register them from `buildProbeRegistry` in `internal/cli/cli.go`, add the protocol to `validProtocol`, and add a case to `newSession`.
6. Templates automatically work against your protocol once `Template.Protocol` matches — the loader and matcher engine are protocol-agnostic.

## One client for every request

`internal/httpx` builds the single `*httpx.Client` a run uses. This is not incidental tidiness: there were previously six independent client and dialer construction sites, four of which hardcoded a 10-second timeout and ignored `--timeout`, which made flags like `--proxy` and `--insecure` impossible to honour consistently. The rate limiter also has to be shared — a per-probe limiter multiplies the requested rate by the number of probes.

`InspectTLS` is the one deliberate exception to certificate verification: it always skips it, because its job is to report on certificates that *would* fail verification, and refusing the connection would mean never producing the finding.

## Why JSON templates instead of YAML (for now)

Nuclei-style YAML templates were the original plan, but this codebase was bootstrapped without access to a Go module proxy, so no third-party YAML library could be vendored. JSON needs zero dependencies via `encoding/json` in the standard library. The `Template` struct and matcher engine in `internal/template/template.go` don't care what the outer serialization format is — swapping in `gopkg.in/yaml.v3` and changing `LoadDir` to unmarshal YAML instead of JSON is a small, isolated PR. Good first-contribution material if you want to pick it up.

## Known heuristic limits

- `mcp-dynamic-dispatch` relies on naming and schema conventions rather than a semantic proof of dispatch. An operator can evade it by avoiding the expected search/catalog wording and by defining a generic executor schema without the common field names or freeform object shape.
- `mcp-session-id-entropy` infers the alphabet an identifier was drawn from. It cannot detect an ID that looks random but is generated from a weak seed.
- `http-rate-limit-absence` observes advertised headers. A server can rate-limit correctly and advertise nothing; the finding says the posture is undiscoverable, not that it is missing.
