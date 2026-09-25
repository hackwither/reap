<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.png">
    <img src="assets/logo.png" alt="REAP logo" width="160">
  </picture>
</p>

<h1 align="center">REAP</h1>
<p align="center"><strong>Reconnaissance and Enumeration for Agent Protocols</strong></p>

<p align="center">
  <img src="https://img.shields.io/github/go-mod/go-version/hackwither/reap" alt="Go version">
  <img src="https://img.shields.io/github/license/hackwither/reap" alt="License">
  <img src="https://img.shields.io/github/v/release/hackwither/reap" alt="Latest release">
</p>

**REAP is black-box reconnaissance for AI agent endpoints.** Point it at a URL or a bare `host:port` that you're authorized to test, and it identifies what agent protocol is running, enumerates the capability surface exposed to the caller, and reports the auth and transport posture around it, without ever invoking a single thing it discovers.

<img width="1080" height="600" alt="reap_video-6" src="https://github.com/user-attachments/assets/fe5cf8f2-c584-4476-9353-99eb50c619f9" />

> **This illustration uses [reap-range](https://github.com/hackwither/reap-range) to demonstrate the capabilities of this tool. Use only against systems you own or are explicitly authorized to test.** `--authorized` is an acknowledgement, not an access control: REAP still runs without it, and prints a warning. Unauthorized access to computer systems is illegal in most jurisdictions even when every request is read-only. See [`SECURITY.md`](SECURITY.md).

## Why REAP exists

The MCP gateway your team shipped last sprint, to the agent endpoint a bug bounty program just put in scope. That's what REAP is for: external, unauthenticated, black-box recon against a live agent endpoint, from the position an actual attacker occupies.

## What makes it different

**It reads, never invokes** This is enforced architecturally, not by review. A probe is only ever handed a `Session` — and that's the entire surface it gets:

```go
type Session interface {
	TargetURL() string
	Do(ctx context.Context, method string, params any, opts ...ReqOption) (*RawResult, error)
}
```

No `Call`. No `Invoke`. There is no method on `Session` that can dispatch a discovered tool — a probe that wants to do more than this has to go through a design discussion first, not a code review. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full boundary.

**It's agent-native** Anyone can point nuclei at an endpoint and check TLS and CORS — that part's table stakes, and REAP does it too (see Transport posture below). What it adds on top is the stuff that only makes sense once you know you're talking to an agent: whether the full tool inventory answers to an anonymous caller, whether the handshake `instructions` field leaks operator prompt material, whether a dynamic-dispatch tool is hiding a capability surface much larger than `tools/list` admits to. Tools like [mcprobe](https://github.com/tamish560/mcprobe) inspect the MCP server you're about to install, by launching it and reading its metadata; REAP inspects the endpoint you've already exposed, from outside, with no credentials and no invocation. Different lane, zero check overlap.

**Silence means something** Every probe records whether it ran, declined, errored, or was cut off, and the report carries a `status` of `complete` or `incomplete`. A target REAP couldn't reach never renders as a clean one — see [Coverage accounting](#coverage-accounting).

**It's built for pipelines and CI** Text for humans, NDJSON for pipelines, SARIF 2.1.0 for GitHub Advanced Security. `--fail-on` gates a build on severity; findings, usage errors, and incomplete scans each get their own exit code. Single static Go binary, zero third-party dependencies, no API key, no telemetry, nothing leaves your machine except the requests you asked for.

**It's designed to outlive MCP** MCP is the only protocol with enumeration probes today. But every transport and TLS check is protocol-neutral, discovery already identifies A2A agent cards and OpenAPI services, and those targets get a real report, identification plus full transport posture with no MCP involved.

## Install

Release binaries (Linux, macOS, Windows; amd64 and arm64) are attached to each [release](https://github.com/hackwither/reap/releases):

```sh
curl -sSL https://github.com/hackwither/reap/releases/download/v0.1.0/reap_0.1.0_linux_amd64.tar.gz | tar xz
```

(swap in the [latest release](https://github.com/hackwither/reap/releases) tag and your platform's `darwin`/`windows` + `amd64`/`arm64` combo.)

macOS binaries are unsigned and unnotarized, so Gatekeeper quarantines them on first download. If `./reap` refuses to run, clear the quarantine flag:

```sh
xattr -d com.apple.quarantine ./reap
```

Docker:

```sh
docker run --rm ghcr.io/hackwither/reap -t https://your-host/mcp --authorized
```

Homebrew:

```sh
brew install hackwither/tap/reap
```

`go install`, if you'd rather build from the module cache than take a binary:

```sh
go install github.com/hackwither/reap/cmd/reap@latest
```

From source:

```sh
git clone https://github.com/hackwither/reap
cd reap && go build -o bin/reap ./cmd/reap
```

Requires Go 1.22+. No other dependencies.
> The built-in templates and fingerprints are embedded in the binary, so a `go install`'d REAP works with no checkout on disk. Point `--templates` / `--fingerprints` at a directory to load your own on top of the built-ins, or pass an empty string to disable the built-in set.

## Quick start

Scan one endpoint:

```sh
reap -t https://your-host/mcp --authorized
```

Give it a bare `host:port` and let discovery find the endpoint:

```sh
reap -t 10.0.0.7:8080 --authorized
```

With credentials, to see what an authenticated caller gets:

```sh
reap -t https://your-host/mcp --auth-header "Bearer $TOKEN" --authorized
```

Just identify what's there, without scanning:

```sh
reap -t 10.0.0.7:8080 --mode discover
```

A whole scope list, concurrently, as NDJSON:

```sh
cat scope.txt | reap --authorized --output json --concurrency 10
```

Through Burp, for manual follow-up:

```sh
reap -t https://your-host/mcp --authorized --proxy http://127.0.0.1:8080
```

In CI, as SARIF, failing the build on anything high:

```sh
reap -t "$MCP_ENDPOINT" --authorized --output sarif --out reap.sarif --fail-on high
```

```yaml
# .github/workflows/agent-recon.yml
- name: Upload REAP findings
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reap.sarif
```

## Discovery: "is there an agent here at all?"

Point `-t` at a URL without knowing the protocol, and `--protocol auto` figures out whether and how it speaks MCP before running a single security check:

```sh
reap -t https://maybe-an-mcp-host.example --protocol auto --authorized
```

This is the fix for the single biggest trust-killer a recon tool can have: firing a stack of findings against a target that was never actually confirmed to speak the protocol being scanned (a plain web server returning `200`/HTML on every path looks a lot like a listener if nothing checks). Every finding carries a `confidence` ("high"/"medium"/"low"), and if the target never completes a real protocol handshake, `reap` says so loudly and caps every finding at `info`/low-confidence rather than reporting them at face value:

```
⚠ TARGET NOT CONFIRMED AS AN AGENT ENDPOINT
  mcp initialize handshake failed: decode initialize response: invalid character '<'
  looking for beginning of value. Findings below are LOW confidence and likely
  reflect a generic web server, not a real MCP handshake.
```

`--mode=discover` runs Discovery only (no enumeration/assessment) and prints the resolved `Fingerprint` [protocol, transport, confidence, server metadata] for every target. `--list-detectors` lists the registered detectors, the discovery-time sibling of `--list-probes`.

Discovered/assumed transport also picks which `Session` implementation actually runs the scan: streamable-HTTP, legacy pre-2025-03-26 HTTP+SSE, or a raw WebSocket (non-standard, but observed in some community gateways), each behind the same `Session` interface and the same no-invoke boundary, so every existing probe and template runs unmodified regardless of which one it lands on.

## Output

The identification block comes first. REAP is a recon tool, so what the endpoint *is* leads, and posture findings follow. This is a real transcript, against the mock target from [Testing against a local range](#testing-against-a-local-range) below:

```
 REAP  /  AI AGENT RECON
 ────────────────────────────────────────────────────────────────────
 v0.1.0

 TARGET
 http://127.0.0.1:8765/mcp
 127.0.0.1  •  MCP 2025-06-18  •  http-streamable  •  CONFIRMED
 Agent       mock-insecure-gateway 0.9.0
 Edge        BaseHTTP/0.6 Python/3.11.14
 Discovery   mcp-http-streamable  •  high confidence
 Auth        open  •  enumeration answered without credentials
 Surface     3 tools  •  1 resources  •  0 prompts

 FINDINGS  10 matched  •  use -v for full evidence

 HIGH mcp-unauth-tools-list  HIGH CONFIDENCE
 MCP tool listing accessible without authentication
 tools/list returned 3 tool(s) to an unauthenticated caller: read_file, exec_shell, send_email
 OWASP       ASI02: Tool Misuse & Exploitation, ASI03: Agent Identity & Privilege Abuse
 Fix         Require authentication before tools/list, or scope the response so anonymous callers see nothing.

 HIGH http-cors-wildcard
 Permissive CORS policy on agent endpoint
 Server returns Access-Control-Allow-Origin: * — any web origin can call this endpoint from a browser context.
 OWASP       ASI03: Agent Identity & Privilege Abuse
 Fix         Scope Access-Control-Allow-Origin to known first-party origins; never combine * with credentialed requests.
 ...

 POSTURE
 HIGH RISK

 17 checks  •  10 matched  •  4 clean  •  3 skipped  •  8ms
 3 high · 2 med · 3 low · 2 info · 0 error
```

`TARGET`'s state (`CONFIRMED`, `CONFIRMED (AUTH-GATED)`, or `UNCONFIRMED`) is about whether the endpoint is provably speaking the protocol — see [Discovery](#discovery-is-there-an-agent-here-at-all) above. `POSTURE` is a separate, unrelated verdict: the highest severity found (`CLEAN`, `INFORMATIONAL`, `LOW`/`MEDIUM`/`HIGH RISK`), or `SCAN ERROR` if nothing ran cleanly. Don't conflate the two — a confirmed target can still post a clean posture, and an unconfirmed one is capped at `INFORMATIONAL` regardless of what it looks like it returned.

### Coverage accounting

The line above `POSTURE` — `17 checks  •  10 matched  •  4 clean  •  3 skipped  •  8ms` — is the part worth reading closely, because it's the difference between "nothing wrong" and "we don't actually know."

- **matched**: the check ran and found something; that's a finding above.
- **clean**: the check ran, found nothing, and *was applicable* — this endpoint was actually tested for that condition and passed.
- **skipped**: the check declined because it didn't apply here (wrong transport, capability absent) *or* was excluded via `--include`/`--exclude`. Either way, it says nothing about whether the target is safe.
- **could not run** (only shown when nonzero): the check errored or was aborted — a transport failure, a decode error, a timeout. This is the one that matters most: it means the report is silent on that check not because the target passed, but because REAP couldn't finish asking the question. Each one is also listed individually below the coverage line, with its status and detail.

When any check falls into that last bucket, the scan's `status` is `incomplete` and the report leads with `⚠ SCAN INCOMPLETE — ABSENT FINDINGS ARE NOT CLEAN RESULTS`. Every probe in REAP returns one of three things — a finding, `probe.NotApplicable("why")`, or a real error — and never silently swallows a failure as "nothing to report" (see [`CONTRIBUTING.md`](CONTRIBUTING.md)). That three-state contract is what makes the coverage line trustworthy: it can only report what it actually checked, because the type system won't let a probe claim "clean" for a check it never really ran.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan ran; nothing at or above `--fail-on` |
| `1` | Findings at or above `--fail-on` (unset means never) |
| `2` | Usage or validation error |
| `3` | Scan could not complete, findings are not a negative result |

## What it checks

Findings map to OWASP Agentic Security Initiative categories (ASI01-ASI10), see [`docs/ASI_MAPPING.md`](docs/ASI_MAPPING.md) for why each check cites what it does, and [`docs/PROBES.md`](docs/PROBES.md) for the full probe reference. Each finding carries a stable rule ID, a confidence level, and, where a single request/response produced it, a reproducible `curl` one-liner so you can verify it by hand rather than take the tool's word for it.

### Recon: what is this endpoint, and what will it tell a stranger?

| Check | What it finds |
|---|---|
| `mcp-auth-posture` | Whether enumeration is open, auth-gated, or unreachable; emits `mcp-enumeration-blocked` when gated |
| `mcp-tool-capability-surface` | Full reported tool inventory, paginated, for asset tracking and cross-run diffing |
| `mcp-unauth-tools-list` | `tools/list` answering to unauthenticated callers |
| `mcp-resources-prompts-exposure` | Unauthenticated `resources/list` and `prompts/list` |
| `mcp-dynamic-dispatch` | Dispatch/search tool patterns implying a hidden capability surface larger than `tools/list` reports |
| `mcp-instructions-exposure` | Handshake `instructions` leaking operator prompt material |

### Auth and session posture

| Check | What it finds |
|---|---|
| `mcp-oauth-metadata-posture` | OAuth metadata not advertising PKCE |
| `mcp-oauth-bearer-challenge-missing` | A 401 with no `WWW-Authenticate: Bearer`, so clients can't discover where to authenticate |
| `mcp-redirect-uri-laxity` | Overly broad or wildcard OAuth redirect URI registration |
| `mcp-session-id-entropy` | Weak or predictable session identifiers (the value itself is never recorded) |
| `mcp-host-header-validation` | Servers not validating `Host` during `initialize` (DNS rebinding) |

### Transport posture: runs against every protocol

These report `protocol=*` and apply to any endpoint REAP can identify, including ones with no enumeration probes yet.

| Check | What it finds |
|---|---|
| `transport-plaintext` | Endpoints served over plaintext HTTP |
| `transport-downgrade` | The same host also accepting agent traffic in the clear |
| `tls-cert-health` | Certificate validity, hostname mismatch, weak protocol and cipher selection |
| `http-cors-wildcard` | Wildcard or reflected CORS, via a real preflight, and wildcard combined with credentials |
| `http-rate-limit-absence` | Missing standard rate-limit headers |

`reap --list-probes` prints the live set. Select with `--include` / `--exclude`; an unknown ID is a usage error rather than a silent no-op.

## Protocol support

| Protocol | Discovery | Enumeration | Transport posture |
|---|---|---|---|
| MCP (streamable HTTP) | yes | yes | yes |
| MCP (legacy HTTP+SSE) | yes | — | yes |
| MCP (WebSocket, non-standard) | yes | — | yes |
| A2A (agent card) | yes | — | yes |
| OpenAPI / REST tool surface | yes | — | yes |

REAP negotiates MCP protocol versions `2025-06-18`, `2025-03-26`, and `2024-11-05`, sends the spec-required `notifications/initialized`, and carries the `MCP-Protocol-Version` header on post-handshake requests.

## Writing your own checks

Drop a JSON template in a directory and point `--templates` at it, no Go, no rebuild. It loads alongside the built-in set embedded in the binary:

```json
{
  "id": "mcp-tmpl-custom-header-leak",
  "protocol": "mcp",
"info": {
    "title": "Internal service header disclosed",
    "severity": "medium",
    "asi_refs": ["ASI09"],
    "description": "tools/list responses disclose an internal-service header."
  },
  "request": { "method": "tools/list" },
  "match_logic": "all",
  "matchers": [
    { "type": "status_code", "equals": 200 },
    { "type": "header", "header": "X-Internal-Service" }
  ]
}
```

Matchers: `status_code`, `header`, `body_contains`, `json_path`, combined with `any` (default) / `all` via `match_logic`. See [`docs/WRITING_PROBES.md`](docs/WRITING_PROBES.md) for the full field reference, including `info.references` and how confidence/reproduction are derived automatically.

Discovery fingerprints in `fingerprints/` use the same matcher vocabulary to identify protocols.

A template deliberately **cannot** chain requests, branch on response data, or invoke a discovered tool. The first two are a roadmap item. The third never will be. If your check needs real logic, write a Go probe, see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Testing against a local range

```sh
python3 scripts/mock_mcp_server.py &          # permissive: lights up most probes
reap -t http://127.0.0.1:8765/mcp --authorized

python3 scripts/strict_mcp_server.py &        # pedantic: old spec revision, paginated, strict handshake
reap -t http://127.0.0.1:8099/mcp --authorized
```

## Roadmap

Shipped: automatic protocol/transport discovery (`--protocol auto`, `--mode discover`), confidence-scored findings with a hard downgrade for unconfirmed targets, legacy HTTP+SSE and WebSocket transports alongside streamable-HTTP.

Planned, not yet shipped:

- **A2A and OpenAPI enumeration**: discovery and transport posture work today; skill/operation enumeration does not exist yet.
- **Baseline diffing**: compare a scan against a stored previous run to surface capability-surface drift.
- **Tag-based selection**: `--tags` alongside `--include`, once probes carry tags rather than only findings.
- **stdio transport**: a manually-specified local MCP server launch (`--target-stdio`), behind the same `Session` interface and no-invoke boundary.
- **Bounded range discovery**: sweep an operator-supplied host and port list for agent endpoints.

Issues and PRs welcome on any of these.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). The one non-negotiable: nothing merged into REAP invokes a discovered capability. Every new protocol, transport, probe, and template is held to that boundary, and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) explains how it's enforced in the type system rather than by review.

## License

MIT. See [`LICENSE`](LICENSE).

Built by [@hackwither](https://github.com/hackwither).
