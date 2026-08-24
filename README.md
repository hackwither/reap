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
 <!-- <img src="https://img.shields.io/github/v/release/hackwither/reap" alt="Latest release"> -->
</p>

**REAP is black-box reconnaissance for AI agent endpoints.** Point it at a URL — or a bare `host:port` — that you're authorized to test, and it identifies what agent protocol is running, enumerates the capability surface exposed to the caller, and reports the auth and transport posture around it, without ever invoking a single thing it discovers.

<img width="1080" height="600" alt="reap_video-6" src="https://github.com/user-attachments/assets/fe5cf8f2-c584-4476-9353-99eb50c619f9" />

> **Use only against systems you own or are explicitly authorized to test.** `--authorized` is an acknowledgement, not an access control: REAP still runs without it, and prints a warning. Unauthorized access to computer systems is illegal in most jurisdictions even when every request is read-only. See [`SECURITY.md`](SECURITY.md).

## Why REAP exists

The MCP gateway your team shipped last sprint. The agent endpoint a bug bounty program just put in scope. The internal service someone stood up behind a load balancer with `allowedOrigins: ["*"]` and forgot about. That's what REAP does: external, unauthenticated, black-box recon against a live agent endpoint, from the position an actual attacker occupies.

## What makes it different

**It reads, it never invokes** This is enforced architecturally, not by convention. A probe is only ever handed a `Session`, and `Session` exposes no method to call a tool — or even to send a notification. There is no code path in REAP that sends `tools/call`, on any transport, from any built-in probe or user-supplied template. A scanner that executes what it finds on an agent endpoint isn't a scanner, it's an agent. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the boundary.

**It's agent-native** Anyone can point nuclei at an endpoint and check TLS and CORS. REAP checks the things that only make sense once you know you're talking to an agent: whether the full tool inventory answers to an anonymous caller, whether the handshake `instructions` field leaks operator prompt material, whether a dynamic-dispatch tool is hiding a capability surface much larger than `tools/list` admits to.

**Silence means something** Every probe records whether it ran, declined, errored, or was cut off, and the report carries a `status` of `complete` or `incomplete`. A target REAP couldn't reach never renders as a clean one.

**It's built for pipelines and CI** Text for humans, NDJSON for pipelines, SARIF 2.1.0 for GitHub Advanced Security. `--fail-on` gates a build on severity; findings, usage errors, and incomplete scans each get their own exit code. Single static Go binary, zero third-party dependencies, no API key, no telemetry, nothing leaves your machine except the requests you asked for.

**It's designed to outlive MCP** MCP is the only protocol with enumeration probes today. But every transport and TLS check is protocol-neutral, discovery already identifies A2A agent cards and OpenAPI services, and those targets get a real report — identification plus full transport posture — with no MCP involved.

## Install

Release binaries (Linux, macOS, Windows; amd64 and arm64) are attached to each [release](https://github.com/hackwither/reap/releases).
```sh
go install github.com/hackwither/reap/cmd/reap@latest
```

Docker:

```sh
docker run --rm ghcr.io/hackwither/reap -t https://your-host/mcp --authorized
```

From source:

```sh
git clone https://github.com/hackwither/reap
cd reap && go build -o bin/reap ./cmd/reap
```

Requires Go 1.22+. No other dependencies.
> `go install` places only the binary on your path. REAP loads templates and fingerprints from disk at startup, so point `--templates` and `--fingerprints` at a checkout, or use a release archive or the Docker image, both of which bundle them.

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

Point `-t` at a URL without knowing the protocol, and `--protocol auto` figures out whether — and how — it speaks MCP before running a single security check:

```sh
reap -t https://maybe-an-mcp-host.example --protocol auto --authorized
```

This is the fix for the single biggest trust-killer a recon tool can have: firing a stack of findings against a target that was never actually confirmed to speak the protocol being scanned (a plain web server returning `200`/HTML on every path looks a lot like a listener if nothing checks). Every finding carries a `confidence` ("high"/"medium"/"low"), and if the target never completes a real protocol handshake, `reap` says so loudly and caps every finding at `info`/low-confidence rather than reporting them at face value:

```
⚠ TARGET NOT CONFIRMED AS AGENT ENDPOINT
  mcp initialize handshake failed: decode initialize response: invalid character '<'
  looking for beginning of value. Findings below are LOW confidence and likely
  reflect a generic web server, not a real MCP handshake.
```

`--mode=discover` runs Discovery only (no enumeration/assessment) and prints the resolved `Fingerprint` — protocol, transport, confidence, server metadata — for every target. `--list-detectors` lists the registered detectors, the discovery-time sibling of `--list-probes`.

Discovered/assumed transport also picks which `Session` implementation actually runs the scan: streamable-HTTP, legacy pre-2025-03-26 HTTP+SSE, or a raw WebSocket (non-standard, but observed in some community gateways) — each behind the same `Session` interface and the same no-invoke boundary, so every existing probe and template runs unmodified regardless of which one it lands on.

## Output

The identification block comes first. REAP is a recon tool, so what the endpoint *is* leads, and posture findings follow.

```
reap report — http://10.0.0.7:8080/mcp
  input:      10.0.0.7:8080 (resolved by discovery)
  protocol:   mcp 2025-03-26
  transport:  http-streamable
  server:     internal-gateway 0.9.0
  auth:       open (capability enumeration answered without credentials)
  surface:    23 tools, 4 resources, 0 prompts
  discovery:  mcp-http-streamable (confidence: high)
  duration:   412ms
  probes:     12 ran, 4 not-applicable

  [HIGH]  MCP tool listing accessible without authentication (ASI02, ASI03)
  ...
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan ran; nothing at or above `--fail-on` |
| `1` | Findings at or above `--fail-on` (unset means never) |
| `2` | Usage or validation error |
| `3` | Scan could not complete — findings are not a negative result |

## What it checks

Findings map to OWASP Agentic Security Initiative categories (ASI01-ASI10) — see [`docs/ASI_MAPPING.md`](docs/ASI_MAPPING.md) for why each check cites what it does. Each finding carries a stable rule ID, a confidence level, and, where a single request/response produced it, a reproducible `curl` one-liner so you can verify it by hand rather than take the tool's word for it.

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

### Transport posture — runs against every protocol

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

Drop a JSON template in `templates/`, no Go, no rebuild:

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

The strict fixture is the more useful of the two — it only answers a client that negotiates protocol versions, sends `notifications/initialized`, carries the protocol header, and follows `nextCursor`.

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
