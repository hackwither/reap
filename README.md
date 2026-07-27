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

**REAP is black-box reconnaissance for AI agent endpoints.** Point it at a URL you're authorized to test and it identifies what agent protocol is running, enumerates the capability surface exposed to the caller, and reports the auth and transport posture around it, without ever invoking a single thing it discovers.

> **Use only against systems you own or are explicitly authorized to test.** REAP runs without `--authorized`, but you should only do that when you have permission. Unauthorized access to computer systems is illegal in most jurisdictions even when every request is read-only. See [`SECURITY.md`](SECURITY.md).

## Why REAP exists

The MCP gateway your team shipped last sprint. The agent endpoint a bug bounty program just put in scope. The internal service someone stood up behind a load balancer with `allowedOrigins: ["*"]` and forgot about. That's what REAP does: external, unauthenticated, black-box recon against a live agent endpoint, from the position an actual attacker occupies.

## What makes it different

**It reads, it never invokes** This is enforced architecturally, not by convention. A probe is only ever handed a `Session`, and `Session` exposes no method to call a tool. There is no code path in REAP that sends `tools/call`, on any transport, from any built-in probe or user-supplied template. A scanner that executes what it finds on an agent endpoint isn't a scanner, it's an agent. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the boundary.

**It's agent-native** Anyone can point nuclei at an endpoint and check TLS and CORS. REAP checks the things that only make sense once you know you're talking to an agent: whether the full tool inventory answers to an anonymous caller, whether the handshake `instructions` field leaks operator prompt material, whether a dynamic-dispatch tool is hiding a capability surface much larger than `tools/list` admits to.

**It's built for pipelines and CI** Text for humans, NDJSON for pipelines, SARIF 2.1.0 for GitHub Advanced Security and every other code-scanning ingestion point. Single static Go binary, zero third-party dependencies, no API key, no telemetry, nothing leaves your machine except the requests you asked for.

**It's designed to outlive MCP** MCP is the only supported protocol today, and it's the right first target. But the architecture (a protocol registry, per-protocol sessions, declarative checks) assumes there will be others.

## Install

```sh
go install github.com/hackwither/reap/cmd/reap@latest
```

Or build from source:

```sh
git clone https://github.com/hackwither/reap
cd reap && go build -o bin/reap ./cmd/reap
```

Requires Go 1.21+. No other dependencies.

## Quick start

Scan a single endpoint:

```sh
reap -t https://your-host/mcp --authorized
```

With credentials, to see what an authenticated caller gets:

```sh
reap -t https://your-host/mcp --auth-header "Bearer $TOKEN" --authorized
```

Machine-readable, written to a file:

```sh
reap -t https://your-host/mcp --authorized --output json --out results/report.json
```

A whole scope list, concurrently, as NDJSON:

```sh
cat scope.txt | reap --authorized --output json --concurrency 10
```

In CI, as SARIF:

```sh
reap -t "$MCP_ENDPOINT" --authorized --output sarif --out reap.sarif
```

```yaml
# .github/workflows/agent-recon.yml
- name: Upload REAP findings
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reap.sarif
```

## What it checks

Findings map to OWASP Agentic Security Initiative categories (ASI01-ASI10).

### Capability surface: what is this endpoint willing to tell a stranger?

| Check | What it finds |
|---|---|
| `mcp-unauth-tools-list` | `tools/list` answering to unauthenticated callers |
| `mcp-tool-capability-surface` | Full reported tool inventory, for asset tracking and cross-run diffing |
| `mcp-resources-prompts-exposure` | Unauthenticated `resources/list` and `prompts/list` |
| `mcp-dynamic-dispatch` | Dispatch/search tool patterns implying a hidden capability surface larger than `tools/list` reports |
| `mcp-instructions-exposure` | Handshake `instructions` leaking operator prompt material |

### Auth and session posture

| Check | What it finds |
|---|---|
| `mcp-oauth-metadata-posture` | OAuth metadata endpoints missing Bearer challenge or PKCE advertisement |
| `mcp-redirect-uri-laxity` | Overly broad or wildcard OAuth redirect URI registration |
| `mcp-session-id-entropy` | Weak or predictable session identifiers |
| `mcp-host-header-validation` | Servers not validating `Host` during `initialize` |

### Transport posture

| Check | What it finds |
|---|---|
| `mcp-plaintext-transport` | Endpoints served over plaintext HTTP |
| `mcp-transport-downgrade` | The same host also accepting MCP traffic in the clear |
| `mcp-tls-cert-health` | Certificate validity, hostname mismatch, weak protocol and cipher selection |
| `mcp-cors-wildcard` | Wildcard CORS, and wildcard combined with credentialed cross-origin access |
| `mcp-rate-limit-absence` | Missing standard rate-limit headers on successful responses |

`reap --list-probes` prints the live set. Select with `--include` / `--exclude`.

## Writing your own checks

Drop a JSON template in `templates/`, no Go, no rebuild:

```json
{
  "id": "mcp-custom-header-leak",
  "protocol": "mcp",
  "severity": "medium",
  "request": { "method": "tools/list" },
  "matchers": {
    "condition": "all",
    "rules": [
      { "type": "status_code", "values": [200] },
      { "type": "header", "name": "X-Internal-Service", "present": true }
    ]
  }
}
```

Matchers: `status_code`, `header`, `body_contains`, `json_path`, combined with `any` / `all`.

A template deliberately **cannot** chain requests, branch on response data, or invoke a discovered tool. The first two are a roadmap item. The third never will be. If your check needs real logic, write a Go probe in `internal/probe/<protocol>/checks.go`, see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Roadmap

Planned, not yet shipped:

- **Additional transports**: legacy HTTP+SSE, stdio, WebSocket, behind the same `Session` interface and the same no-invoke boundary.
- **Bounded range discovery**: sweep an operator-supplied host and port list for agent endpoints.
- **More protocols**: A2A, and whatever else reaches deployment scale.

Issues and PRs welcome on any of these.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). The one non-negotiable: nothing merged into REAP invokes a discovered capability. Every new protocol, transport, probe, and template is held to that boundary, and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) explains how it's enforced in the type system rather than by review.

## License

MIT. See [`LICENSE`](LICENSE).

Built by [@hackwither](https://github.com/hackwither).
