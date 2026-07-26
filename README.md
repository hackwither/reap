# REAP

### **Reconnaissance and Enumeration for Agent Protocols**

`reap` is active reconnaissance for AI agent endpoints. It probes protocol surface and auth posture, and surfaces findings without invoking any discovered tool.

>  **Use only against systems you own or are explicitly authorized to test.**
> `reap` can run without `--authorized`, but you should only do so when you have permission to test the target. Unauthorized access to computer systems is illegal in most jurisdictions even when every request is read-only. See [`SECURITY.md`](SECURITY.md).

## Why REAP

Agent protocols are being deployed faster than the tooling to audit them. An MCP server can leak its full tool inventory to anonymous callers, advertise permissive CORS, or expose a dynamic-dispatch tool that hides a much larger capability surface than `tools/list` reports, and today there's no standard way to check for any of it before something goes live.

`reap` exists to close that gap: a single, purpose-built recon tool for the agent-protocol layer, with a hard architectural boundary against ever touching what it finds.

## What this project is

`reap` is designed as a reconnaissance tool for agent protocols, with an initial focus on MCP (Model Context Protocol) over streamable HTTP.

It is intentionally not:

- an internet-wide scanner
- a tool that invokes discovered agent capabilities
- a static analysis tool that needs target source code

## Use cases

`reap` is useful for:

- detecting overly-permissive CORS headers on agent gateways
- finding plaintext HTTP transport exposure
- auditing whether handshake instructions leak sensitive prompt material
- discovering dynamic-dispatch patterns where the true capability surface may be larger than `tools/list`
- integrating agent protocol reconnaissance into security reviews and CI workflows

## Supported protocol

- `mcp`: the Model Context Protocol over HTTP

The codebase is architected so new protocols can be added later, but MCP is the only supported protocol today. As agent protocols proliferate, REAP is designed to grow into the protocol-agnostic recon layer for all of them.

## Built-in MCP checks

The built-in MCP probe suite includes the following checks:
| Check Name | Description |
|---|---|
| `mcp-unauth-tools-list` | Detects whether `tools/list` is accessible to unauthenticated callers. |
| `mcp-tool-capability-surface` | Enumerates the full reported tool inventory for asset discovery and diffing. |
| `mcp-cors-wildcard` | Flags permissive wildcard CORS policies and credentialed cross-origin access. |
| `mcp-plaintext-transport` | Detects MCP endpoints served over plaintext HTTP instead of HTTPS. |
| `mcp-tls-cert-health` | Checks TLS certificate validity, hostname matching, and weak protocol/cipher posture. |
| `mcp-host-header-validation` | Verifies the server validates the Host header during MCP initialize requests. |
| `mcp-rate-limit-absence` | Reports missing standard rate-limit headers on successful MCP responses. |
| `mcp-transport-downgrade` | Detects the same host accepting MCP-style traffic over plaintext HTTP. |
| `mcp-oauth-metadata-posture` | Inspects OAuth metadata endpoints for Bearer challenge and PKCE advertising. |
| `mcp-redirect-uri-laxity` | Identifies overly broad or wildcard OAuth redirect URI registration. |
| `mcp-session-id-entropy` | Checks MCP session ID entropy for weak or predictable identifiers. |
| `mcp-instructions-exposure` | Flags lengthy or sensitive-feeling initialize instructions returned during handshake. |
| `mcp-resources-prompts-exposure` | Detects unauthenticated access to `resources/list` and `prompts/list`. |
| `mcp-dynamic-dispatch` | Detects dynamic dispatch/search tool patterns that imply a hidden or incomplete capability surface. |

## How it works

### CLI flow

1. Parse flags and load templates from `templates/` by default
2. Validate authorization via `--authorized`
3. Collect targets from `-t`, `--targets-file`, or stdin
4. For each target:
   - create an MCP session
   - perform `initialize`
   - run all probes for the requested protocol
   - build a `report.Report`
5. Render output as text, JSON, or SARIF

### Output modes

- `text` : human-readable report
- `json` : machine-readable JSON report (`NDJSON` for batch mode)
- `sarif` : SARIF 2.1.0 report for CI/security tooling

If `--out` is provided, file output is written in addition to stdout.

## Installation

Build from source with Go:

```bash
go install github.com/hackwither/reap/cmd/reap@latest
```

Or build locally:

```bash
go build -o bin/reap ./cmd/reap
```

## Basic usage

```bash
reap -t https://your-host/mcp --auth-header "Bearer $TOKEN" --authorized
```

Machine readable output:

```bash
reap -t https://your-host/mcp --authorized --output json --out results/report.json
```

List available probes:

```bash
reap --list-probes
```

Batch mode example:

```bash
cat targets.txt | reap --authorized --output json
```

## CLI flags

- `-t`, `--target` : target MCP endpoint URL
- `--targets-file` : file containing one target URL per line
- `--protocol` : protocol to probe (`mcp`)
- `--auth-header` : optional Authorization header value
- `--timeout` : per-request timeout (default `10s`)
- `--templates` : directory of JSON probe templates (default `templates`)
- `-v`, `--verbose` : enable verbose scan progress output
- `--output` : output format: `text`, `json`, `sarif`
- `--out` : write report to file in addition to stdout
- `--include` : comma-separated probe IDs to run
- `--exclude` : comma-separated probe IDs to skip
- `--list-probes` : list all registered probes and exit
- `--authorized` : assert you are authorized to test the target(s)
- `--concurrency` : number of concurrent target scans in batch mode

## Templates and extensibility

`reap` supports declarative JSON probe templates in `templates/`.

A template can:

- send a single request to the target protocol
- inspect HTTP headers, status code, response body, and JSON payload
- run `status_code`, `header`, `body_contains`, and `json_path` matchers
- be enabled or disabled via `--include` / `--exclude`

### Limitations

A template cannot:

- chain multiple requests
- branch based on response data
- invoke discovered tools or side-effecting actions

If your check needs more logic than this, write a Go probe in `internal/probe/<protocol>/checks.go`.


## Development

Run the unit tests:

```bash
go test ./...
```

Build a local executable:

```bash
go build -o bin/reap ./cmd/reap
```

## Safety notice

`reap` is a reconnaissance-only tool. It is explicitly designed to avoid destructive or exploitation behavior. Review the safety boundary in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) before adding new protocol support.

## License

MIT, see [`LICENSE`](LICENSE).
