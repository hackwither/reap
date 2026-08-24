# Probes

Reap ships 16 built-in MCP probes: 15 hand-written Go probes (`internal/probe/mcp/checks.go`, `server_header.go`) registered via `BuiltinProbes()`, plus 1 declarative JSON template probe (`templates/mcp/high-risk-tool-names.json`) loaded at runtime from `--templates` (default `templates/`). See [WRITING_PROBES.md](WRITING_PROBES.md) for how to add more.

## Basis: OWASP ASI

Each finding maps to a category from the **OWASP Agentic Security Initiative (ASI)**, ASI01–ASI10 (see [README.md:131](../README.md#L131)). This is the classification scheme the probes are organized against, not a probe-writing spec. Probe logic itself is hand-derived (protocol RFCs, MCP spec, common misconfig patterns), and each finding just carries an `ASI` tag (`report.Finding.ASI`) pointing at the category it evidences. A probe can tag more than one category.

## Go probes (`internal/probe/mcp`)

| ID | Severity (max) | ASI | Description |
|---|---|---|---|
| `mcp-tls-cert-health` | High | ASI09 | Inspects the live TLS handshake for expired/not-yet-valid/self-signed certs, hostname mismatch, weak TLS version, or weak cipher suite. |
| `mcp-host-header-validation` | High | ASI05 | Sends `initialize` with a mismatched `Host` header; flags servers that process it anyway (no host-name validation). |
| `mcp-rate-limit-absence` | Info | ASI08 | Checks `initialize`/`tools/list` responses for standard rate-limit headers (`Retry-After`, `RateLimit-*`); flags their absence as a DoS reconnaissance signal. |
| `mcp-transport-downgrade` | Medium | ASI09 | On an `https://` target, probes for a plaintext-HTTP listener on the same host/path (and `/sse`) that also serves MCP traffic. |
| `mcp-oauth-bearer-challenge-missing` | Medium | ASI03 | An unauthenticated `tools/list` returns 401 but the `WWW-Authenticate` header doesn't include a `Bearer` challenge (RFC 9728/6750). Emitted by the same probe as `mcp-oauth-metadata-posture`. |
| `mcp-oauth-metadata-posture` | Low | ASI03 | Checks published OAuth authorization-server/protected-resource metadata (`.well-known/*`) for PKCE advertisement (`code_challenge_methods_supported`). |
| `mcp-redirect-uri-laxity` | Medium | ASI03 | Scans discovered OAuth metadata for registered redirect URIs that are wildcarded, non-HTTPS, missing a host, or missing a path. |
| `mcp-session-id-entropy` | Medium | ASI03 | Analyzes the `Mcp-Session-Id` header value for short length, small character set, repeated characters, or low estimated bit-entropy. Streamable-HTTP only. |
| `mcp-unauth-tools-list` | High | ASI02, ASI03 | Re-issues `tools/list` with no auth header; flags a successful (200, no RPC error) response, escalating severity if any returned tool name matches high-risk hints (exec, shell, sql, fetch_url, ...). |
| `mcp-enumeration-blocked` | Info | ASI09 | Companion finding to `mcp-tool-capability-surface`: reports (informationally) when `tools/list` is correctly gated behind auth (401/403), so enumeration coverage is documented either way. |
| `mcp-tool-capability-surface` | Info | ASI09 | On a successful `tools/list`, records the full tool inventory plus a dangerous-tools subset for asset-inventory/diffing purposes. |
| `mcp-cors-wildcard` | High | ASI03 | Sends a foreign `Origin` header; flags `Access-Control-Allow-Origin: *`, escalating to High if combined with `Access-Control-Allow-Credentials: true`. |
| `mcp-plaintext-transport` | Medium | ASI04 | Flags when the target URL itself uses `http://` rather than `https://`. |
| `mcp-instructions-exposure` | Low | ASI09 | Flags the `initialize` response's free-text `instructions` field when it's long (>400 chars) or contains secrecy/credential-flavored keywords ("never reveal", "api key", "internal", ...). |
| `mcp-resources-prompts-exposure` | Low | ASI02 | Calls `resources/list` and `prompts/list` with no auth; flags either returning items to an anonymous caller (finding ID suffixed per method). |
| `mcp-dynamic-dispatch` | High | ASI09 | Inspects `tools/list` for a search/discovery tool plus a generic executor tool (free-form args + required identifier); flags that the declared surface likely undercounts real callable tools. Pattern-matching heuristic, evadable. |
| `mcp-tmpl-server-header-fingerprint` | Info | ASI09 | Flags a `Server` header (excluding known CDN/edge tokens: cloudflare, envoy, nginx, cloudfront, varnish, akamai, fastly) or any `X-Powered-By` header identifying backend/origin software. |

## Template probes (`templates/mcp`)

| ID | Severity | ASI | Description |
|---|---|---|---|
| `mcp-tmpl-high-risk-tool-names` | Medium | ASI02, ASI07 | Declarative JSON-template probe: `tools/list` (with credentials, if any) and match any tool name against a code-execution/filesystem-primitive name list (exec_shell, run_command, eval, read_file, write_file, ...). |

## Notes

- Every probe declares `Transports()` — most run on `anyTransport`, but several are gated to `httpOnlyTransports` (TLS/CORS/host-header/rate-limit/downgrade/OAuth probes, since they're HTTP-specific) or `streamableHTTPOnly` (session-ID entropy, since only that transport returns `Mcp-Session-Id`).
- `mcp-oauth-metadata-posture`'s `Run` can emit two distinct finding IDs (`mcp-oauth-bearer-challenge-missing` and `mcp-oauth-metadata-posture` itself) from one probe, since the two RFC signals live in different places and shouldn't be conflated.
