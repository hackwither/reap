# ASI mapping rationale

REAP cites [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) categories on its findings, and [`docs/WRITING_PROBES.md`](WRITING_PROBES.md) tells contributors not to cite one just to look thorough. This file holds REAP to the same rule: every mapping below has to be defensible, and two earlier ones weren't.

## Current mappings

| Check | ASI | Why |
|---|---|---|
| `mcp-unauth-tools-list` | ASI02, ASI03 | An anonymous caller learning the full tool inventory is the reconnaissance step for tool misuse (ASI02), and it means the endpoint applies no caller identity (ASI03). |
| `mcp-tool-capability-surface` | ASI09 | Inventory for asset tracking and drift detection — an observability concern, not a vulnerability. |
| `mcp-resources-prompts-exposure` | ASI02 | Resource and prompt listings widen what an unauthenticated caller can enumerate and later target. |
| `mcp-dynamic-dispatch` | ASI09 | The real callable surface exceeds what `tools/list` reports, so any inventory built from it is incomplete. That is an auditability gap. |
| `mcp-instructions-exposure` | ASI09 | Operator prompt material returned pre-authentication is unintended disclosure through a protocol field. |
| `mcp-auth-posture` / `mcp-enumeration-blocked` | — | Deliberately uncited. It records a fact about the endpoint; it is not a weakness. |
| `mcp-oauth-metadata-posture` | ASI03 | MCP clients are public OAuth clients, for which PKCE is required. Without it, an intercepted authorization code is redeemable — an identity weakness. |
| `mcp-oauth-bearer-challenge-missing` | ASI03 | Clients cannot discover where to authenticate, so deployments drift toward weaker out-of-band credential handling. |
| `mcp-redirect-uri-laxity` | ASI03 | Broad redirect registration enables confused-deputy and code-interception attacks against the agent's identity. |
| `mcp-session-id-entropy` | ASI03 | A guessable session ID lets an attacker assume another caller's identity directly. |
| `mcp-host-header-validation` | ASI03 | DNS rebinding lets a web page reach an agent endpoint and act with the victim's network position. |
| `transport-plaintext` | ASI04 | Agent traffic, tool arguments, and bearer tokens readable on the wire. |
| `transport-downgrade` | ASI04 | A plaintext listener on the same host defeats the TLS the endpoint otherwise offers. |
| `tls-cert-health` | ASI09 | Certificate and cipher problems undermine the assurance the transport is supposed to provide. |
| `http-cors-wildcard` | ASI03 | Permissive CORS lets an arbitrary web origin act as the agent from a victim's browser. |
| `http-rate-limit-absence` | ASI06 | No advertised limiting means a caller can drive the agent (and everything downstream of it) without backpressure. |

## Two corrections

**`mcp-host-header-validation` cited ASI05 (Memory & Context Poisoning).** DNS rebinding has nothing to do with an agent's memory or context. It is an identity and privilege problem: the attacker borrows the victim's network position to reach an endpoint that trusts it. Now ASI03.

**`http-rate-limit-absence` cited ASI08 (Supply Chain & Dependency Risk).** Missing rate-limit headers say nothing about dependencies. Unbounded call volume against an agent is a cascading-failure and availability concern. Now ASI06.

## Severity calibration

Severity reflects **exposure**, not confirmed impact — REAP never exploits anything, so it is never in a position to claim impact.

One check is deliberately conditional. `mcp-host-header-validation` was HIGH for every server that didn't validate `Host`, which is very nearly every server: anything behind an ingress, load balancer, or reverse proxy typically never sees the original header. A finding that fires on almost every target is a noise floor rather than a signal. It is now MEDIUM by default, and HIGH only for loopback targets, where a browser-driven rebinding attack reaches a local agent directly and the finding is genuinely actionable.
