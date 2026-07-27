# Security & Responsible Use

## Authorized use only

`reap` is an active reconnaissance tool: it sends real requests to a real endpoint. Running it against a target you don't own and don't have explicit, documented permission to test is unauthorized access in most jurisdictions, regardless of whether every individual request is "just a read."

Before scanning anything:

- Get written authorization (a pentest SOW, a bug bounty program's published scope, or your own infrastructure).
- Use `--authorized` only once you can truthfully make that claim.
- Respect published bug bounty scope and rules of engagement exactly "MCP endpoint discovered via recon" is not automatically in scope just because it responds.

## What the tool will not do

By design, `reap`:

- Never invokes a tool discovered on the target (no `tools/call`) enumeration only.
- Never attempts credential brute-forcing, injection payloads, or auth bypass beyond "does this listing method respond without an Authorization header."
- Defaults to a single request per probe; it is not built as a load-testing or rate-limit-exhaustion tool.
- Ships a plugin format (JSON templates) that is deliberately not Turing-complete — one request, a fixed set of matcher types specifically so a template can't smuggle in exploitation logic. See `docs/ARCHITECTURE.md`.

If you find a way for a template or probe to do something beyond read-only enumeration, that's a bug in this project — please report it (see below), not a feature request.

## Reporting a vulnerability in reap itself

Please report security issues in the tool (not findings from *using* the tool against a target) privately rather than as a public GitHub issue. Open a GitHub security advisory on this repository, or email the address listed in the repository's GitHub profile. We'll acknowledge within 72 hours.

## Reporting findings from using this tool

If `reap` surfaces a real exposure on a system you were authorized to test but don't own outright (e.g. a vendor's product), follow coordinated disclosure norms: report to the vendor/operator first, give them reasonable time to remediate, and only publish after a fix or an agreed disclosure timeline.
