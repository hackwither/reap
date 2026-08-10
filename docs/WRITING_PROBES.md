# Writing a probe template

Most new checks should be a JSON template, not new Go code. A template is one request plus one or more matchers.

## Minimal example

```json
{
  "id": "mcp-tmpl-my-check",
  "protocol": "mcp",
  "info": {
    "title": "Human-readable title shown in reports",
    "severity": "medium",
    "asi_refs": ["ASI02"],
    "description": "What this checks for and why it matters.",
    "remediation": "What the operator should do about it."
  },
  "request": {
    "method": "tools/list",
    "params": {},
    "no_auth": true
  },
  "matchers": [
    { "type": "json_path", "path": "result.tools", "min_count": 1 }
  ]
}
```

Drop the file anywhere under `templates/` (subdirectories are fine — `templates/mcp/` by convention, matching protocol) and it loads automatically.

## Fields

- **id** — stable, unique slug. Prefix with `mcp-tmpl-` (or `<protocol>-tmpl-`) by convention so built-in Go probe IDs (`mcp-*`) and template IDs never collide.
- **protocol** — which `Session` implementation this runs against. `"mcp"` today.
- **info.severity** — one of `info`, `low`, `medium`, `high`. Recon findings are exposure signals, not confirmed exploits — keep severities honest; most things are `low`/`medium`, not `high`.
- **info.asi_refs** — cite [OWASP ASI01–ASI10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) where genuinely applicable. Don't cite one just to look thorough.
- **info.references** — optional list of the underlying standards this check is judged against, e.g. `["RFC 6750 (Bearer Token Usage)"]`. Shown alongside the ASI code in reports so a reader can see *why* the check exists, not just that it fired.
- **request.no_auth** — if `true`, the request is sent with any configured `--auth-header` deliberately stripped, so you're explicitly testing the anonymous path.
- **match_logic** — `"any"` (default, OR) or `"all"` (AND) across the matchers list.

## Confidence and reproduction

Every finding carries a `confidence` ("high"/"medium"/"low") and, where possible, a reproducible `request` (the exact method/URL/headers/body that triggered it, rendered in reports as an evidence block plus a `curl` one-liner). For **template-defined checks this is automatic** — a template only fires when its matchers actually matched, so its findings are always `confidence: "high"`, and the request/response that matched is captured for you; you don't need to do anything extra.

If you're writing a **hand-written Go probe** instead (see below), set both explicitly on the `report.Finding` you build:

- `Confidence`: `"high"` for a direct protocol-level observation (a header that's actually present, a status code that actually came back), `"medium"` for a heuristic (keyword matching, naming-convention pattern matching, absence-of-evidence signals like a missing rate-limit header).
- `Request: &report.HTTPExchange{...}` populated from the `probe.RawResult` your probe already has in scope — `Method`, `URL`, `StatusCode`, `ContentType`, `BodySize`, and `Body` (the exact request body sent, if any — without it a `curl -X POST` repro can't actually reproduce a body-dependent match). Skip this field only when there genuinely isn't a single request/response the finding traces back to (e.g. a TLS-handshake-level observation, or a value like a session ID that was captured incidentally on an earlier, unrelated call).

Also note: **when a target hasn't confirmed the protocol being scanned** (e.g. an MCP `initialize` handshake that returned HTML instead of JSON-RPC), `Report.ApplyConfidenceDowngrade` overrides all of this uniformly — every finding's severity is capped at `info` and confidence forced to `"low"`, regardless of what an individual probe or template set. This is deliberate: a scanner firing MED findings against a plain web server because a handshake failed is the credibility failure this whole mechanism exists to prevent. See `internal/report/report.go`.

## Matcher types

| type | fields | checks |
|---|---|---|
| `status_code` | `equals` | response HTTP status equals N |
| `header` | `header`, plus one of `value` (exact) / `contains` (substring) / neither (presence only) | response header |
| `body_contains` | `any_of: [...]` | raw response body contains any of the given strings (case-insensitive) |
| `json_path` | `path`, plus one of `any_of: [...]` / `min_count` / neither (presence only) | walks the decoded JSON body |

`json_path` uses dotted segments; `*` means "iterate every element/value here and keep resolving the rest of the path against each." Examples:

- `result.tools` → the tools array itself
- `result.tools.*.name` → every tool's `name` field, flattened into one list
- `result.serverInfo.name` → a single nested string

## What templates can't do (on purpose)

- No chaining multiple requests in one template.
- No branching ("if X then check Y").
- No invoking a discovered tool.

If your check genuinely needs one of these, it's not a template — write a Go probe in `internal/probe/<protocol>/checks.go` instead, where the extra power is visible in reviewable code rather than hidden in a config file. See `docs/ARCHITECTURE.md` for why that boundary exists.

## Testing your template

```bash
reap -t https://your-test-target/mcp --authorized --include mcp-tmpl-my-check --output json
```

`--include` restricts the run to just your probe ID so you can iterate quickly without waiting on the full suite.
