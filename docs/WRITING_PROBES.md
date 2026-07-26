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
- **request.no_auth** — if `true`, the request is sent with any configured `--auth-header` deliberately stripped, so you're explicitly testing the anonymous path.
- **match_logic** — `"any"` (default, OR) or `"all"` (AND) across the matchers list.

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
agentrecon -t https://your-test-target/mcp --authorized --include mcp-tmpl-my-check --output json
```

`--include` restricts the run to just your probe ID so you can iterate quickly without waiting on the full suite.
