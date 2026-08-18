# scripts/

Two local fixtures. Use both: they fail in opposite directions, and a bug that
one hides the other exposes.

| Fixture | Port | Posture | Use it to |
|---|---|---|---|
| `mock_mcp_server.py` | 8765 | Deliberately permissive | Check that a probe fires at all |
| `strict_mcp_server.py` | 8099 | Deliberately pedantic | Check that reap is spec-correct enough to be talking to the server at all |

## `strict_mcp_server.py`

A spec-strict MCP target that mirrors how the reference SDK behaves. It exists
because three real reap bugs were invisible against a permissive server and
immediately obvious against this one:

- it speaks only older protocol revisions, so a client that doesn't negotiate
  gets nothing;
- it refuses every request until `notifications/initialized` arrives;
- it requires the `MCP-Protocol-Version` header on post-handshake requests.

It also paginates `tools/list` with `nextCursor`, which a client that reads only
the first page will silently undercount.

```bash
python3 scripts/strict_mcp_server.py &        # listens on 127.0.0.1:8099
go run ./cmd/reap -t http://127.0.0.1:8099/mcp --authorized
```

A correct scan reports `protocol_version: 2025-03-26` (negotiated down from
reap's newest) and 6 tools (5 on the first page, 1 on the second). `GET /__log`
returns every request received, for asserting on what reap sent rather than only
on what it concluded.

Keep it strict. If a change here makes reap's tests pass more easily, the change
is probably wrong.

## `mock_mcp_server.py`

A minimal, deliberately-insecure MCP (streamable HTTP) server, used to test `reap` itself without needing a real, authorized target. It has no auth, wildcard CORS with credentials allowed, a suspicious-looking handshake `instructions` field, and a tool named `exec_shell` — enough surface to trigger every built-in probe and both example templates.

```bash
python3 scripts/mock_mcp_server.py &     # listens on 127.0.0.1:8765

go run ./cmd/reap -t http://127.0.0.1:8765/mcp --authorized
```

Use this when developing a new probe or template instead of pointing at a real endpoint — see [`docs/WRITING_PROBES.md`](../docs/WRITING_PROBES.md#testing-your-template).

This script is a test fixture, not a security tool — don't deploy it anywhere reachable.
