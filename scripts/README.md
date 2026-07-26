# scripts/

## `mock_mcp_server.py`

A minimal, deliberately-insecure MCP (streamable HTTP) server, used to test `agentrecon` itself without needing a real, authorized target. It has no auth, wildcard CORS with credentials allowed, a suspicious-looking handshake `instructions` field, and a tool named `exec_shell` — enough surface to trigger every built-in probe and both example templates.

```bash
python3 scripts/mock_mcp_server.py &     # listens on 127.0.0.1:8765

go run ./cmd/agentrecon -t http://127.0.0.1:8765/mcp --authorized
```

Use this when developing a new probe or template instead of pointing at a real endpoint — see [`docs/WRITING_PROBES.md`](../docs/WRITING_PROBES.md#testing-your-template).

This script is a test fixture, not a security tool — don't deploy it anywhere reachable.
