#!/usr/bin/env python3
"""strict_mcp_server.py — a spec-strict MCP (streamable HTTP) target.

Where mock_mcp_server.py is deliberately permissive so every probe fires, this
one is deliberately *pedantic*, mirroring how the reference MCP SDK behaves. It
exists because three real reap bugs were invisible against a lenient server and
obvious against this one:

  1. reap sent a single hardcoded protocolVersion. This server speaks only
     older revisions, so a client that doesn't negotiate gets nothing — and
     reap used to report the target as clean rather than unreachable.
  2. reap never sent notifications/initialized. This server refuses every
     request until it arrives, as the spec requires.
  3. reap never sent the MCP-Protocol-Version header. This server requires it
     on all post-handshake requests, per MCP 2025-06-18.

It also paginates tools/list with nextCursor, which reap used to ignore while
presenting the first page as a complete inventory.

Keep it strict. If a change here makes reap's tests pass more easily, the change
is probably wrong.

Usage:
    python3 scripts/strict_mcp_server.py [--port 8099]
    reap -t http://127.0.0.1:8099/mcp --authorized

GET /__log returns every request received, for asserting on what reap sent
rather than only on what it concluded.
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Deliberately excludes reap's newest supported revision, so a scan only
# succeeds if the version ladder is walked.
SUPPORTED_VERSIONS = ("2025-03-26", "2024-11-05")

PAGE_ONE = [
    {"name": f"page1_tool_{i}", "description": "first page", "inputSchema": {"type": "object"}}
    for i in range(5)
]
PAGE_TWO = [
    {"name": "exec_shell", "description": "Run a shell command", "inputSchema": {"type": "object"}}
]

STATE = {"initialized": False}
LOG = []


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # keep test output clean

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            body = {}

        method = body.get("method")
        req_id = body.get("id")
        params = body.get("params") or {}

        LOG.append({
            "method": method,
            "has_id": "id" in body,
            "protocol_version_param": params.get("protocolVersion"),
            "protocol_version_header": self.headers.get("MCP-Protocol-Version"),
            "user_agent": self.headers.get("User-Agent"),
            "cursor": params.get("cursor"),
        })

        if method == "initialize":
            self._handle_initialize(req_id, params)
            return

        if method == "notifications/initialized":
            STATE["initialized"] = True
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        # Spec: the client MUST send notifications/initialized before issuing
        # any other request.
        if not STATE["initialized"]:
            self._rpc_error(400, req_id, -32602, "Received request before initialization was complete")
            return

        # Spec (2025-06-18): every post-handshake HTTP request carries the
        # negotiated protocol version.
        if not self.headers.get("MCP-Protocol-Version"):
            self._rpc_error(400, req_id, -32602, "Missing MCP-Protocol-Version header")
            return

        if method == "tools/list":
            self._handle_tools_list(req_id, params)
            return
        if method == "resources/list":
            self._rpc_result(req_id, {"resources": []})
            return
        if method == "prompts/list":
            self._rpc_result(req_id, {"prompts": []})
            return

        self._rpc_error(404, req_id, -32601, "method not found")

    def _handle_initialize(self, req_id, params):
        requested = params.get("protocolVersion")
        if requested not in SUPPORTED_VERSIONS:
            self._rpc_error(
                400, req_id, -32602,
                f"Unsupported protocol version: {requested}. Supported: {list(SUPPORTED_VERSIONS)}",
            )
            return
        self._rpc_result(
            req_id,
            {
                "protocolVersion": requested,
                "serverInfo": {"name": "strict-mcp-server", "version": "1.0.0"},
                "capabilities": {"tools": {"listChanged": True}},
            },
            headers={"Mcp-Session-Id": "9f2c4d8e1a7b3f5c9e2d4a8b6c1f3e5d"},
        )

    def _handle_tools_list(self, req_id, params):
        if params.get("cursor") is None:
            self._rpc_result(req_id, {"tools": PAGE_ONE, "nextCursor": "page-2"})
            return
        self._rpc_result(req_id, {"tools": PAGE_TWO})

    def do_GET(self):
        if self.path == "/__log":
            self._json(200, LOG)
            return
        self._json(404, {"error": "not found"})

    def _rpc_result(self, req_id, result, headers=None):
        self._json(200, {"jsonrpc": "2.0", "id": req_id, "result": result}, headers)

    def _rpc_error(self, status, req_id, code, message):
        self._json(status, {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})

    def _json(self, status, payload, headers=None):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8099)
    args = parser.parse_args()
    print(f"strict-mcp-server on :{args.port} (supports {', '.join(SUPPORTED_VERSIONS)})")
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
