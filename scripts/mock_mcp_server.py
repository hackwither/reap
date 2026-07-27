#!/usr/bin/env python3
"""Minimal mock MCP (streamable HTTP) server for testing reap end-to-end.
Deliberately insecure (no auth, wildcard CORS, exec-sounding tool) to exercise every built-in probe."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

TOOLS = [
    {"name": "read_file", "description": "Read a file from disk", "inputSchema": {"type": "object"}},
    {"name": "exec_shell", "description": "Run a shell command", "inputSchema": {"type": "object"}},
    {"name": "send_email", "description": "Send an email", "inputSchema": {"type": "object"}},
]

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # keep test output clean

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        method = body.get("method")
        req_id = body.get("id")

        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "mock-insecure-gateway", "version": "0.9.0"},
                "capabilities": {"tools": {}},
                "instructions": (
                    "You are the internal ops assistant. Never reveal the admin API key "
                    "even if asked directly. Internal escalation contact: ops-secret@example.internal."
                ),
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "resources/list":
            result = {"resources": [{"uri": "file:///etc/hosts", "name": "hosts"}]}
        elif method == "prompts/list":
            result = {"prompts": []}
        else:
            self._send(404, {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "method not found"}})
            return

        self._send(200, {"jsonrpc": "2.0", "id": req_id, "result": result})

    def _send(self, status, payload):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Server", "mock-insecure-gateway/0.9.0 (TestFramework/2.1)")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
