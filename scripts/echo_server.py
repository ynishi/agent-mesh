#!/usr/bin/env python3
"""Minimal echo server for meshd local_agent testing."""
import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

class EchoHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}
        response = {"echo": body, "agent": sys.argv[2] if len(sys.argv) > 2 else "unknown"}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, fmt, *args):
        print(f"[{sys.argv[2] if len(sys.argv) > 2 else 'echo'}] {fmt % args}")

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9900
    print(f"Echo server on port {port}")
    HTTPServer(("127.0.0.1", port), EchoHandler).serve_forever()
