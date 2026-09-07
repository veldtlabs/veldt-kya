"""A stand-in for the tool your agents actually call.

Records every request it receives so the examples can show what was
executed rather than only what was allowed.
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

EXECUTED = "executed.jsonl"


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        with open(EXECUTED, "ab") as fh:
            fh.write(body + b"\n")
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "result": "executed"})
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(payload.encode())

    def log_message(self, *_a):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 9099), _Handler).serve_forever()
