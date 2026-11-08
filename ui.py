#!/usr/bin/env python3
"""Local settings page for one sidecar rules file.

Binds to localhost only. Saving rewrites that rules file. It does not write
bitcoin.conf and it does not restart Knots.
"""
from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import settings as ruleset

HERE = Path(__file__).resolve().parent
PAGE = (HERE / "ui.html").read_text()
HOST = "127.0.0.1"
PORT = 8092


def meta(path: Path, rules: dict) -> dict:
    whitelist = rules.get("whitelist_ark_zero_anchor") is True
    return {
        "path": str(path),
        "fields": list(ruleset.RULE_FIELDS),
        "rules": rules,
        "knots": ruleset.knots_notice(True),
        "whitelist_on": whitelist,
    }


class Handler(BaseHTTPRequestHandler):
    rules_path: Path

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.address_string()} {fmt % args}", flush=True)

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: dict) -> None:
        self._send(code, json.dumps(payload).encode(), "application/json")

    def do_GET(self) -> None:
        if self.path == "/":
            self._send(200, PAGE.encode(), "text/html; charset=utf-8")
            return
        if self.path == "/api/meta":
            rules = json.loads(self.rules_path.read_text())
            self._json(200, meta(self.rules_path, rules))
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/api/rules":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("content-length") or "0")
        if length > 100_000:
            self._json(413, {"error": "rules file is too large"})
            return
        try:
            incoming = json.loads(self.rfile.read(length) or b"{}")
            previous = json.loads(self.rules_path.read_text())
            rules = ruleset.normalize_rules(incoming, previous)
        except (json.JSONDecodeError, ValueError) as exc:
            self._json(400, {"error": str(exc)})
            return
        text = json.dumps(rules, indent=2) + "\n"
        tmp = self.rules_path.with_suffix(self.rules_path.suffix + ".tmp")
        tmp.write_text(text)
        tmp.replace(self.rules_path)
        notice = ruleset.knots_notice(rules.get("whitelist_ark_zero_anchor") is True)
        self._json(200, {"rules": rules, "notice": notice})


def serve(path: Path, port: int = PORT) -> None:
    if not path.is_file():
        raise SystemExit(f"rules file not found: {path}")
    Handler.rules_path = path
    server = ThreadingHTTPServer((HOST, port), Handler)
    print(f"settings http://{HOST}:{port}/  rules {path}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else HERE / "rules.json")
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    serve(path, port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
