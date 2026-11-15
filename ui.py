#!/usr/bin/env python3
"""Local settings page for one sidecar rules file.

Binds to localhost only. Saving rewrites that rules file. It does not write
bitcoin.conf and it does not restart Knots.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import board
import hello
import settings as ruleset
import spamcore

HERE = Path(__file__).resolve().parent
SHAPES_URL = "https://raw.githubusercontent.com/Maveth/filter_sidecar/main/shapes"
PAGE = (HERE / "ui.html").read_text()
BOARD = (HERE / "board.html").read_text()
HOST = "192.168.1.195"
PORT = 8093


def _private_catalog() -> tuple[Path, dict]:
    path = HERE / "shapes.local.json"
    if path.is_file():
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            data = {"version": 1, "shapes": []}
    else:
        data = {"version": 1, "shapes": []}
    if not isinstance(data, dict):
        data = {"version": 1, "shapes": []}
    data.setdefault("shapes", [])
    return path, data


def import_private_shape(shape: dict) -> dict:
    if not isinstance(shape, dict):
        raise ValueError("shape must be a JSON object")
    shape_id = str(shape.get("id") or "").strip()
    if not shape_id.replace("-", "").isalnum() or shape_id != shape_id.lower():
        raise ValueError("id must be lowercase letters, numbers, and dashes")
    if shape.get("kind") not in ("spam", "whitelist"):
        raise ValueError("kind must be spam or whitelist")
    title = str(shape.get("title") or "").strip()
    if not title:
        raise ValueError("title is required")
    public = json.loads((HERE / "shapes.json").read_text())
    if any(row.get("id") == shape_id for row in public.get("shapes") or []):
        raise ValueError("that id is already in the shared catalog")
    row = {
        "id": shape_id,
        "kind": shape.get("kind"),
        "carry": "definition",
        "title": title,
        "from": "local",
        "checker": None,
        "schema": shape.get("schema") if isinstance(shape.get("schema"), dict) else {},
        "note": str(shape.get("note") or ""),
        "transfer": False,
    }
    path, catalog = _private_catalog()
    catalog["shapes"] = [item for item in catalog["shapes"] if item.get("id") != shape_id] + [row]
    path.write_text(json.dumps(catalog, indent=2) + "\n")
    return {"summary": f"Imported {shape_id}. It is not sent to peers. Restart the marker to load it."}


def shape_pull_request(shape_id: str) -> dict:
    path, catalog = _private_catalog()
    shape = next((row for row in catalog.get("shapes") or [] if row.get("id") == shape_id), None)
    if shape is None:
        raise ValueError("import the shape on this node first")
    public = {key: value for key, value in shape.items() if key != "transfer"}
    public["from"] = "ours"
    folder = HERE / "shapes"
    folder.mkdir(exist_ok=True)
    (folder / f"{shape_id}.json").write_text(json.dumps(public, indent=2) + "\n")
    index_path = folder / "index.json"
    try:
        index = json.loads(index_path.read_text())
    except (OSError, json.JSONDecodeError):
        index = {"version": 1, "ids": []}
    if shape_id not in index.get("ids", []):
        index.setdefault("ids", []).append(shape_id)
        index_path.write_text(json.dumps(index, indent=2) + "\n")
    return {
        "summary": (
            f"Wrote shapes/{shape_id}.json for a pull request to Maveth/filter_sidecar. "
            "The request was not opened from here. "
            "The shape stays off the peer offer until that pull request is merged and downloaded."
        )
    }


def sync_shapes() -> dict:
    """Download shape files that this catalog does not have yet."""
    catalog_path = HERE / "shapes.json"
    catalog = json.loads(catalog_path.read_text())
    have = {row.get("id") for row in catalog.get("shapes") or [] if isinstance(row, dict)}
    try:
        with urllib.request.urlopen(SHAPES_URL + "/index.json", timeout=15) as resp:
            index = json.loads(resp.read().decode())
    except Exception as exc:
        return {"error": f"The shape repo is not reachable ({exc}). Local files are in shapes/."}
    remote_ids = [item for item in (index.get("ids") or []) if isinstance(item, str)]
    added = []
    for shape_id in remote_ids:
        if shape_id in have:
            continue
        try:
            with urllib.request.urlopen(f"{SHAPES_URL}/{shape_id}.json", timeout=15) as resp:
                shape = json.loads(resp.read().decode())
        except Exception as exc:
            return {"error": f"Could not download {shape_id}: {exc}", "added": added}
        if not isinstance(shape, dict) or shape.get("id") != shape_id:
            continue
        shape = spamcore.sanitize_shape(shape)
        if shape.get("id") != shape_id:
            continue
        catalog.setdefault("shapes", []).append(shape)
        (HERE / "shapes" / f"{shape_id}.json").write_text(json.dumps(shape, indent=2) + "\n")
        added.append(shape_id)
        have.add(shape_id)
    if added:
        catalog_path.write_text(json.dumps(catalog, indent=2) + "\n")
    summary = f"Remote {len(remote_ids)}. Local {len(have)}. Added {len(added)}."
    if added:
        summary += " " + ", ".join(added) + ". Restart the marker to load them. They stay off."
    else:
        summary += " No new shapes."
    return {"summary": summary, "added": added}


_github_main = {"at": 0.0, "sha": ""}


def github_main_commit() -> str:
    """Short hash of filter_sidecar main. Empty when GitHub does not answer."""
    now = time.time()
    if _github_main["sha"] and now - _github_main["at"] < 300:
        return _github_main["sha"]
    try:
        req = urllib.request.Request(
            "https://api.github.com/repos/Maveth/filter_sidecar/commits/main",
            headers={"accept": "application/vnd.github+json", "user-agent": "sift"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
        sha = str(data.get("sha") or "")
    except (OSError, ValueError, json.JSONDecodeError):
        return _github_main["sha"]
    short = sha[:12]
    _github_main["sha"] = short
    _github_main["at"] = now
    return short


def version_view() -> dict:
    local = hello.running_commit()
    remote = github_main_commit()
    same = bool(local and remote and (remote.startswith(local) or local.startswith(remote)))
    return {"commit": local, "github": remote, "same": same}


def tail_view(log_path: Path) -> dict:
    def last_lines(path: Path, count: int) -> str:
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            return ""
        return "\n".join(lines[-count:])

    inbox_path = log_path.with_suffix(".inbox.json")
    summary = []
    try:
        inbox = json.loads(inbox_path.read_text())
    except (OSError, json.JSONDecodeError):
        inbox = {}
    for listen, row in (inbox.get("peers") or {}).items():
        if not isinstance(row, dict):
            continue
        whitelist = [item.get("id") for item in row.get("whitelist") or [] if isinstance(item, dict)]
        summary.append(
            f"{row.get('name') or listen}  {row.get('when') or ''}  "
            f"spam {len(row.get('shapes') or [])}  whitelist {len(whitelist)}  "
            + ", ".join(str(item) for item in whitelist)
        )
    from datetime import datetime, timezone
    return {
        "when": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "log": last_lines(log_path, 15),
        "inbox": "\n".join(summary),
        "node_conf": board.current_node_conf(log_path),
    }


def meta(path: Path, rules: dict) -> dict:
    whitelist = rules.get("whitelist_ark_zero_anchor") is True
    return {
        "path": str(path),
        "fields": list(ruleset.RULE_FIELDS),
        "rules": rules,
        "knots": ruleset.knots_notice(True),
        "whitelist_on": whitelist,
        "conf": ruleset.bitcoin_conf_lines(rules),
    }


class Handler(BaseHTTPRequestHandler):
    rules_path: Path
    shapes_path: Path = HERE / "shapes.json"
    log_path: Path = HERE / "sidecar.log"
    sent_path: Path = HERE / "whitelist-sent.json"

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
            self._send(200, BOARD.encode(), "text/html; charset=utf-8")
            return
        if self.path == "/settings":
            self._send(200, PAGE.encode(), "text/html; charset=utf-8")
            return
        if self.path == "/api/meta":
            rules = json.loads(self.rules_path.read_text())
            self._json(200, meta(self.rules_path, rules))
            return
        if self.path == "/api/board":
            rules = json.loads(self.rules_path.read_text())
            self._json(200, board.view(self.shapes_path, rules, self.log_path, self.sent_path))
            return
        if self.path == "/api/local":
            self._json(200, board.read_local())
            return
        if self.path == "/api/tail":
            self._json(200, tail_view(self.log_path))
            return
        if self.path == "/api/version":
            self._json(200, version_view())
            return
        self._json(404, {"error": "not found"})

    def _read_json(self) -> dict:
        length = int(self.headers.get("content-length") or "0")
        if length > 100_000:
            raise ValueError("rules file is too large")
        incoming = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(incoming, dict):
            raise ValueError("body must be a JSON object")
        return incoming

    def _write_rules_to(self, path: Path, payload) -> None:
        text = json.dumps(payload, indent=2) + "\n"
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(text)
        tmp.replace(path)

    def _write_rules(self, rules: dict) -> None:
        self._write_rules_to(self.rules_path, rules)

    def do_POST(self) -> None:
        if self.path not in {"/api/rules", "/api/shape", "/api/test", "/api/local", "/api/peers", "/api/shapes", "/api/shapes/import", "/api/shapes/pr"}:
            self._json(404, {"error": "not found"})
            return
        try:
            incoming = self._read_json()
            previous = json.loads(self.rules_path.read_text())
            if self.path == "/api/shapes":
                self._json(200, sync_shapes())
                return
            if self.path == "/api/shapes/import":
                self._json(200, import_private_shape(incoming))
                return
            if self.path == "/api/shapes/pr":
                self._json(200, shape_pull_request(str(incoming.get("id") or "")))
                return
            if self.path == "/api/local":
                current = board.read_local()
                for key in ("search_port_plus_2", "accept_packages", "import_received"):
                    if isinstance(incoming.get(key), bool):
                        current[key] = incoming[key]
                if incoming.get("search_now") is True:
                    current["search_now"] = True
                path = board._base() / "sift-local.json"
                self._write_rules_to(path, current)
                self._json(200, current)
                return
            if self.path == "/api/peers":
                op = str(incoming.get("op") or "")
                path = board._base() / ("sidecar-seed.manual.json" if "seed" in self.log_path.name else "sidecar.manual.json")
                rows = board.manual_peers(self.log_path)
                if op == "add":
                    address = board.clean_address(str(incoming.get("address") or ""))
                    if address not in rows:
                        rows.append(address)
                elif op == "delete":
                    address = board.clean_address(str(incoming.get("address") or ""))
                    rows = [item for item in rows if item != address]
                elif op == "search":
                    current = board.read_local()
                    current["search_now"] = True
                    self._write_rules_to(board._base() / "sift-local.json", current)
                    self._json(200, {"ok": True})
                    return
                else:
                    raise ValueError("unknown peer action")
                self._write_rules_to(path, rows)
                self._json(200, {"peers": rows})
                return
            if self.path == "/api/test":
                sat = incoming.get("sat_vb")
                sliders = incoming.get("sliders") if isinstance(incoming.get("sliders"), dict) else None
                result = board.preview_mempool(
                    self.log_path, previous, str(incoming.get("id") or ""),
                    None if sat is None else float(sat),
                    sliders,
                )
                self._json(200, result)
                return
            if self.path == "/api/shape":
                node = board.load_node_policy(self.log_path)
                incoming = board.change_shape(previous, str(incoming.get("id") or ""), incoming, node)
            rules = ruleset.normalize_rules(incoming, previous)
        except (json.JSONDecodeError, ValueError) as exc:
            code = 413 if "too large" in str(exc) else 400
            self._json(code, {"error": str(exc)})
            return
        self._write_rules(rules)
        notice = ruleset.knots_notice(rules.get("whitelist_ark_zero_anchor") is True)
        self._json(200, {"rules": rules, "notice": notice})


def serve(path: Path, port: int = PORT, log_path: Path | None = None) -> None:
    if not path.is_file():
        raise SystemExit(f"rules file not found: {path}")
    Handler.rules_path = path
    Handler.shapes_path = HERE / "shapes.json"
    if log_path is not None:
        Handler.log_path = log_path
        if "seed" in log_path.name and (HERE / "shapes.seed.json").is_file():
            Handler.shapes_path = HERE / "shapes.seed.json"
    server = ThreadingHTTPServer((HOST, port), Handler)
    print(f"sidecar view http://{HOST}:{port}/  settings /settings  rules {path} log {Handler.log_path}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else HERE / "rules.json")
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    log_path = Path(sys.argv[3]) if len(sys.argv) > 3 else None
    serve(path, port, log_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
