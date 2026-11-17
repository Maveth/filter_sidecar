"""Versioned handshake between two sidecars.

One JSON object per line. proto must match. The catalog version is
advertised and does not have to match. A sidecar dials its Knots peers
at that peer's port plus 4, unless this node picked another offset, and keeps the listen address from a hello
so the other side can be dialed back.
"""
from __future__ import annotations

import builtins
import hashlib
import json
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import spamcore

def _stamp(*args, **kwargs):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    builtins.print(now, *args, **kwargs)

print = _stamp

PROTO = 1
CARRIES = ("spam", "whitelist")


def split_addr(addr: str) -> tuple[str, int] | None:
    text = addr.strip()
    if text.startswith("["):
        host, sep, port = text[1:].rpartition("]:")
        if not sep or not port.isdigit():
            return None
        return host, int(port)
    host, sep, port = text.rpartition(":")
    if not sep or not host or not port.isdigit():
        return None
    return host, int(port)


def running_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(Path(__file__).resolve().parent), "rev-parse", "--short=12", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def commit_time(commit: str) -> int:
    """Unix time of a local commit. Zero when git cannot read it."""
    if not commit:
        return 0
    try:
        raw = subprocess.check_output(
            ["git", "-C", str(Path(__file__).resolve().parent), "show", "-s", "--format=%ct", commit],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        return int(raw)
    except (OSError, subprocess.CalledProcessError, ValueError):
        return 0


def _read_varint(raw: bytes, off: int) -> tuple[int, int]:
    if off >= len(raw):
        raise ValueError("short")
    mark = raw[off]
    if mark < 0xfd:
        return mark, off + 1
    if mark == 0xfd and off + 3 <= len(raw):
        return int.from_bytes(raw[off + 1:off + 3], "little"), off + 3
    if mark == 0xfe and off + 5 <= len(raw):
        return int.from_bytes(raw[off + 1:off + 5], "little"), off + 5
    if off + 9 <= len(raw):
        return int.from_bytes(raw[off + 1:off + 9], "little"), off + 9
    raise ValueError("short")


def txid_of_hex(raw_hex: str) -> str:
    """Transaction id of a signed package transaction. Empty when the hex is not a transaction."""
    try:
        raw = bytes.fromhex(raw_hex.strip())
    except ValueError:
        return ""
    if len(raw) < 10:
        return ""
    try:
        if raw[4] == 0x00 and raw[5] == 0x01:
            off = 6
            vin, off = _read_varint(raw, off)
            in_start = 6
            for _ in range(vin):
                off += 36
                script_len, off = _read_varint(raw, off)
                off += script_len + 4
            in_end = off
            vout, off = _read_varint(raw, off)
            for _ in range(vout):
                off += 8
                script_len, off = _read_varint(raw, off)
                off += script_len
            out_end = off
            for _ in range(vin):
                stack, off = _read_varint(raw, off)
                for _ in range(stack):
                    item, off = _read_varint(raw, off)
                    off += item
            stripped = raw[:4] + raw[in_start:out_end] + raw[off:off + 4]
        else:
            stripped = raw
    except (ValueError, IndexError):
        return ""
    if len(stripped) < 10:
        return ""
    digest = hashlib.sha256(hashlib.sha256(stripped).digest()).digest()
    return digest[::-1].hex()


def package_id(shape_id: str, parent_hex: str, child_hex: str = "", extra: list[str] | tuple[str, ...] = ()) -> str:
    """Hash of one whitelist set. A second set is a different hash."""
    parts = [shape_id, parent_hex.strip().lower(), child_hex.strip().lower()]
    parts.extend(item.strip().lower() for item in extra)
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


def _hex_or_empty(value: str) -> bool:
    if value == "":
        return True
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def shareable_address(address: str) -> bool:
    """An announced address other sidecars can dial. Loopback and wildcards stay local."""
    parsed = split_addr(address)
    if parsed is None:
        return False
    host = parsed[0].lower()
    return host not in {"0.0.0.0", "127.0.0.1", "::", "::1"} and not host.startswith("127.")


def probe_is_due(last: float, now: float, interval: float = 3600) -> bool:
    """True when this Bitcoin peer has not been checked within the last hour."""
    return now - last >= interval


def hello_body(name: str, listen: str, catalog: int, carries: list[str], commit: str = "", known: list[str] | None = None) -> dict:
    body = {
        "op": "hello",
        "proto": PROTO,
        "catalog": catalog,
        "commit": commit or running_commit(),
        "carries": carries,
        "listen": listen,
        "name": name,
    }
    if known:
        body["known"] = known
    return body


def read_message(conn: socket.socket) -> dict | None:
    conn.settimeout(3)
    data = b""
    while b"\n" not in data and len(data) < 2_000_000:
        chunk = conn.recv(1024)
        if not chunk:
            break
        data += chunk
    line = data.split(b"\n", 1)[0]
    try:
        body = json.loads(line.decode())
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(body, dict):
        return None
    return body


def read_hello(conn: socket.socket) -> dict | None:
    body = read_message(conn)
    if body is None or body.get("op") != "hello":
        return None
    return body


def write_hello(conn: socket.socket, body: dict) -> None:
    conn.sendall((json.dumps(body) + "\n").encode())


class Directory:
    def __init__(self, name: str, listen: str, catalog: int, path: Path, carries: list[str] | None = None, announce: str = "", commit: str = "") -> None:
        self.name = name
        self.listen = listen
        self.announce = announce or listen
        self.commit = commit
        self._tried: dict[str, float] = {}
        self.packages: dict[str, dict] = {}
        self.marked_packages: set[str] = set()
        self.open_shapes: set[str] = set()
        self.have_ids: set[str] = set()
        self.pending_submit: list[str] = []
        self.submitted: set[str] = set()
        self.sent_items = 0
        self.catalog = catalog
        self.path = path
        self.carries = carries or list(CARRIES)
        self.catalog_shapes: list[dict] = []
        self.inbox_path: Path | None = None
        self.inbox: dict[str, dict] = {}
        self.peers: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        host, port = split_addr(listen) or ("127.0.0.1", 0)
        self._host = host
        self._port = port

    def start(self) -> None:
        self._load_saved_peers()
        self.publish()
        thread = threading.Thread(target=self._listen, name="sidecar-hello", daemon=True)
        thread.start()

    def _load_saved_peers(self) -> None:
        """Keep each peer's in and out across a restart. A new hello still adds to that set."""
        try:
            loaded = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError):
            return
        rows = loaded.get("peers") if isinstance(loaded, dict) else None
        if not isinstance(rows, list):
            return
        for row in rows:
            if not isinstance(row, dict):
                continue
            listen = str(row.get("address") or "")
            if not listen or listen == self.listen:
                continue
            directions = [str(item) for item in (row.get("directions") or []) if item]
            if not directions and row.get("direction"):
                directions = [str(row["direction"])]
            kept = dict(row)
            kept["directions"] = sorted(set(directions))
            self.peers[listen] = kept

    def stop(self) -> None:
        self._stop.set()

    def _listen(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self._host, self._port))
        server.listen(8)
        server.settimeout(1)
        print(f"hello listen {self.listen} proto={PROTO} catalog={self.catalog}", flush=True)
        try:
            while not self._stop.is_set():
                try:
                    conn, addr = server.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=self._incoming, args=(conn, addr), daemon=True).start()
        finally:
            server.close()

    def _incoming(self, conn: socket.socket, addr: tuple) -> None:
        try:
            remote = read_hello(conn)
            accept = bool(remote) and remote.get("proto") == PROTO
            reply = self._hello()
            reply["accept"] = accept
            if not accept:
                reply["reason"] = "proto" if remote else "malformed"
            write_hello(conn, reply)
            if accept and remote is not None:
                request = read_message(conn)
                asked = request.get("ids") if isinstance(request, dict) and request.get("op") == "get" else []
                items = self.data_for(asked, str(remote.get("name") or remote.get("listen") or ""))
                write_hello(conn, {"op": "data", "items": items})
                write_hello(conn, {"op": "get", "ids": self.wants(remote.get("inv") or [])})
                reply_data = read_message(conn)
                if isinstance(reply_data, dict) and reply_data.get("op") == "data":
                    self.take_data(remote, reply_data.get("items") or [])
                self.absorb_known(remote.get("known") or [])
                print(f"exchange in {remote.get('name') or addr[0]} asked={len(asked)} sent={len(items)}", flush=True)
                self.remember(remote, "in", f"{addr[0]}:{addr[1]}")
        except OSError as exc:
            print(f"hello in {addr[0]}: {exc}", flush=True)
        finally:
            conn.close()

    def dial(self, address: str, direction: str = "out", record_failure: bool = False) -> bool:
        parsed = split_addr(address)
        if parsed is None or address in {self.listen, self.announce}:
            return False
        host, port = parsed
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            conn.settimeout(0.5)
            conn.connect((host, port))
            conn.settimeout(3)
            write_hello(conn, self._hello())
            remote = read_hello(conn)
            if not remote or remote.get("accept") is not True or remote.get("proto") != PROTO:
                if record_failure or (remote and remote.get("proto") not in (None, PROTO)):
                    self.remember(remote or {"listen": address, "accept": False, "reason": "proto"}, direction, address)
                return False
            wanted = self.wants(remote.get("inv") or [])
            write_hello(conn, {"op": "get", "ids": wanted})
            incoming = read_message(conn)
            if isinstance(incoming, dict) and incoming.get("op") == "data":
                self.take_data(remote, incoming.get("items") or [])
            request = read_message(conn)
            asked = request.get("ids") if isinstance(request, dict) and request.get("op") == "get" else []
            items = self.data_for(asked, str(remote.get("name") or remote.get("listen") or address))
            write_hello(conn, {"op": "data", "items": items})
            self.absorb_known(remote.get("known") or [])
            print(f"exchange out {remote.get('name') or address} asked={len(wanted)} sent={len(items)}", flush=True)
        except OSError:
            if record_failure:
                self.remember({"listen": address, "accept": False, "reason": "unreachable"}, direction, address)
            return False
        finally:
            conn.close()
        self.remember(remote, direction, address)
        return True

    def remember(self, remote: dict, direction: str, fallback: str) -> None:
        listen = str(remote.get("listen") or fallback)
        if listen == self.listen:
            return
        row = {
            "address": listen,
            "direction": direction,
            "name": remote.get("name") or "",
            "proto": remote.get("proto"),
            "catalog": remote.get("catalog"),
            "commit": remote.get("commit") or "",
            "carries": remote.get("carries") or [],
            "accept": remote.get("accept") is True or remote.get("proto") == PROTO and direction == "in",
            "reason": remote.get("reason") or "",
            "when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        if direction == "in" and remote.get("proto") == PROTO:
            row["accept"] = True
        with self._lock:
            previous = self.peers.get(listen) or {}
            directions = set(previous.get("directions") or [])
            if previous.get("direction"):
                directions.add(previous["direction"])
            directions.add(direction)
            row["directions"] = sorted(directions)
            self.peers[listen] = row
            already_out = "out" in directions and previous.get("accept") is True and direction == "in"
        self.publish()
        if row["accept"] and direction == "in" and not already_out and split_addr(listen) is not None:
            threading.Thread(target=self.dial, args=(listen, "out"), daemon=True).start()
        if row["accept"] and not previous.get("accept") and shareable_address(listen):
            self._tell_others(listen)

    def set_identity(self, name: str, announce: str) -> None:
        """Use a saved name and published address on the next hello."""
        changed = False
        cleaned = name.strip()
        if cleaned and cleaned != self.name:
            self.name = cleaned[:40]
            changed = True
        if announce and shareable_address(announce) and announce != self.announce:
            self.announce = announce
            changed = True
        if changed:
            self.publish()

    def _hello(self) -> dict:
        body = hello_body(self.name, self.announce, self.catalog, self.carries, self.commit, self.known_addresses())
        body["inv"] = self.inv()
        return body

    def known_addresses(self) -> list[str]:
        found = []
        if shareable_address(self.announce):
            found.append(self.announce)
        with self._lock:
            for row in self.peers.values():
                address = str(row.get("address") or "")
                if row.get("accept") and shareable_address(address):
                    found.append(address)
        return list(dict.fromkeys(found))[:50]

    def absorb_known(self, addresses: list) -> None:
        for address in addresses:
            if isinstance(address, str):
                self.learn_address(address)

    def learn_address(self, address: str) -> None:
        if not shareable_address(address) or address in {self.listen, self.announce}:
            return
        now = time.time()
        with self._lock:
            if (self.peers.get(address) or {}).get("accept"):
                return
            if now - self._tried.get(address, 0) < 3600:
                return
            self._tried[address] = now
        threading.Thread(target=self.dial, args=(address, "out"), daemon=True).start()

    def _tell_others(self, arrived: str) -> None:
        with self._lock:
            others = [
                address for address, row in self.peers.items()
                if address != arrived and row.get("accept") and shareable_address(address)
            ]
        for address in others:
            threading.Thread(target=self.dial, args=(address, "out"), daemon=True).start()

    def set_open_shapes(self, shapes: set[str]) -> None:
        """Whitelist ids whose switch is on. Only those packages are offered."""
        self.open_shapes = {str(shape) for shape in shapes}

    def add_package(self, shape_id: str, parent_hex: str, child_hex: str = "", extra: list[str] | tuple[str, ...] = (), local: bool = False) -> str | None:
        parent_hex = parent_hex.strip().lower()
        child_hex = child_hex.strip().lower()
        extras = [item.strip().lower() for item in extra]
        if not shape_id or not parent_hex or not _hex_or_empty(parent_hex) or not _hex_or_empty(child_hex):
            return None
        if any(not item or not _hex_or_empty(item) for item in extras):
            return None
        digest = package_id(shape_id, parent_hex, child_hex, extras)
        if digest not in self.packages:
            self.packages[digest] = {
                "op": "package",
                "id": digest,
                "shape": shape_id,
                "parent": parent_hex,
                "child": child_hex,
                "extra": extras,
            }
            print(f"package {shape_id} {digest[:12]}", flush=True)
        if local:
            self.marked_packages.add(digest)
        self._fill_known_package(digest)
        return digest

    def _sendable(self, digest: str) -> bool:
        """A package goes out only when this node marked it and that whitelist is on."""
        package = self.packages.get(digest)
        if not package or digest not in self.marked_packages:
            return False
        return str(package.get("shape") or "") in self.open_shapes

    def inv(self) -> list[str]:
        found = []
        for shape in self.catalog_shapes:
            if isinstance(shape, dict) and shape.get("transfer") is not False and shape.get("id"):
                found.append(str(shape["id"]))
        found.extend(sorted(item for item in self.have_ids if not str(item).startswith("pkg:")))
        found.extend(f"pkg:{digest}" for digest in self.packages if self._sendable(digest))
        return list(dict.fromkeys(found))

    def _accepts_packages(self) -> bool:
        local_path = self.path.parent / "sift-local.json"
        try:
            local = json.loads(local_path.read_text())
        except (OSError, json.JSONDecodeError):
            return False
        return isinstance(local, dict) and local.get("accept_packages") is True

    def wants(self, their_inv: list) -> list[str]:
        have = set(self.inv())
        ask = []
        for item in their_inv:
            if not isinstance(item, str) or item in have or item in self.have_ids:
                continue
            if item.startswith("pkg:") and not self._accepts_packages():
                continue
            ask.append(item)
        return ask[:100]

    def data_for(self, ids: list, peer: str = "") -> list[dict]:
        items = []
        shapes = {str(shape.get("id")): shape for shape in self.catalog_shapes if isinstance(shape, dict)}
        for item_id in ids or []:
            if not isinstance(item_id, str):
                continue
            if item_id.startswith("pkg:"):
                digest = item_id[4:]
                package = self.packages.get(digest)
                if package and self._sendable(digest):
                    items.append(package)
                    self._note_package("out", digest, peer)
                continue
            shape = shapes.get(item_id)
            if shape and shape.get("transfer") is not False:
                row = spamcore.sanitize_shape(shape)
                row["enabled"] = False
                items.append(row)
        self.sent_items += len(items)
        return items

    def take_data(self, remote: dict, items: list) -> None:
        listen = str(remote.get("listen") or "")
        if not listen or listen == self.listen:
            return
        previous = self.inbox.get(listen) or {}
        kept = {}
        for row in (previous.get("shapes") or []) + (previous.get("whitelist") or []):
            if isinstance(row, dict) and row.get("enabled") is True:
                kept[row.get("id")] = True
        shapes = list(previous.get("shapes") or [])
        whitelist = list(previous.get("whitelist") or [])
        seen = {row.get("id") for row in shapes + whitelist if isinstance(row, dict)}
        for item in items:
            if not isinstance(item, dict):
                continue
            if item.get("op") == "package":
                shape_id = str(item.get("shape") or "")
                parent = str(item.get("parent") or "")
                child = str(item.get("child") or "")
                extra = [str(part) for part in item.get("extra") or []] if isinstance(item.get("extra"), list) else []
                if not self._accepts_packages():
                    continue
                if package_id(shape_id, parent, child, extra) != str(item.get("id") or ""):
                    print(f"package rejected hash {shape_id}", flush=True)
                    continue
                digest = self.add_package(shape_id, parent, child, extra)
                if digest:
                    self.have_ids.add(f"pkg:{digest}")
                    self._note_package("in", digest, str(remote.get("name") or listen))
                    if digest not in self.submitted and digest not in self.pending_submit:
                        self.pending_submit.append(digest)
                continue
            row = spamcore.sanitize_shape(item)
            if not row.get("id") or row["id"] in seen:
                continue
            row["enabled"] = bool(kept.get(row["id"]))
            self.have_ids.add(str(row["id"]))
            seen.add(row["id"])
            if row.get("kind") == "whitelist":
                whitelist.append(row)
            else:
                shapes.append(row)
        self.inbox[listen] = {
            "name": remote.get("name") or previous.get("name") or "",
            "catalog": self.catalog,
            "when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "shapes": shapes,
            "whitelist": whitelist,
        }
        self.publish_inbox()

    def offer_for(self, remote_carries: list) -> dict:
        wanted = set(remote_carries) or set(CARRIES)
        shapes = []
        whitelist = []
        for shape in self.catalog_shapes:
            if not isinstance(shape, dict) or shape.get("transfer") is False:
                continue
            row = spamcore.sanitize_shape(shape)
            row["enabled"] = False
            if row.get("carry") != "package":
                row.pop("parent", None)
                row.pop("child", None)
            if row.get("kind") == "whitelist" and "whitelist" in wanted:
                if row.get("carry") == "package":
                    row["parent"] = shape.get("parent") if isinstance(shape.get("parent"), str) else None
                    row["child"] = shape.get("child") if isinstance(shape.get("child"), str) else None
                whitelist.append(row)
            elif row.get("kind") in ("spam", "watch") and "spam" in wanted:
                shapes.append(row)
        return {"op": "offer", "catalog": self.catalog, "shapes": shapes, "whitelist": whitelist}

    def take_offer(self, remote: dict, offer: dict) -> None:
        if offer.get("op") != "offer":
            return
        listen = str(remote.get("listen") or "")
        if not listen or listen == self.listen:
            return
        previous = (self.inbox.get(listen) or {})
        kept = {}
        for row in (previous.get("shapes") or []) + (previous.get("whitelist") or []):
            if isinstance(row, dict) and row.get("enabled") is True:
                kept[row.get("id")] = True
        shapes = []
        whitelist = []
        for row in offer.get("shapes") or []:
            if isinstance(row, dict):
                row = dict(row)
                row["enabled"] = bool(kept.get(row.get("id")))
                shapes.append(row)
        accept_packages = True
        local_path = self.path.parent / "sift-local.json"
        try:
            local = json.loads(local_path.read_text())
            if isinstance(local, dict) and local.get("accept_packages") is False:
                accept_packages = False
        except (OSError, json.JSONDecodeError):
            accept_packages = False
        for row in offer.get("whitelist") or []:
            if isinstance(row, dict):
                row = dict(row)
                if not accept_packages and row.get("parent") and row.get("child"):
                    continue
                row["enabled"] = bool(kept.get(row.get("id")))
                whitelist.append(row)
        self.inbox[listen] = {
            "name": remote.get("name") or "",
            "catalog": offer.get("catalog"),
            "when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "shapes": shapes,
            "whitelist": whitelist,
        }
        packages = sum(1 for row in whitelist if row.get("parent") and row.get("child"))
        print(
            f"offer from {remote.get('name') or listen} shapes={len(shapes)} whitelist={len(whitelist)} packages={packages}",
            flush=True,
        )
        self.publish_inbox()

    def _traffic_path(self) -> Path:
        return self.path.with_suffix(".traffic.json")

    def _package_row(self, digest: str, peer: str) -> dict:
        package = self.packages.get(digest) or {}
        return {
            "id": digest,
            "shape": str(package.get("shape") or ""),
            "parent": txid_of_hex(str(package.get("parent") or "")),
            "child": txid_of_hex(str(package.get("child") or "")),
            "to": peer,
            "when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    def _write_traffic(self, loaded: dict) -> None:
        path = self._traffic_path()
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(loaded, indent=2) + "\n")
        tmp.replace(path)

    def _load_traffic(self) -> dict:
        try:
            loaded = json.loads(self._traffic_path().read_text())
        except (OSError, json.JSONDecodeError):
            return {}
        return loaded if isinstance(loaded, dict) else {}

    def _note_package(self, direction: str, digest: str, peer: str = "") -> None:
        detail_key = "sent" if direction == "out" else "received"
        with self._lock:
            loaded = self._load_traffic()
            rows = loaded.get(direction)
            if not isinstance(rows, list):
                rows = []
            if digest not in rows:
                rows.append(digest)
            loaded[direction] = rows
            details = loaded.get(detail_key)
            if not isinstance(details, list):
                details = []
            current = next((row for row in details if isinstance(row, dict) and row.get("id") == digest), None)
            fresh = self._package_row(digest, peer)
            if current is None:
                details.append(fresh)
            else:
                if peer and not current.get("to"):
                    current["to"] = peer
                if fresh["parent"] and not current.get("parent"):
                    current["parent"] = fresh["parent"]
                    current["child"] = fresh["child"]
                    current["shape"] = fresh["shape"] or current.get("shape") or ""
            loaded[detail_key] = details
            self._write_traffic(loaded)

    def _fill_known_package(self, digest: str) -> None:
        """A package already counted keeps its hash. Fill in the parent and child when we still have them."""
        with self._lock:
            loaded = self._load_traffic()
            changed = False
            for direction, key in (("out", "sent"), ("in", "received")):
                hashes = loaded.get(direction)
                if not isinstance(hashes, list) or digest not in hashes:
                    continue
                details = loaded.get(key)
                if not isinstance(details, list):
                    details = []
                current = next((row for row in details if isinstance(row, dict) and row.get("id") == digest), None)
                fresh = self._package_row(digest, "")
                if current is None:
                    details.append(fresh)
                    changed = True
                elif fresh["parent"] and not current.get("parent"):
                    current["parent"] = fresh["parent"]
                    current["child"] = fresh["child"]
                    current["shape"] = fresh["shape"] or current.get("shape") or ""
                    changed = True
                loaded[key] = details
            if changed:
                self._write_traffic(loaded)

    def publish_inbox(self) -> None:
        if self.inbox_path is None:
            return
        body = {"peers": self.inbox}
        tmp = self.inbox_path.with_suffix(self.inbox_path.suffix + ".tmp")
        tmp.write_text(json.dumps(body, indent=2) + "\n")
        tmp.replace(self.inbox_path)

    def publish(self) -> None:
        with self._lock:
            peers = list(self.peers.values())
        body = {
            "self": self._hello(),
            "peers": peers,
        }
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(body, indent=2) + "\n")
        tmp.replace(self.path)


def port_offset(value, default: int = 4) -> int:
    """Ports added to a Bitcoin peer port. 4 dials 8337 when the peer is on 8333."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    if number < 1 or number > 100:
        return default
    return number


def outbound_sidecar_addrs(peers: list[dict], offset: int = 4) -> list[str]:
    """Bitcoin peers we dialed, at their port plus the offset. Inbound ports are ephemeral."""
    step = port_offset(offset)
    found = []
    for peer in peers:
        if peer.get("inbound") is True:
            continue
        parsed = split_addr(str(peer.get("addr") or ""))
        if parsed is None:
            continue
        host, port = parsed
        found.append(f"{host}:{port + step}")
    return found
