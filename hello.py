"""Versioned handshake between two sidecars.

One JSON object per line. proto must match. The catalog version is
advertised and does not have to match. A sidecar dials its Knots peers
at that peer's port plus 4, unless this node picked another offset, and keeps the listen address from a hello
so the other side can be dialed back.
"""
from __future__ import annotations

import builtins
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
            ["git", "-C", str(Path(__file__).resolve().parent), "rev-parse", "--short", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


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
        self.publish()
        thread = threading.Thread(target=self._listen, name="sidecar-hello", daemon=True)
        thread.start()

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
                offer = read_message(conn)
                write_hello(conn, self.offer_for(remote.get("carries") or []))
                if offer is not None:
                    self.take_offer(remote, offer)
                self.absorb_known(remote.get("known") or [])
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
            write_hello(conn, self.offer_for(remote.get("carries") or []))
            offer = read_message(conn)
            if offer is not None:
                self.take_offer(remote, offer)
            self.absorb_known(remote.get("known") or [])
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

    def _hello(self) -> dict:
        return hello_body(self.name, self.announce, self.catalog, self.carries, self.commit, self.known_addresses())

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
