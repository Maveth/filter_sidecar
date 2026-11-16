#!/usr/bin/env python3
"""Mark spam in one node's mempool and leave the mark there.

The gateway never connects to this program. Knots builds the only template.
One node, one policy. dry_run stays on until a config turns it off.
"""
from __future__ import annotations

import json
import sys
import threading
import time
import urllib.request
from pathlib import Path

import board
from hello import Directory, outbound_sidecar_addrs
from datetime import datetime, timezone
import builtins

def _stamp(*args, **kwargs):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    builtins.print(now, *args, **kwargs)

print = _stamp

from spamcore import package_from_entry, prevout_scripts, single_opreturn, tx_is_ark_whitelist, whitelist_items, tx_reject_reason

# Larger than a block of fees, so a child cannot pay a marked parent back in.
# Satoshis. Knots adds this to the fee it uses for mining selection only.
DEFAULT_DELTA = -1_000_000_000_000_000
HERE = Path(__file__).resolve().parent


def load_json(path: Path) -> dict:
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"{path} must be a JSON object")
    return data


class Node:
    def __init__(self, cfg: dict) -> None:
        self.url = str(cfg.get("rpc_url") or "").rstrip("/")
        cookie = str(cfg.get("cookie_file") or "")
        user = str(cfg.get("rpc_user") or "")
        password = str(cfg.get("rpc_password") or "")
        if cookie:
            pair = Path(cookie).read_text().strip()
            user, _, password = pair.partition(":")
        self._auth = None
        if user or password:
            import base64
            token = base64.b64encode(f"{user}:{password}".encode()).decode()
            self._auth = f"Basic {token}"

    def call(self, method: str, params: list):
        if not self.url:
            raise RuntimeError("rpc_url is empty")
        body = json.dumps({"jsonrpc": "1.0", "id": "sidecar", "method": method, "params": params}).encode()
        req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json"})
        if self._auth:
            req.add_header("Authorization", self._auth)
        with urllib.request.urlopen(req, timeout=60) as resp:
            payload = json.loads(resp.read().decode())
        if payload.get("error"):
            raise RuntimeError(f"{method}: {payload['error']}")
        return payload.get("result")

    def batch(self, calls: list[tuple[str, list]], timeout: int = 120) -> list:
        """One HTTP request, many RPC calls. A failed call comes back as None."""
        if not self.url:
            raise RuntimeError("rpc_url is empty")
        body = json.dumps([
            {"jsonrpc": "1.0", "id": i, "method": method, "params": params}
            for i, (method, params) in enumerate(calls)
        ]).encode()
        req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json"})
        if self._auth:
            req.add_header("Authorization", self._auth)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode())
        if isinstance(payload, dict):
            if payload.get("error"):
                raise RuntimeError(str(payload["error"]))
            payload = [payload]
        by_id = {item.get("id"): item for item in payload if isinstance(item, dict)}
        out = []
        for i in range(len(calls)):
            item = by_id.get(i) or {}
            out.append(None if item.get("error") else item.get("result"))
        return out


def rules_stamp(path: Path) -> tuple[int, int]:
    st = path.stat()
    return st.st_mtime_ns, st.st_size


def mark(node: Node, txid: str, delta: int, reason: str, dry_run: bool) -> None:
    if dry_run:
        print(f"would mark {txid} {reason} delta={delta}", flush=True)
        return
    node.call("prioritisetransaction", [txid, 0, int(delta)])
    print(f"marked {txid} {reason} delta={delta}", flush=True)


def unmark(node: Node, txid: str, delta: int, dry_run: bool) -> None:
    """Knots adds each fee delta. The opposite delta removes a mark."""
    if dry_run:
        print(f"would unmark {txid} delta={-delta}", flush=True)
        return
    node.call("prioritisetransaction", [txid, 0, int(-delta)])
    print(f"unmarked {txid} delta={-delta}", flush=True)


def fee_delta_sat(entry: dict) -> int:
    fees = entry.get("fees") or {}
    base = fees.get("base")
    modified = fees.get("modified")
    if base is None or modified is None:
        return 0
    return int(round((float(modified) - float(base)) * 100_000_000))


def already_marked(entry: dict, delta: int) -> bool:
    return fee_delta_sat(entry) <= delta // 2


def wanted_marks(reasons: dict[str, str | None], children: dict[str, list[str]]) -> dict[str, str]:
    """txid -> reason. A child of a marked tx is marked even with no reason of its own."""
    want: dict[str, str] = {}
    for txid, reason in reasons.items():
        if reason:
            want[txid] = reason
    for txid, reason in list(want.items()):
        if reason.startswith("child of "):
            continue
        for child in children.get(txid) or []:
            if child not in want:
                want[child] = f"child of {reason}"
    return want


def scan(
    node: Node,
    flags: dict,
    delta: int,
    dry_run: bool,
    decided: dict[str, str | None],
    marked: dict[str, str],
    whitelist_ids: set[str],
    one_ids: set[str],
    two_ids: set[str],
    rescan: bool,
) -> dict[str, int]:
    txids = node.call("getrawmempool", [False]) or []
    live = set(txids)
    if rescan:
        decided.clear()
    for gone in [txid for txid in list(decided) if txid not in live]:
        decided.pop(gone, None)
    for gone in [txid for txid in list(whitelist_ids) if txid not in live]:
        whitelist_ids.discard(gone)
    for gone in [txid for txid in list(one_ids) if txid not in live]:
        one_ids.discard(gone)
    for gone in [txid for txid in list(two_ids) if txid not in live]:
        two_ids.discard(gone)
    reasons: dict[str, str | None] = {}
    parents: dict[str, str | None] = {}
    want_parents = flags.get("whitelist_lightning_anchor_sweep") is True or flags.get("whitelist_p2a_sweep") is True

    def parent_hex(txid: str) -> str | None:
        if txid not in parents:
            got = node.call("getrawtransaction", [txid])
            parents[txid] = got if isinstance(got, str) else None
        return parents[txid]

    for txid in txids:
        if txid in decided and not rescan:
            reasons[txid] = decided[txid]
            continue
        try:
            entry = node.call("getmempoolentry", [txid]) or {}
            raw_hex = node.call("getrawtransaction", [txid])
            if not isinstance(raw_hex, str):
                continue
            fees = (entry.get("fees") or {}).get("base")
            fee_sat = int(round(float(fees) * 100_000_000)) if fees is not None else None
            weight = entry.get("weight")
            sigops = entry.get("sigops")
            raw = bytes.fromhex(raw_hex)
            package_fee, package_vsize = package_from_entry(entry)
            prevouts = prevout_scripts(raw, parent_hex) if want_parents and single_opreturn(raw) else None
            reason = tx_reject_reason(
                raw, flags, fee=fee_sat,
                weight=int(weight) if isinstance(weight, int) else None,
                sigops=int(sigops) if isinstance(sigops, int) else None,
                package_fee_sat=package_fee, package_vsize=package_vsize,
                prevouts=prevouts,
            )
            if tx_is_ark_whitelist(raw, flags, fee_sat):
                whitelist_ids.add(txid)
            else:
                whitelist_ids.discard(txid)
            span = whitelist_items(
                raw, flags, fee=fee_sat,
                weight=int(weight) if isinstance(weight, int) else None,
                sigops=int(sigops) if isinstance(sigops, int) else None,
                package_fee_sat=package_fee, package_vsize=package_vsize,
                descendant_count=int(entry.get("descendantcount") or 0),
                prevouts=prevouts,
            )
            if span == 2:
                two_ids.add(txid)
                one_ids.discard(txid)
            elif span == 1:
                one_ids.add(txid)
                two_ids.discard(txid)
            else:
                one_ids.discard(txid)
                two_ids.discard(txid)
        except Exception as exc:
            print(f"skip {txid}: {exc}", flush=True)
            continue
        decided[txid] = reason
        reasons[txid] = reason
        if not dry_run and txid not in marked and already_marked(entry, delta):
            marked[txid] = reason or "marked"
    children: dict[str, list[str]] = {}
    for txid, reason in reasons.items():
        if not reason:
            continue
        try:
            kids = node.call("getmempooldescendants", [txid, False]) or []
        except Exception as exc:
            print(f"descendants {txid}: {exc}", flush=True)
            kids = []
        children[txid] = list(kids)
    want = wanted_marks(reasons, children)
    for txid, reason in want.items():
        if txid in marked:
            marked[txid] = reason
            continue
        mark(node, txid, delta, reason, dry_run)
        if not dry_run:
            marked[txid] = reason
    for txid in [txid for txid in marked if txid in live and txid not in want]:
        unmark(node, txid, delta, dry_run)
        if not dry_run:
            marked.pop(txid, None)
    blocked = sum(1 for txid in marked if txid in live)
    return {
        "mempool": len(live),
        "blocked": blocked,
        "whitelist": sum(1 for txid in whitelist_ids if txid in live),
        "whitelist_one": sum(1 for txid in one_ids if txid in live),
        "whitelist_two": sum(1 for txid in two_ids if txid in live),
    }


def main() -> int:
    cfg_path = Path(sys.argv[1] if len(sys.argv) > 1 else HERE / "config.json")
    cfg = load_json(cfg_path)
    rules_path = Path(cfg.get("rules_file") or "rules.json")
    if not rules_path.is_absolute():
        rules_path = cfg_path.parent / rules_path
    delta = int(cfg.get("fee_delta_sats") or DEFAULT_DELTA)
    if delta >= 0:
        print("fee_delta_sats must be negative", flush=True)
        return 2
    dry_run = cfg.get("dry_run") is not False
    poll = max(2, int(cfg.get("poll_seconds") or 10))
    node = Node(cfg)
    print(
        f"sidecar dry_run={dry_run} delta={delta} rules={rules_path} poll={poll}s",
        flush=True,
    )
    if dry_run:
        print("dry_run is on: the node will not be changed", flush=True)
    decided: dict[str, str | None] = {}
    marked: dict[str, str] = {}
    whitelist_ids: set[str] = set()
    one_ids: set[str] = set()
    two_ids: set[str] = set()
    stamp: tuple[int, int] | None = None
    flags: dict = {}
    once = cfg.get("once") is True
    listen = str(cfg.get("listen") or "")
    status_path = cfg_path.parent / "sidecar.status.json"
    if listen and not once:
        catalog = 1
        catalog_shapes: list = []
        shapes = Path(cfg.get("shapes_file") or "shapes.json")
        if not shapes.is_absolute():
            shapes = cfg_path.parent / shapes
        if shapes.is_file():
            try:
                loaded = json.loads(shapes.read_text())
                catalog = int(loaded.get("version") or 1)
                catalog_shapes = loaded.get("shapes") if isinstance(loaded.get("shapes"), list) else []
                catalog_shapes = list(catalog_shapes) + board.load_private_shapes(shapes.parent)
            except (json.JSONDecodeError, TypeError, ValueError):
                catalog = 1
        peers_path = Path(cfg.get("peers_file") or "peers.json")
        if not peers_path.is_absolute():
            peers_path = cfg_path.parent / peers_path
        status_path = peers_path.parent / peers_path.name.replace(".peers.json", ".status.json")
        carries = cfg.get("carries") if isinstance(cfg.get("carries"), list) else None
        directory = Directory(str(cfg.get("name") or "sidecar"), listen, catalog, peers_path, carries)
        directory.catalog_shapes = catalog_shapes
        inbox_name = peers_path.name.replace(".peers.json", ".inbox.json")
        inbox_path = Path(cfg.get("inbox_file") or peers_path.parent / inbox_name)
        if not inbox_path.is_absolute():
            inbox_path = cfg_path.parent / inbox_path
        directory.inbox_path = inbox_path
        directory.start()
        configured = [str(item) for item in cfg.get("peers") or []]
        manual_path = peers_path.with_name(peers_path.name.replace(".peers.json", ".manual.json"))
        local_path = cfg_path.parent / "sift-local.json"

        def read_local() -> dict:
            try:
                loaded = json.loads(local_path.read_text())
            except (OSError, json.JSONDecodeError):
                loaded = {}
            if not isinstance(loaded, dict):
                loaded = {}
            loaded.setdefault("search_port_plus_2", True)
            loaded.setdefault("accept_packages", False)
            loaded.setdefault("import_received", False)
            return loaded

        def read_manual() -> list[str]:
            try:
                loaded = json.loads(manual_path.read_text())
            except (OSError, json.JSONDecodeError):
                return []
            if not isinstance(loaded, list):
                return []
            return [str(item) for item in loaded if isinstance(item, str)]

        def find_peers() -> None:
            next_search = 0.0
            while True:
                local = read_local()
                now = time.time()
                if not local.get("search_now") and now < next_search:
                    time.sleep(2)
                    continue
                targets = list(configured)
                targets.extend(read_manual())
                if local.get("search_port_plus_2", True):
                    try:
                        targets.extend(outbound_sidecar_addrs(node.call("getpeerinfo", []) or []))
                    except Exception as exc:
                        print(f"peer list failed: {exc}", flush=True)
                seen: set[str] = set()
                for address in targets:
                    if address in seen or address == listen:
                        continue
                    seen.add(address)
                    directory.dial(address)
                if local.get("search_now"):
                    local["search_now"] = False
                    tmp = local_path.with_suffix(".json.tmp")
                    tmp.write_text(json.dumps(local, indent=2) + "\n")
                    tmp.replace(local_path)
                next_search = time.time() + max(poll, 15)
                time.sleep(2)

        threading.Thread(target=find_peers, name="sidecar-find", daemon=True).start()
    while True:
        try:
            now = rules_stamp(rules_path)
            rescan = stamp is None or now != stamp
            if rescan:
                flags = load_json(rules_path)
                stamp = now
                print("rules loaded", flush=True)
            counts = scan(node, flags, delta, dry_run, decided, marked, whitelist_ids, one_ids, two_ids, rescan)
            peers_sent = 0
            if status_path.with_name(status_path.name.replace(".status.json", ".peers.json")).is_file():
                try:
                    peer_rows = json.loads(status_path.with_name(status_path.name.replace(".status.json", ".peers.json")).read_text())
                    peers_sent = sum(1 for row in peer_rows.get("peers") or [] if row.get("accept"))
                except (json.JSONDecodeError, OSError):
                    peers_sent = 0
            status_path.write_text(json.dumps({
                "mempool": counts["mempool"],
                "blocked": counts["blocked"],
                "whitelist": counts["whitelist"],
                "whitelist_one": counts["whitelist_one"],
                "whitelist_two": counts["whitelist_two"],
                "peers_sent": peers_sent,
            }) + "\n")
        except Exception as exc:
            print(f"scan failed: {exc}", flush=True)
            if once:
                return 1
        if once:
            return 0
        time.sleep(poll)


if __name__ == "__main__":
    raise SystemExit(main())
