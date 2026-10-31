#!/usr/bin/env python3
"""Mark spam in one node's mempool and leave the mark there.

The gateway never connects to this program. Knots builds the only template.
One node, one policy. dry_run stays on until a config turns it off.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request
from pathlib import Path

from spamcore import tx_reject_reason

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


def rules_stamp(path: Path) -> tuple[int, int]:
    st = path.stat()
    return st.st_mtime_ns, st.st_size


def consider(node: Node, txid: str, flags: dict) -> str | None:
    entry = node.call("getmempoolentry", [txid]) or {}
    raw_hex = node.call("getrawtransaction", [txid])
    if not isinstance(raw_hex, str):
        return None
    fees = (entry.get("fees") or {}).get("base")
    fee_sat = int(round(float(fees) * 100_000_000)) if fees is not None else None
    weight = entry.get("weight")
    sigops = entry.get("sigops")
    return tx_reject_reason(
        bytes.fromhex(raw_hex),
        flags,
        fee=fee_sat,
        weight=int(weight) if isinstance(weight, int) else None,
        sigops=int(sigops) if isinstance(sigops, int) else None,
    )


def mark(node: Node, txid: str, delta: int, reason: str, dry_run: bool) -> None:
    if dry_run:
        print(f"would mark {txid} {reason} delta={delta}", flush=True)
        return
    node.call("prioritisetransaction", [txid, 0, int(delta)])
    print(f"marked {txid} {reason} delta={delta}", flush=True)


def scan(node: Node, flags: dict, delta: int, dry_run: bool, decided: dict[str, str | None]) -> None:
    txids = node.call("getrawmempool", [False]) or []
    live = set(txids)
    for gone in [txid for txid in decided if txid not in live]:
        decided.pop(gone, None)
    for txid in txids:
        if txid in decided:
            continue
        try:
            reason = consider(node, txid, flags)
        except Exception as exc:
            print(f"skip {txid}: {exc}", flush=True)
            continue
        decided[txid] = reason
        if not reason:
            continue
        mark(node, txid, delta, reason, dry_run)
        try:
            children = node.call("getmempooldescendants", [txid, False]) or []
        except Exception as exc:
            print(f"descendants {txid}: {exc}", flush=True)
            children = []
        for child in children:
            if decided.get(child):
                continue
            decided[child] = f"child:{reason}"
            mark(node, child, delta, f"child of {reason}", dry_run)


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
    stamp: tuple[int, int] | None = None
    flags: dict = {}
    while True:
        try:
            now = rules_stamp(rules_path)
            if now != stamp:
                flags = load_json(rules_path)
                stamp = now
                decided.clear()
                print("rules loaded", flush=True)
            scan(node, flags, delta, dry_run, decided)
        except Exception as exc:
            print(f"scan failed: {exc}", flush=True)
        time.sleep(poll)


if __name__ == "__main__":
    raise SystemExit(main())
