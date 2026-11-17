#!/usr/bin/env python3
"""Mark spam in one node's mempool and leave the mark there.

The gateway never connects to this program. Knots builds the only template.
One node, one policy. dry_run is off unless the config sets it true.
"""
from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import board
from hello import Directory, outbound_sidecar_addrs, port_offset, probe_is_due
from datetime import datetime, timezone
import builtins

def _stamp(*args, **kwargs):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    builtins.print(now, *args, **kwargs)

print = _stamp

from spamcore import ANCHOR_SCRIPT, package_from_entry, paid_by_descendant, prevout_scripts, single_opreturn, tx_input_outpoints, tx_is_ark_whitelist, whitelist_items, tx_reject_reason, _tx_parts

# Larger than a block of fees, so a child cannot pay a marked parent back in.
# Satoshis. Knots adds this to the fee it uses for mining selection only.
DEFAULT_DELTA = -1_000_000_000_000_000
# Put back on a whitelist transaction and its descendants. 1000 covers the
# 240 sat dust-anchor penalty and leaves the pair above 1 sat/vB.
WHITELIST_DELTA = 1000
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
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                payload = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode(errors="replace")
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError as err:
                raise RuntimeError(f"{method}: {raw}") from err
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


ARK_IGNORE = ["min relay fee not met", "dust-nonanchor", "dust-nonzero", "dust"]
FEE_IGNORE = ["min relay fee not met"]
ALREADY = ("already in mempool", "txn-already-in-mempool", "txn-already-known")


def _rpc_text(exc: Exception) -> str:
    return str(exc).lower()


def send_one(node: Node, raw_hex: str, ignores: list[str]) -> str:
    """Add one transaction. A conflict stops the caller. An already-present tx is fine."""
    try:
        node.call("sendrawtransaction", [raw_hex, 0, 0, ignores])
    except RuntimeError as exc:
        text = _rpc_text(exc)
        if any(phrase in text for phrase in ALREADY):
            return "already"
        if "conflict" in text:
            return "conflict"
        return "rejected"
    return "added"


def package_hexes(pkg: dict) -> list[str]:
    hexes = [str(pkg.get("parent") or "")]
    child = str(pkg.get("child") or "")
    if child:
        hexes.append(child)
    hexes.extend(str(part) for part in pkg.get("extra") or [])
    return [item for item in hexes if item]


def topo_order(node: Node, hexes: list[str]) -> list[str] | None:
    """Parents before the transactions that spend them. None if the set does not order."""
    decoded = []
    for raw_hex in hexes:
        try:
            info = node.call("decoderawtransaction", [raw_hex])
        except RuntimeError:
            return None
        if not isinstance(info, dict) or not info.get("txid"):
            return None
        prevs = [vin["txid"] for vin in info.get("vin") or [] if isinstance(vin, dict) and vin.get("txid")]
        decoded.append((raw_hex, info["txid"], prevs))
    ids = {txid for _raw, txid, _prevs in decoded}
    deps = {txid: {prev for prev in prevs if prev in ids} for _raw, txid, prevs in decoded}
    by_id = {txid: raw_hex for raw_hex, txid, _prevs in decoded}
    ordered_ids = []
    while len(ordered_ids) < len(decoded):
        ready = sorted(txid for txid, need in deps.items() if txid not in ordered_ids and not need)
        if not ready:
            return None
        txid = ready[0]
        ordered_ids.append(txid)
        for need in deps.values():
            need.discard(txid)
    return [by_id[txid] for txid in ordered_ids]


def submit_package(node: Node, pkg: dict) -> str:
    """Insert one received set, one transaction after another. No retry on conflict."""
    shape = str(pkg.get("shape") or "")
    ordered = topo_order(node, package_hexes(pkg))
    if not ordered:
        return "unordered"
    if shape == "WLS-1":
        ignores_for = [ARK_IGNORE] + [[] for _ in ordered[1:]]
    else:
        ignores_for = [FEE_IGNORE for _ in ordered[:-1]] + [[]]
    notes = []
    for raw_hex, ignores in zip(ordered, ignores_for):
        result = send_one(node, raw_hex, ignores)
        notes.append(result)
        if result in {"conflict", "rejected"}:
            return " ".join(notes) + " stopped"
    return " ".join(notes)


def submit_pending(node: Node, directory: Directory) -> None:
    while directory.pending_submit:
        digest = directory.pending_submit.pop(0)
        if digest in directory.submitted:
            continue
        pkg = directory.packages.get(digest)
        directory.submitted.add(digest)
        if not pkg:
            continue
        result = submit_package(node, pkg)
        print(f"submit {pkg.get('shape')} {digest[:12]} {result}", flush=True)


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


def priority_top_up(have: int, want: int) -> int:
    """Sats still to add so this node's priority delta reaches want. Knots adds each call."""
    if want <= 0 or have >= want:
        return 0
    return want - have


def _priority_add(node: Node, txid: str, add: int) -> str:
    """ok, or dust when Knots refuses priority on a dust output."""
    try:
        node.call("prioritisetransaction", [txid, 0, add])
    except Exception as exc:
        body = ""
        read = getattr(exc, "read", None)
        if read is not None:
            try:
                body = read().decode(errors="replace")
            except Exception:
                body = ""
        text = f"{exc} {body}".lower()
        if "dust" in text:
            return "dust"
        raise
    return "ok"


def boost_whitelist(node: Node, txids: set[str], boosted: set[str], dry_run: bool, want: int) -> None:
    """Add mining priority to whitelist transactions. The priority is local and is not relayed.

    Knots refuses priority on a transaction with a dust output, such as the
    zero-value anchor. The same amount is then added to its descendants.
    """
    pending = {txid for txid in txids if txid not in boosted}
    if want <= 0 or not pending:
        return
    try:
        current = node.call("getprioritisedtransactions", []) or {}
    except Exception as exc:
        print(f"whitelist priority skipped: {exc}", flush=True)
        return
    if not isinstance(current, dict):
        current = {}

    def have_of(txid: str) -> int:
        row = current.get(txid)
        return int(row.get("fee_delta") or 0) if isinstance(row, dict) else 0

    def give(txid: str) -> None:
        if txid in boosted:
            return
        add = priority_top_up(have_of(txid), want)
        if add == 0:
            boosted.add(txid)
            return
        if dry_run:
            print(f"would whitelist {txid} delta=+{add}", flush=True)
            boosted.add(txid)
            return
        if _priority_add(node, txid, add) == "dust":
            print(f"whitelist {txid} dust output, priority refused", flush=True)
            try:
                kids = node.call("getmempooldescendants", [txid, False]) or []
            except Exception:
                kids = []
            for kid in kids:
                give(str(kid))
        else:
            print(f"whitelist {txid} delta=+{add}", flush=True)
        boosted.add(txid)

    for txid in sorted(pending):
        try:
            give(txid)
        except Exception as exc:
            print(f"whitelist {txid} skipped: {exc}", flush=True)


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


def anchor_child_hex(node: Node, parent_txid: str, parent_hex: str, kids: list) -> str:
    """The child that spends this parent's zero-value anchor, not the next tree transaction."""
    try:
        parts = _tx_parts(bytes.fromhex(parent_hex))
    except ValueError:
        return ""
    if not parts:
        return ""
    anchor = next((i for i, (value, script) in enumerate(parts[1]) if value == 0 and script == ANCHOR_SCRIPT), None)
    if anchor is None:
        return ""
    want = bytes.fromhex(parent_txid)[::-1]
    for kid in kids:
        raw_hex = node.call("getrawtransaction", [kid])
        if not isinstance(raw_hex, str):
            continue
        points = tx_input_outpoints(bytes.fromhex(raw_hex)) or []
        if any(prev == want and vout == anchor for prev, vout in points):
            return raw_hex
    return ""


def paid_sets(links: dict[str, set[str]]) -> list[list[str]]:
    """One set per low-fee root. A descendant of another low-fee tx stays in that parent's set."""
    roots = [
        txid for txid in links
        if not any(txid in kids for other, kids in links.items() if other != txid)
    ]
    return [[root] + sorted(links[root]) for root in sorted(roots)]


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
    packages: list | None = None,
    paid: list | None = None,
    boosted: set[str] | None = None,
    whitelist_delta: int = WHITELIST_DELTA,
) -> dict[str, int]:
    if boosted is None:
        boosted = set()
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
    ark_packages: list[tuple[str, str]] = packages if packages is not None else []
    paid_packages: list[tuple[str, str]] = paid if paid is not None else []
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
                ark_packages.append((raw_hex, txid))
            else:
                whitelist_ids.discard(txid)
            own_vsize = entry.get("vsize")
            if not isinstance(own_vsize, int) and isinstance(weight, int):
                own_vsize = (int(weight) + 3) // 4
            if flags.get("whitelist_package_paid") is True and paid_by_descendant(flags, fee_sat, own_vsize if isinstance(own_vsize, int) else None, package_fee, package_vsize):
                paid_packages.append((raw_hex, txid))
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
    protected = set(whitelist_ids)
    for txid in list(whitelist_ids):
        try:
            protected.update(node.call("getmempooldescendants", [txid, False]) or [])
        except Exception:
            pass
    for txid in protected:
        want.pop(txid, None)
    lift = {txid for txid in (protected | two_ids) if txid in live and txid not in want}
    for gone in [txid for txid in list(boosted) if txid not in live or txid not in lift]:
        boosted.discard(gone)
    boost_whitelist(node, lift, boosted, dry_run, whitelist_delta)
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


def dry_run_enabled(cfg: dict) -> bool:
    """Live unless the config sets dry_run true. A missing key is not a dry run."""
    return cfg.get("dry_run") is True


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
    dry_run = dry_run_enabled(cfg)
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
    boosted: set[str] = set()
    whitelist_ids: set[str] = set()
    one_ids: set[str] = set()
    two_ids: set[str] = set()
    stamp: tuple[int, int] | None = None
    flags: dict = {}
    once = cfg.get("once") is True
    listen = str(cfg.get("listen") or "")
    status_path = cfg_path.parent / "sidecar.status.json"
    directory = None
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
        directory = Directory(
            str(cfg.get("name") or "sidecar"), listen, catalog, peers_path, carries,
            announce=str(cfg.get("announce") or ""), commit=str(cfg.get("commit") or ""),
        )
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
            loaded["port_offset"] = port_offset(loaded.get("port_offset", 4))
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

        probes_path = cfg_path.parent / (peers_path.stem + ".probes.json")

        def load_probes() -> dict[str, float]:
            try:
                loaded_probes = json.loads(probes_path.read_text())
            except (OSError, json.JSONDecodeError):
                return {}
            if not isinstance(loaded_probes, dict):
                return {}
            stamps = {}
            for key, value in loaded_probes.items():
                if isinstance(value, (int, float)):
                    stamps[str(key)] = float(value)
            return stamps

        def save_probes(stamps: dict[str, float]) -> None:
            tmp = probes_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(stamps, indent=2) + "\n")
            tmp.replace(probes_path)

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
                        found = outbound_sidecar_addrs(node.call("getpeerinfo", []) or [], local.get("port_offset", 4))
                    except Exception as exc:
                        print(f"peer list failed: {exc}", flush=True)
                        found = []
                    stamps = load_probes()
                    due = [address for address in found if probe_is_due(stamps.get(address, 0), now)]
                    if due:
                        picked = due[0]
                        stamps[picked] = now
                        save_probes(stamps)
                        targets.append(picked)
                        print(f"probe {picked}", flush=True)
                seen: set[str] = set()
                for address in targets:
                    if address in seen or address == listen or address == directory.announce:
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
            local = board.read_local()
            if directory is not None:
                host = str(local.get("publish_host") or "")
                port = local.get("publish_port") or ""
                announce = f"{host}:{port}" if host and port else str(cfg.get("announce") or "")
                directory.set_identity(str(local.get("name") or cfg.get("name") or ""), announce)
            found_packages: list[tuple[str, str]] = []
            found_paid: list[tuple[str, str]] = []
            counts = scan(
                node, flags, delta, dry_run, decided, marked, whitelist_ids, one_ids, two_ids,
                rescan, found_packages, found_paid, boosted, int(local.get("whitelist_delta_sats") or 0),
            )
            if listen:
                open_shapes = set()
                if flags.get("whitelist_ark_zero_anchor") is True:
                    open_shapes.add("WLS-1")
                if flags.get("whitelist_package_paid") is True:
                    open_shapes.add("WLS-2")
                directory.set_open_shapes(open_shapes)
                for raw_hex, txid in found_packages:
                    try:
                        kids = node.call("getmempooldescendants", [txid, False]) or []
                    except Exception:
                        kids = []
                    directory.add_package("WLS-1", raw_hex, anchor_child_hex(node, txid, raw_hex, kids), local=True)
                raws = {txid: raw_hex for raw_hex, txid in found_paid}
                links = {}
                for txid in raws:
                    try:
                        kids = node.call("getmempooldescendants", [txid, False]) or []
                    except Exception:
                        kids = []
                    links[txid] = set(kids)
                for group in paid_sets(links):
                    hexes = []
                    for txid in group:
                        raw_hex = raws.get(txid)
                        if raw_hex is None:
                            fetched = node.call("getrawtransaction", [txid])
                            raw_hex = fetched if isinstance(fetched, str) else ""
                        if not raw_hex:
                            hexes = []
                            break
                        hexes.append(raw_hex)
                    if len(hexes) < 2:
                        continue
                    directory.add_package("WLS-2", hexes[0], hexes[1], hexes[2:], local=True)
                submit_pending(node, directory)
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
