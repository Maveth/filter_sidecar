"""Shape catalog, live rules, and the mark log for the Sift page.

change_shape updates the rules file values the page is allowed to change.
It does not dial a peer or insert a transaction.
"""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

import spamcore

# Catalog id -> rules.json key that turns that check on.
# These rules are already on in Knots. A sidecar rule outside this set is extra.
NODE_RULES = {
    "rejectparasites",
    "rejectrunestones",
    "rejectcounterparty",
    "rejectstamps",
    "rejectfakemultisig",
    "rejectdeadbranches",
    "rejectbareenvelopes",
    "dust_sat_per_kvb",
}

LIVE_RULE = {
    "ark-exit": "whitelist_ark_zero_anchor",
    "cat21": "rejectparasites",
    "runestone": "rejectrunestones",
    "counterparty": "rejectcounterparty",
    "stamps": "rejectstamps",
    "fake-multisig": "rejectfakemultisig",
    "dead-branch": "rejectdeadbranches",
    "bare-envelope": "rejectbareenvelopes",
    "json-token": "rejecttokenmessages",
    "omni": "rejecttokenmessages",
    "dust-p2wsh-run": "rejectfakeoutputs",
    "dust-output": "dust_sat_per_kvb",
    "min-fee": "minfeerate_sat_vb",
    "fan-out": "rejectfanout",
    "dust-spray": "rejectdustspray",
    "opreturn-stack": "rejectopreturnstack",
    "data-heavy": "rejectheavytapscript",
    "opreturn-text": "rejectopreturntext",
    "opreturn-data": "rejectopreturndata",
    "swap-memo": "rejectswapmemo",
    "babylon-tag": "rejectbabylon",
    "core-dao-tag": "rejectcoredao",
    "bare-inscription": "rejectbareinscription",
    "many-sigs": "rejectmanysigs",
    "dust-sweep": "whitelist_dust_sweep",
    "lightning-anchor-sweep": "whitelist_lightning_anchor_sweep",
    "p2a-sweep": "whitelist_p2a_sweep",
    "powpeg-flyover": "whitelist_powpeg",
    "package-paid": "whitelist_package_paid",
    "empty-runestone": "whitelist_empty_runestone",
    "commitment-32": "whitelist_commitment_32",
    "empty-opreturn": "whitelist_empty_opreturn",
    "consolidation": "whitelist_consolidation",
}

# A spam row names the whitelist that can put a matching transaction back.
EXEMPTS = {
    "dust-output": ("ark-exit", "consolidation"),
    "dust-spray": ("ark-exit", "consolidation"),
    "min-fee": ("ark-exit", "package-paid"),
    "runestone": ("empty-runestone",),
    "opreturn-text": ("commitment-32", "empty-opreturn", "dust-sweep", "lightning-anchor-sweep", "p2a-sweep"),
    "opreturn-data": ("commitment-32", "empty-opreturn", "dust-sweep", "lightning-anchor-sweep", "p2a-sweep"),
    "opreturn-stack": ("commitment-32", "empty-opreturn"),
    "fake-multisig": ("powpeg-flyover",),
}

# A Knots option that defaults on. The shape cannot be turned off while this
# node still has that option on and the rules file has the check on.
LOCKED_BY_NODE = {
    "cat21": "rejectparasites",
    "runestone": "rejectparasites",
    "counterparty": "rejectparasites",
    "stamps": "rejectparasites",
    "dead-branch": "rejectdeadbranches",
}

# bitcoin.conf key shown on the card. Not every shape has one.
CONF_KEY = {
    "cat21": "rejectparasites",
    "runestone": "rejectparasites",
    "counterparty": "rejectparasites",
    "stamps": "rejectparasites",
    "dead-branch": "rejectdeadbranches",
    "json-token": "rejecttokens",
    "omni": "rejecttokens",
    "dust-output": "dustrelayfee",
    "min-fee": "blockmintxfee",
}

def node_conf_path(log_path: Path) -> Path | None:
    """Conf path from the local node-paths.json. Absent file means no conf is read."""
    table_path = Path(__file__).resolve().parent / "node-paths.json"
    try:
        table = json.loads(table_path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(table, dict):
        return None
    raw = table.get(Path(log_path).name)
    if not isinstance(raw, str) or not raw.strip():
        return None
    return Path(raw)
CONF_LINES = (
    "dustrelayfee",
    "minrelaytxfee",
    "blockmintxfee",
    "rejectparasites",
    "rejecttokens",
    "rejectdeadbranches",
    "datacarrier",
    "datacarriersize",
)
DUST_DEFAULT_SAT_VB = 3.0
MINFEE_DEFAULT_SAT_VB = 1.0

# What one shape's check returns from spamcore, and the flags that turn only
# that check on. A preview clears the other reject switches first.
PREVIEW = {
    "cat21": ("parasite", {"rejectparasites": True}),
    "runestone": ("runestone", {"rejectrunestones": True}),
    "counterparty": ("token", {"rejectcounterparty": True}),
    "stamps": ("token", {"rejectstamps": True}),
    "fake-multisig": ("fakemultisig", {"rejectfakemultisig": True}),
    "dead-branch": ("deadbranch", {"rejectdeadbranches": True}),
    "bare-envelope": ("bareenvelope", {"rejectbareenvelopes": True}),
    "json-token": ("token", {"rejecttokenmessages": True}),
    "omni": ("token", {"rejecttokenmessages": True}),
    "dust-p2wsh-run": ("fakeoutput", {"rejectfakeoutputs": True}),
    "dust-output": ("dust", {}),
    "min-fee": ("minfeerate", {}),
    "opreturn-text": ("datacarrier", {"datacarrier": False}),
    "opreturn-data": ("datacarrier", {"datacarrier": False}),
    "many-sigs": ("bytespersigop", {}),
    "fan-out": ("fanout", {}),
    "dust-spray": ("dustspray", {}),
    "opreturn-stack": ("opreturnstack", {}),
    "data-heavy": ("heavytapscript", {}),
    "opreturn-text": ("opreturntext", {}),
    "opreturn-data": ("opreturndata", {}),
    "swap-memo": ("swapmemo", {}),
    "babylon-tag": ("babylon", {}),
    "core-dao-tag": ("coredao", {}),
    "bare-inscription": ("bareinscription", {}),
    "many-sigs": ("manysigs", {}),
}

# Numeric lines on a shape. Apply writes them. Test uses the slider positions.
SLIDERS = {
    "fan-out": (
        {"key": "fanout_outputs_min", "label": "Kept outputs", "min": 2, "max": 80, "step": 1, "default": 25},
        {"key": "fanout_inputs_max", "label": "Inputs at most", "min": 1, "max": 8, "step": 1, "default": 2},
    ),
    "dust-spray": (
        {"key": "dustspray_count_min", "label": "Outputs under the line", "min": 2, "max": 80, "step": 1, "default": 10},
        {"key": "dustspray_sat_max", "label": "Under this many sats", "min": 1, "max": 10000, "step": 1, "default": 1000},
    ),
    "opreturn-stack": (
        {"key": "opreturn_count_min", "label": "OP_RETURN outputs", "min": 2, "max": 20, "step": 1, "default": 2},
    ),
    "data-heavy": (
        {"key": "tapscript_bytes_min", "label": "Tapscript bytes", "min": 1, "max": 10000, "step": 1, "default": 521},
    ),
    "dust-p2wsh-run": (
        {"key": "fakeoutput_count_min", "label": "Same-value outputs", "min": 2, "max": 20, "step": 1, "default": 3},
        {"key": "fakeoutput_sat_max", "label": "Sats at most", "min": 1, "max": 5000, "step": 1, "default": 546},
    ),
    "consolidation": (
        {"key": "consolidation_inputs_min", "label": "Inputs at least", "min": 2, "max": 80, "step": 1, "default": 25},
        {"key": "consolidation_outputs_max", "label": "Kept outputs at most", "min": 1, "max": 10, "step": 1, "default": 3},
    ),
    "many-sigs": (
        {"key": "manysigs_min", "label": "Signature checks", "min": 1, "max": 1000, "step": 1, "default": 100},
    ),
    "dust-sweep": (
        {"key": "dustsweep_payload_max", "label": "OP_RETURN bytes at most", "min": 0, "max": 80, "step": 1, "default": 4},
    ),
    "lightning-anchor-sweep": (
        {"key": "lightning_sweep_payload_max", "label": "OP_RETURN bytes at most", "min": 0, "max": 80, "step": 1, "default": 3},
    ),
    "p2a-sweep": (
        {"key": "p2a_sweep_payload_max", "label": "OP_RETURN bytes at most", "min": 0, "max": 80, "step": 1, "default": 4},
    ),
    "package-paid": (
        {"key": "package_paid_sat_vb", "label": "Package at least", "min": 1, "max": 10, "step": 1, "default": 1},
    ),
}

# Settings besides the main switch. The options popup edits these.
EXTRA_KEYS = {
    "dust-output": ("permitephemeral",),
    "opreturn-text": ("datacarrier", "datacarriersize", "datacarrierfullcount"),
    "opreturn-data": ("datacarrier", "datacarriersize", "datacarrierfullcount"),
    "data-heavy": ("datacarriersize", "datacarriercost"),
    "many-sigs": ("bytespersigop", "maxtxlegacysigops"),
}
CESSPOOL = "https://cesspool.lol/guide/"
GBT = "https://bitcoin-blake.github.io/gbt-rules/schema/"


def rule_is_on(rules: dict, key: str) -> bool:
    if key == "dust_sat_per_kvb":
        value = rules.get(key)
        return isinstance(value, int) and value > 0
    return rules.get(key) is True


def slug_of(shape_id: str) -> str:
    """SFS-1 and the old name both resolve to the name the rules use."""
    if not hasattr(slug_of, "table"):
        table = {}
        path = Path(__file__).resolve().parent / "shapes.json"
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            data = {}
        for shape in data.get("shapes") or []:
            if not isinstance(shape, dict):
                continue
            slug = shape.get("slug") or shape.get("id") or ""
            table[shape.get("id") or slug] = slug
            table[slug] = slug
        slug_of.table = table
    return slug_of.table.get(shape_id, shape_id)


def load_shapes(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    data = json.loads(path.read_text())
    shapes = data.get("shapes") if isinstance(data, dict) else None
    rows = shapes if isinstance(shapes, list) else []
    return rows + load_private_shapes(path.parent)


def load_private_shapes(base: Path) -> list[dict]:
    path = base / "shapes.local.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    shapes = data.get("shapes") if isinstance(data, dict) else None
    rows = []
    for shape in shapes or []:
        if not isinstance(shape, dict):
            continue
        row = dict(shape)
        row["transfer"] = False
        rows.append(row)
    return rows


def load_package_counts(log_path: Path) -> tuple[int, int]:
    """Verified packages received, then packages sent. One hash counts once."""
    path = log_path.with_suffix(".peers.traffic.json")
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return 0, 0
    if not isinstance(data, dict):
        return 0, 0
    incoming = data.get("in") if isinstance(data.get("in"), list) else []
    outgoing = data.get("out") if isinstance(data.get("out"), list) else []
    return len(dict.fromkeys(incoming)), len(dict.fromkeys(outgoing))


def load_package_rows(log_path: Path, key: str) -> list[dict]:
    """Sent or received package rows. One row per hash."""
    path = log_path.with_suffix(".peers.traffic.json")
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    rows = data.get(key)
    if not isinstance(rows, list):
        return []
    found = []
    seen = set()
    for item in rows:
        if not isinstance(item, dict) or not item.get("id") or item["id"] in seen:
            continue
        seen.add(item["id"])
        found.append({
            "id": item.get("id") or "",
            "shape": item.get("shape") or "",
            "parent": item.get("parent") or "",
            "child": item.get("child") or "",
            "to": item.get("to") or "",
            "when": item.get("when") or "",
        })
    return found


def load_sent(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    data = json.loads(path.read_text())
    if not isinstance(data, list):
        return []
    rows = []
    for item in data:
        if not isinstance(item, dict):
            continue
        rows.append({
            "id": item.get("id") or "",
            "parent": item.get("parent") or "",
            "child": item.get("child") or "",
            "to": item.get("to") or "",
            "when": item.get("when") or "",
        })
    return rows


def parse_marks(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        dry = False
        if line.startswith("would mark "):
            rest = line[len("would mark "):]
            dry = True
        elif line.startswith("marked "):
            rest = line[len("marked "):]
        else:
            continue
        txid, _, tail = rest.partition(" ")
        if len(txid) != 64:
            continue
        reason, sep, _delta = tail.rpartition(" delta=")
        if not sep:
            reason = tail
        rows.append({"txid": txid, "reason": reason.strip(), "dry_run": dry})
    return rows


def stopped_from_log(path: Path, recent: int = 40) -> dict:
    if not path.is_file():
        return {"total": 0, "by_reason": [], "recent": [], "log": str(path)}
    marks = [row for row in parse_marks(path.read_text(errors="replace")) if not row["dry_run"]]
    counts: dict[str, int] = {}
    for row in marks:
        counts[row["reason"]] = counts.get(row["reason"], 0) + 1
    by_reason = [{"reason": reason, "count": count} for reason, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]
    tail = marks[-recent:]
    tail.reverse()
    return {
        "total": len(marks),
        "by_reason": by_reason,
        "recent": [{"txid": row["txid"], "reason": row["reason"]} for row in tail],
        "log": str(path),
    }


def btc_per_kvb_to_sat_vb(text: str | None) -> float | None:
    try:
        return round(float(text) * 100_000, 8)
    except (TypeError, ValueError):
        return None


def _conf_on(text: str | None, default: bool = True) -> bool:
    if text is None:
        return default
    return text.strip().lower() in {"1", "true", "yes"}


def _read_conf(path: Path) -> dict[str, str]:
    try:
        text = path.read_text()
    except PermissionError:
        pattern = "^(" + "|".join(CONF_LINES) + ")="
        done = subprocess.run(
            ["sudo", "-n", "grep", "-E", pattern, str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
        text = done.stdout if done.returncode in (0, 1) else ""
    except OSError:
        text = ""
    found = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key in CONF_LINES:
            found[key] = value.strip()
    return found


def load_node_policy(log_path: Path) -> dict:
    """Fee lines and the spam switches for the node this page watches."""
    path = node_conf_path(log_path)
    conf = _read_conf(path) if path is not None else {}
    dust = btc_per_kvb_to_sat_vb(conf.get("dustrelayfee"))
    relay = btc_per_kvb_to_sat_vb(conf.get("minrelaytxfee"))
    mintx = btc_per_kvb_to_sat_vb(conf.get("blockmintxfee"))
    return {
        "rejectparasites": _conf_on(conf.get("rejectparasites"), True),
        "rejecttokens": _conf_on(conf.get("rejecttokens"), True),
        "rejectdeadbranches": _conf_on(conf.get("rejectdeadbranches"), True),
        "dust_sat_vb": dust if conf.get("dustrelayfee") else None,
        "dust_line": _conf_line("dustrelayfee", conf),
        "relay_sat_vb": relay if conf.get("minrelaytxfee") else None,
        "relay_line": _conf_line("minrelaytxfee", conf),
        "mintx_sat_vb": mintx if conf.get("blockmintxfee") else None,
        "mintx_line": _conf_line("blockmintxfee", conf),
        "lines": {key: conf[key] for key in CONF_LINES if key in conf},
    }


def current_node_conf(log_path: Path) -> str:
    """Policy lines from this node's bitcoin.conf. Passwords are not included."""
    path = node_conf_path(log_path)
    if path is None:
        return ""
    conf = _read_conf(path)
    return "\n".join(f"{key}={conf[key]}" for key in CONF_LINES if key in conf)


def _conf_line(key: str, conf: dict) -> str:
    if key not in conf:
        return ""
    return f"{key}={conf[key]}"


def source_of(origin: str) -> tuple[str, str]:
    text = (origin or "").strip()
    number = ""
    mark = "Knots #"
    if mark in text:
        tail = text.split(mark, 1)[1]
        number = "".join(ch for ch in tail if ch.isdigit())
    if number:
        return text, f"https://github.com/bitcoinknots/bitcoin/pull/{number}"
    if text.startswith("cesspool"):
        return "cesspool", CESSPOOL
    if text.startswith("gbt-rules"):
        rest = text.split(" ", 1)[1] if " " in text else ""
        return text, GBT + ("#" + rest if rest else "")
    if text.startswith("knots"):
        option = text.replace("knots -", "", 1).strip()
        return text, GBT + ("#knots-" + option if option else "")
    if text == "ours":
        return "ours", ""
    return text, ""


def _sat_vb(value) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def spam_cards(shapes: list[dict], rules: dict, node: dict, whitelist_titles: dict[str, str] | None = None) -> list[dict]:
    rows = [
        shape_row(shape, rules)
        for shape in shapes
        if shape.get("kind") == "spam" and shape.get("slug") != "min-fee"
    ]
    dust_at = next(
        (i for i, row in enumerate(rows) if (row.get("slug") or row.get("id")) == "dust-output"),
        len(rows) - 1,
    )
    rows.insert(dust_at + 1, _min_fee_row(rules))
    titles: dict[str, list[str]] = {}
    for row in rows:
        if row.get("rule"):
            titles.setdefault(row["rule"], []).append(row["title"])
    faced = []
    for n, row in enumerate(rows, start=1):
        faced.append(_face(row, n, rules, node, titles, whitelist_titles or {}))
    return faced


def whitelist_cards(shapes: list[dict], rules: dict) -> tuple[list[dict], dict[str, str]]:
    """Same row shape as spam. A rule can be turned on. Test counts what it puts back."""
    rows = [shape_row(shape, rules) for shape in shapes if shape.get("kind") == "whitelist"]
    titles = {}
    for row in rows:
        titles[row["id"]] = row["title"]
        titles[row.get("slug") or row["id"]] = row["title"]
    faced = []
    for n, row in enumerate(rows, start=1):
        label, url = source_of(row.get("from") or "")
        key = row.get("rule") or ""
        item = dict(row)
        item.update({
            "n": n,
            "options": [],
            "conf": [],
            "also": [],
            "source_label": label,
            "source_url": url,
            "exempt": [],
            "control": "bool" if key else "none",
            "active": rule_is_on(rules, key) if key else False,
            "test": bool(key),
            "sliders": [
                {
                    "key": spec["key"],
                    "label": spec["label"],
                    "min": spec["min"],
                    "max": spec["max"],
                    "step": spec["step"],
                    "value": int(rules.get(spec["key"]) or spec["default"]),
                }
                for spec in SLIDERS.get(row.get("slug") or row["id"], ())
            ],
        })
        faced.append(item)
    return faced, titles


def _min_fee_row(rules: dict) -> dict:
    key = "minfeerate_sat_vb"
    value = rules.get(key)
    return {
        "id": "SFS-28",
        "slug": "min-fee",
        "title": "Minimum fee",
        "kind": "spam",
        "carry": "definition",
        "from": "knots -blockmintxfee",
        "checker": "min-fee",
        "schema": {"mark_below_sat_vb": value},
        "note": "Mark a transaction under this fee so the node leaves it out of the block. It stays in the mempool.",
        "insert": None,
        "live": _sat_vb(value) is not None and value > 0,
        "rule": key,
        "owner": "sidecar",
        "catalog": False,
    }


def _face(row: dict, n: int, rules: dict, node: dict, titles: dict[str, list[str]], whitelist_titles: dict[str, str]) -> dict:
    label, url = source_of(row.get("from") or "")
    others = [title for title in titles.get(row.get("rule") or "", []) if title != row.get("title")]
    faced = dict(row)
    faced["n"] = n
    faced["catalog"] = row.get("catalog", True)
    faced["description"] = row.get("note") or "No description yet."
    faced["source_label"] = label
    faced["source_url"] = url
    faced["also"] = others
    faced["conf"] = _conf_for(row["id"], node)
    control, active, sat_vb, floor, node_vb, default_vb = _control(row, rules, node)
    faced["control"] = control
    faced["active"] = active
    faced["sat_vb"] = sat_vb
    faced["floor_sat_vb"] = floor
    faced["node_sat_vb"] = node_vb
    faced["default_sat_vb"] = default_vb
    faced["below_default"] = node_vb is not None and default_vb is not None and node_vb < default_vb
    faced["exempt"] = [
        {"id": wid, "title": whitelist_titles.get(wid, wid)}
        for wid in EXEMPTS.get(row.get("slug") or row["id"], ())
    ]
    faced["options"] = _options(row["id"], rules)
    # A Knots lock already drops the match, so there is nothing to preview.
    # A raise dial can still go higher inside Sift, and that preview is useful.
    faced["test"] = (row.get("slug") or row["id"]) in PREVIEW and control != "locked"
    faced["sliders"] = [
        {
            "key": spec["key"],
            "label": spec["label"],
            "min": spec["min"],
            "max": spec["max"],
            "step": spec["step"],
            "value": int(rules.get(spec["key"]) or spec["default"]),
        }
        for spec in SLIDERS.get(row.get("slug") or row["id"], ())
    ]
    return faced


def _options(shape_id: str, rules: dict) -> list[dict]:
    shape_id = slug_of(shape_id)
    import settings as ruleset
    known = {field["key"]: field for field in ruleset.RULE_FIELDS}
    rows = []
    for key in EXTRA_KEYS.get(shape_id, ()):
        field = known.get(key)
        if not field:
            continue
        rows.append({
            "key": key,
            "label": field["label"],
            "type": field["type"],
            "help": field["help"],
            "value": rules.get(key),
        })
    return rows


def preview_flags(rules: dict, shape_id: str, sat_vb: float | None, proposal: dict | None = None) -> tuple[dict, str]:
    shape_id = slug_of(shape_id)
    """Rules with only this shape's check turned on, and the reason it returns."""
    found = PREVIEW.get(shape_id)
    if not found:
        raise ValueError("this shape is not checked against the mempool yet")
    reason, turn_on = found
    flags = dict(rules)
    for key in list(flags):
        if key.startswith("reject"):
            flags[key] = False
    flags["datacarrier"] = True
    flags["dust_sat_per_kvb"] = None
    flags["minfeerate_sat_vb"] = None
    flags["bytespersigop"] = 0
    flags["datacarriercost"] = 0
    flags["permitbarepubkey"] = True
    flags["permitbaremultisig"] = True
    flags["permitbaredatacarrier"] = True
    flags["permitbareanchor"] = True
    flags.update(turn_on)
    if shape_id == "dust-output":
        rate = _sat_vb(sat_vb)
        if rate is None or rate <= 0:
            raise ValueError("set the dial above the current dust line")
        flags["dust_sat_per_kvb"] = int(round(rate * 1000))
        flags["dust_sift"] = True
        flags["permitephemeral"] = rules.get("permitephemeral") is True
    elif shape_id == "min-fee":
        rate = _sat_vb(sat_vb)
        if rate is None or rate <= 0:
            raise ValueError("set the dial above the current minimum fee")
        flags["minfeerate_sat_vb"] = rate
        flags["minfee_sift"] = True
    proposal = proposal or {}
    for spec in SLIDERS.get(shape_id, ()):
        flags[spec["key"]] = _whole(proposal.get(spec["key"]), rules.get(spec["key"]), spec["default"])
    rule = LIVE_RULE.get(shape_id) or ""
    if rule.startswith("reject"):
        flags[rule] = True
    return flags, reason


def _whole(proposed, saved, default: int) -> int:
    for value in (proposed, saved, default):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        number = int(value)
        if number > 0:
            return number
    return default


_MEMPOOL: dict[str, tuple[float, dict, dict]] = {}


def _config_for_log(log_path: Path) -> dict:
    name = Path(log_path).name
    filename = "config.seed.json" if "seed" in name else "config.json"
    path = Path(__file__).resolve().parent / filename
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or not data.get("rpc_url"):
        raise ValueError("this node's connection is not configured")
    return data


def _mempool(log_path: Path) -> tuple[dict, dict]:
    """Verbose mempool entries and raw transactions, reused for a minute."""
    key = Path(log_path).name
    now = time.monotonic()
    cached = _MEMPOOL.get(key)
    if cached and now - cached[0] < 60:
        return cached[1], cached[2]
    import sidecar
    node = sidecar.Node(_config_for_log(log_path))
    verbose = node.call("getrawmempool", [True]) or {}
    if not isinstance(verbose, dict):
        verbose = {}
    raws: dict[str, str] = {}
    txids = list(verbose)
    for start in range(0, len(txids), 150):
        chunk = txids[start:start + 150]
        got = node.batch([("getrawtransaction", [txid]) for txid in chunk])
        for txid, raw in zip(chunk, got):
            if isinstance(raw, str):
                raws[txid] = raw
    _MEMPOOL[key] = (now, verbose, raws)
    return verbose, raws


def _spent_scripts(log_path: Path, raw: bytes, cache: dict, node_box: dict) -> list[bytes] | None:
    """Parent output scripts for a one-output OP_RETURN. Other transactions are not looked up."""
    from spamcore import prevout_scripts, single_opreturn
    if not single_opreturn(raw):
        return None
    if node_box.get("node") is None:
        import sidecar
        node_box["node"] = sidecar.Node(_config_for_log(log_path))

    def fetch(txid: str) -> str | None:
        if txid not in cache:
            got = node_box["node"].call("getrawtransaction", [txid])
            cache[txid] = got if isinstance(got, str) else None
        return cache[txid]

    return prevout_scripts(raw, fetch)


def preview_mempool(log_path: Path, rules: dict, shape_id: str, sat_vb: float | None, proposal: dict | None = None) -> dict:
    """Transactions this check would block, or a whitelist would put back. Nothing is marked."""
    shape_id = slug_of(shape_id)
    if (LIVE_RULE.get(shape_id) or "").startswith("whitelist"):
        return _bring_back(log_path, rules, shape_id, proposal)
    flags, reason = preview_flags(rules, shape_id, sat_vb, proposal)
    from spamcore import package_from_entry, tx_is_ark_whitelist, tx_reject_reason
    entries, raws = _mempool(log_path)
    parents: dict[str, str | None] = {}
    node_box: dict = {}
    need_parents = flags.get("whitelist_lightning_anchor_sweep") is True or flags.get("whitelist_p2a_sweep") is True
    hits = []
    for txid, entry in entries.items():
        raw_hex = raws.get(txid)
        if not isinstance(entry, dict) or not isinstance(raw_hex, str):
            continue
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError:
            continue
        fees = (entry.get("fees") or {}).get("base")
        fee_sat = int(round(float(fees) * 100_000_000)) if fees is not None else None
        weight = entry.get("weight")
        sigops = entry.get("sigops")
        if tx_is_ark_whitelist(raw, flags, fee_sat):
            continue
        package_fee, package_vsize = package_from_entry(entry)
        prevouts = _spent_scripts(log_path, raw, parents, node_box) if need_parents else None
        got = tx_reject_reason(
            raw, flags, fee=fee_sat,
            weight=int(weight) if isinstance(weight, int) else None,
            sigops=int(sigops) if isinstance(sigops, int) else None,
            package_fee_sat=package_fee, package_vsize=package_vsize,
            prevouts=prevouts,
        )
        if got == reason:
            hits.append(txid)
    return {
        "count": len(hits),
        "txids": hits[:12],
        "more": max(0, len(hits) - 12),
        "mempool": len(entries),
        "reason": reason,
        "brought_back": False,
    }


def _silence(flags: dict, reason: str) -> dict | None:
    """Turn off the check that just matched, so the next call can find another."""
    nxt = dict(flags)
    flag = {
        "parasite": "rejectparasites",
        "runestone": "rejectrunestones",
        "fakeoutput": "rejectfakeoutputs",
        "fanout": "rejectfanout",
        "dustspray": "rejectdustspray",
        "opreturnstack": "rejectopreturnstack",
        "heavytapscript": "rejectheavytapscript",
        "opreturntext": "rejectopreturntext",
        "opreturndata": "rejectopreturndata",
        "swapmemo": "rejectswapmemo",
        "babylon": "rejectbabylon",
        "coredao": "rejectcoredao",
        "bareinscription": "rejectbareinscription",
        "manysigs": "rejectmanysigs",
        "deadbranch": "rejectdeadbranches",
        "bareenvelope": "rejectbareenvelopes",
        "fakemultisig": "rejectfakemultisig",
    }.get(reason)
    if flag:
        nxt[flag] = False
        return nxt
    if reason == "token":
        for key in ("rejecttokenmessages", "rejectcounterparty", "rejectstamps", "rejecttokens"):
            nxt[key] = False
        return nxt
    if reason == "dust":
        nxt["dust_sift"] = False
        return nxt
    if reason == "minfeerate":
        nxt["minfee_sift"] = False
        return nxt
    if reason == "datacarrier":
        nxt["datacarrier"] = True
        return nxt
    if reason == "datacarriersize":
        nxt["datacarriersize"] = 10**9
        return nxt
    if reason == "scriptsize":
        nxt["maxscriptsize"] = 10**9
        return nxt
    if reason == "legacysigops":
        nxt["maxtxlegacysigops"] = 10**9
        return nxt
    if reason == "baredatacarrier":
        nxt["permitbaredatacarrier"] = True
        return nxt
    if reason == "bareanchor":
        nxt["permitbareanchor"] = True
        return nxt
    if reason == "bytespersigop":
        nxt["bytespersigop"] = 0
        return nxt
    if reason == "datacarriercost":
        nxt["datacarriercost"] = 0
        return nxt
    return None


def _all_reasons(raw: bytes, flags: dict, **kwargs) -> list[str]:
    from spamcore import tx_reject_reason
    found = []
    current = dict(flags)
    for _ in range(12):
        reason = tx_reject_reason(raw, current, **kwargs)
        if not reason or reason in found:
            break
        found.append(reason)
        nxt = _silence(current, reason)
        if nxt is None:
            break
        current = nxt
    return found


def _bring_back(log_path: Path, rules: dict, shape_id: str, proposal: dict | None) -> dict:
    """Split transactions this whitelist fully saves from ones another rule still blocks."""
    shape_id = slug_of(shape_id)
    key = LIVE_RULE.get(shape_id) or ""
    if not key:
        raise ValueError("this whitelist is not checked against the mempool yet")
    proposal = proposal or {}
    off = dict(rules)
    on = dict(rules)
    off[key] = False
    on[key] = True
    for spec in SLIDERS.get(shape_id, ()):
        value = _whole(proposal.get(spec["key"]), rules.get(spec["key"]), spec["default"])
        off[spec["key"]] = value
        on[spec["key"]] = value
    if shape_id == "package-paid" and rules.get("minfee_sift") is not True:
        # The fee switch is off, so measure the whitelist against its own line.
        off["minfee_sift"] = True
        on["minfee_sift"] = True
        off["minfeerate_sat_vb"] = on["package_paid_sat_vb"]
        on["minfeerate_sat_vb"] = on["package_paid_sat_vb"]
    from spamcore import package_from_entry
    entries, raws = _mempool(log_path)
    parents: dict[str, str | None] = {}
    node_box: dict = {}
    need_parents = shape_id in ("lightning-anchor-sweep", "p2a-sweep") or on.get("whitelist_lightning_anchor_sweep") is True or on.get("whitelist_p2a_sweep") is True
    only = []
    also = []
    cleared_names = []
    for txid, entry in entries.items():
        raw_hex = raws.get(txid)
        if not isinstance(entry, dict) or not isinstance(raw_hex, str):
            continue
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError:
            continue
        fees = (entry.get("fees") or {}).get("base")
        fee_sat = int(round(float(fees) * 100_000_000)) if fees is not None else None
        weight = entry.get("weight")
        sigops = entry.get("sigops")
        package_fee, package_vsize = package_from_entry(entry)
        kwargs = {
            "fee": fee_sat,
            "weight": int(weight) if isinstance(weight, int) else None,
            "sigops": int(sigops) if isinstance(sigops, int) else None,
            "package_fee_sat": package_fee,
            "package_vsize": package_vsize,
            "prevouts": _spent_scripts(log_path, raw, parents, node_box) if need_parents else None,
        }
        before = _all_reasons(raw, off, **kwargs)
        after = _all_reasons(raw, on, **kwargs)
        cleared = [reason for reason in before if reason not in after]
        if not cleared:
            continue
        if after:
            also.append({"txid": txid, "cleared": cleared, "remains": after})
        else:
            only.append(txid)
            for reason in cleared:
                if reason not in cleared_names:
                    cleared_names.append(reason)
    return {
        "count": len(only),
        "txids": only[:12],
        "more": max(0, len(only) - 12),
        "also_count": len(also),
        "also": also[:12],
        "also_more": max(0, len(also) - 12),
        "cleared": cleared_names,
        "mempool": len(entries),
        "reason": key,
        "brought_back": True,
    }


def _conf_for(shape_id: str, node: dict) -> list[dict]:
    shape_id = slug_of(shape_id)
    if shape_id == "min-fee":
        rows = []
        if node.get("mintx_line"):
            rows.append({"line": node["mintx_line"], "note": "minimum fee to include a transaction in a block"})
        if node.get("relay_line"):
            rows.append({"line": node["relay_line"], "note": "minimum fee to relay"})
        return rows
    key = CONF_KEY.get(shape_id)
    if not key:
        return []
    if key == "dustrelayfee":
        line = node.get("dust_line") or ""
        return [{"line": line, "note": "dust line"}] if line else []
    raw = (node.get("lines") or {}).get(key)
    if raw is None:
        return []
    return [{"line": f"{key}={raw}", "note": "Knots default is on" if _conf_on(raw) else "this node has it off"}]


def _control(row: dict, rules: dict, node: dict) -> tuple:
    shape_id = row.get("slug") or row["id"]
    if shape_id == "dust-output":
        current = _sat_vb(rules.get("dust_sat_per_kvb"))
        current_vb = None if current is None else current / 1000
        node_vb = node.get("dust_sat_vb")
        floor = current_vb if current_vb is not None else node_vb
        return "raise", rules.get("dust_sift") is not False, current_vb, floor, node_vb, DUST_DEFAULT_SAT_VB
    if shape_id == "min-fee":
        current = _sat_vb(rules.get("minfeerate_sat_vb"))
        node_vb = node.get("mintx_sat_vb")
        floor = current if current is not None else node_vb
        return "raise", rules.get("minfee_sift") is True, current, floor, node_vb, MINFEE_DEFAULT_SAT_VB
    key = row.get("rule") or ""
    if not key:
        return "none", False, None, None, None, None
    active = rule_is_on(rules, key)
    cover = LOCKED_BY_NODE.get(shape_id)
    if cover and active and node.get(cover, True):
        return "locked", True, None, None, None, None
    return "bool", active, None, None, None, None


def _above(new: float, floor: float | None, what: str) -> None:
    if floor is None:
        raise ValueError(f"this node's {what} is not loaded")
    if not new > floor:
        raise ValueError(f"{what} can only be raised above {floor:g} sat/vB")


def change_shape(rules: dict, shape_id: str, change: dict, node: dict) -> dict:
    """Return updated rules. Refuse turning off a Knots default, or lowering a fee."""
    if not isinstance(change, dict):
        raise ValueError("change must be an object")
    shape_id = slug_of(shape_id)
    updated = dict(rules)
    sliders = change.get("sliders")
    allowed_sliders = {spec["key"] for spec in SLIDERS.get(shape_id, ())}
    if isinstance(sliders, dict) and allowed_sliders:
        for key in allowed_sliders:
            if key in sliders:
                updated[key] = sliders[key]
        if "active" not in change and "sat_vb" not in change and not isinstance(change.get("options"), dict):
            return updated
    options = change.get("options")
    if isinstance(options, dict):
        allowed = set(EXTRA_KEYS.get(shape_id, ()))
        if not allowed:
            raise ValueError("this shape has no other settings")
        refused = [key for key in options if key not in allowed]
        if refused:
            raise ValueError("that setting is not on this shape")
        updated.update(options)
        if "active" not in change and "sat_vb" not in change:
            return updated
    if shape_id == "dust-output" and isinstance(change.get("active"), bool) and "sat_vb" not in change:
        updated["dust_sift"] = change["active"]
        return updated
    if shape_id == "min-fee" and isinstance(change.get("active"), bool):
        updated["minfee_sift"] = change["active"]
        if "sat_vb" not in change:
            return updated
    if shape_id == "dust-output":
        sat_vb = _sat_vb(change.get("sat_vb"))
        if sat_vb is None or sat_vb <= 0:
            raise ValueError("enter a dust line above the current value, in sat/vB")
        current = _sat_vb(rules.get("dust_sat_per_kvb"))
        floor = None if current is None else current / 1000
        if floor is None:
            floor = node.get("dust_sat_vb")
        _above(sat_vb, floor, "dust")
        stored = int(round(sat_vb * 1000))
        if current is not None and stored <= current:
            raise ValueError(f"dust can only be raised above {floor:g} sat/vB")
        updated["dust_sat_per_kvb"] = stored
        return updated
    if shape_id == "min-fee":
        sat_vb = _sat_vb(change.get("sat_vb"))
        if sat_vb is None or sat_vb <= 0:
            raise ValueError("enter a minimum fee above the current value, in sat/vB")
        current = _sat_vb(rules.get("minfeerate_sat_vb"))
        floor = current if current is not None else node.get("mintx_sat_vb")
        _above(sat_vb, floor, "the minimum fee")
        updated["minfeerate_sat_vb"] = sat_vb
        return updated
    key = LIVE_RULE.get(shape_id)
    if not key or key == "dust_sat_per_kvb":
        raise ValueError("this shape has no on/off switch")
    active = change.get("active")
    if not isinstance(active, bool):
        raise ValueError("active must be true or false")
    cover = LOCKED_BY_NODE.get(shape_id)
    if active is False and cover and rule_is_on(rules, key) and node.get(cover, True):
        raise ValueError("Knots already has this on. Sift cannot turn it off.")
    updated[key] = active
    return updated


def shape_row(shape: dict, rules: dict) -> dict:
    slug = shape.get("slug") or shape.get("id") or ""
    key = LIVE_RULE.get(slug) or ""
    return {
        "id": shape.get("id") or slug,
        "slug": slug,
        "title": shape.get("title") or "",
        "kind": shape.get("kind") or "",
        "carry": shape.get("carry") or "",
        "from": shape.get("from") or "",
        "checker": slug if slug in spamcore.CHECKERS else "",
        "schema": shape.get("schema") if isinstance(shape.get("schema"), dict) else {},
        "note": shape.get("note") or "",
        "insert": shape.get("insert") or None,
        "live": bool(key) and rule_is_on(rules, key),
        "rule": key,
        "owner": "node" if key in NODE_RULES else "sidecar" if key else "",
        "transfer": shape.get("transfer") is not False,
    }


def load_peers(log_path: Path) -> tuple[dict, list[dict]]:
    path = log_path.with_suffix(".peers.json")
    if not path.is_file():
        return {}, []
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}, []
    if not isinstance(data, dict):
        return {}, []
    self_row = data.get("self") if isinstance(data.get("self"), dict) else {}
    peers = [row for row in data.get("peers") or [] if isinstance(row, dict)]
    return self_row, peers


def load_inbox(log_path: Path) -> dict:
    path = log_path.with_suffix(".inbox.json")
    if not path.is_file():
        return {"peers": []}
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"peers": []}
    peers = data.get("peers") if isinstance(data, dict) else None
    rows = []
    if isinstance(peers, dict):
        for listen, item in peers.items():
            if not isinstance(item, dict):
                continue
            shapes = item.get("shapes") if isinstance(item.get("shapes"), list) else []
            whitelist = item.get("whitelist") if isinstance(item.get("whitelist"), list) else []
            rows.append({
                "address": listen,
                "name": item.get("name") or "",
                "catalog": item.get("catalog"),
                "when": item.get("when") or "",
                "spam": sum(1 for row in shapes if isinstance(row, dict) and row.get("kind") == "spam"),
                "watch": sum(1 for row in shapes if isinstance(row, dict) and row.get("kind") == "watch"),
                "whitelist": len([row for row in whitelist if isinstance(row, dict)]),
                "packages": sum(1 for row in whitelist if isinstance(row, dict) and row.get("parent") and row.get("child")),
                "enabled": sum(1 for row in shapes + whitelist if isinstance(row, dict) and row.get("enabled") is True),
            })
    return {"peers": rows}


def view(shapes_path: Path, rules: dict, log_path: Path, sent_path: Path) -> dict:
    node = load_node_policy(log_path)
    catalog = load_shapes(shapes_path)
    whitelist, whitelist_titles = whitelist_cards(catalog, rules)
    rows = [shape_row(shape, rules) for shape in catalog]
    datacarrier_off = rules.get("datacarrier") is False
    self_row, peers = load_peers(log_path)
    received = load_inbox(log_path)
    package_in, package_out = load_package_counts(log_path)
    stopped = stopped_from_log(log_path)
    counts = load_counts(log_path, stopped["total"], peers)
    return {
        "spam": spam_cards(catalog, rules, node, whitelist_titles),
        "whitelist": whitelist,
        "watch": [row for row in rows if row["kind"] == "watch"],
        "datacarrier_off": datacarrier_off,
        "self": self_row,
        "peers": peers,
        "manual_peers": manual_peers(log_path),
        "local": read_local(),
        "conf": __import__("settings").bitcoin_conf_lines(rules),
        "received": received,
        "peers_note": "Listening for a versioned hello. No other sidecar has answered yet.",
        "package_in": package_in,
        "package_out": package_out,
        "sent": load_package_rows(log_path, "sent") or load_sent(sent_path),
        "received_packages": load_package_rows(log_path, "received"),
        "sent_note": "Each hash is one package. Sent is the second number: a peer asked for it and this sidecar sent it.",
        "stopped": stopped,
        "counts": counts,
    }


def _base() -> Path:
    return Path(__file__).resolve().parent


def published_from_config() -> dict:
    """Name and address from config.json, for the settings form before a save."""
    out = {"name": "", "publish_host": "", "publish_port": ""}
    try:
        cfg = json.loads((_base() / "config.json").read_text())
    except (OSError, json.JSONDecodeError):
        return out
    if not isinstance(cfg, dict):
        return out
    if isinstance(cfg.get("name"), str):
        out["name"] = cfg["name"].strip()[:40]
    from hello import shareable_address, split_addr
    announce = str(cfg.get("announce") or "")
    parsed = split_addr(announce)
    if parsed and shareable_address(announce):
        out["publish_host"] = parsed[0]
        out["publish_port"] = parsed[1]
    return out


def clean_name(value) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 40 or any(ch.isspace() for ch in text):
        raise ValueError("Name must be 1 to 40 characters with no spaces")
    return text


def clean_published(host, port) -> tuple[str, int]:
    from hello import shareable_address
    text = str(host or "").strip()
    try:
        number = int(port)
    except (TypeError, ValueError):
        raise ValueError("Published port must be a number")
    if not text or number < 1 or number > 65535:
        raise ValueError("Published address needs a host and a port from 1 to 65535")
    address = f"{text}:{number}"
    if not shareable_address(address):
        raise ValueError("Published address cannot be 0.0.0.0 or a loopback address. Other sidecars cannot dial those.")
    return text, number


def clean_whitelist_delta(value) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError("Whitelist priority must be a number of sats")
    if number < 0 or number > 1_000_000_000:
        raise ValueError("Whitelist priority must be from 0 to 1000000000 sats")
    return number


def read_local() -> dict:
    defaults = {
        "search_port_plus_2": True,
        "accept_packages": False,
        "import_received": False,
        "port_offset": 4,
        "whitelist_delta_sats": 1000,
    }
    defaults.update(published_from_config())
    path = _base() / "sift-local.json"
    try:
        loaded = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        loaded = {}
    if not isinstance(loaded, dict):
        loaded = {}
    for key in ("search_port_plus_2", "accept_packages", "import_received"):
        if isinstance(loaded.get(key), bool):
            defaults[key] = loaded[key]
    from hello import port_offset
    defaults["port_offset"] = port_offset(loaded.get("port_offset", 4))
    if "whitelist_delta_sats" in loaded:
        try:
            defaults["whitelist_delta_sats"] = clean_whitelist_delta(loaded.get("whitelist_delta_sats"))
        except ValueError:
            pass
    if isinstance(loaded.get("name"), str) and loaded["name"].strip():
        defaults["name"] = loaded["name"].strip()[:40]
    if loaded.get("publish_host") and loaded.get("publish_port"):
        try:
            host, number = clean_published(loaded.get("publish_host"), loaded.get("publish_port"))
        except ValueError:
            pass
        else:
            defaults["publish_host"] = host
            defaults["publish_port"] = number
    return defaults


def manual_peers(log_path: Path) -> list[str]:
    name = "sidecar-seed.manual.json" if "seed" in Path(log_path).name else "sidecar.manual.json"
    path = _base() / name
    try:
        loaded = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(loaded, list):
        return []
    return [str(item) for item in loaded if isinstance(item, str)]


def clean_address(text: str) -> str:
    host, sep, port = str(text).strip().rpartition(":")
    if not sep or not host or not port.isdigit():
        raise ValueError("use host:port")
    number = int(port)
    if number < 1 or number > 65535:
        raise ValueError("port is out of range")
    return f"{host}:{number}"


def load_counts(log_path: Path, total_blocked: int, peers: list[dict]) -> dict:
    path = log_path.with_suffix(".status.json")
    data: dict = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text())
            if isinstance(loaded, dict):
                data = loaded
        except json.JSONDecodeError:
            data = {}
    return {
        "mempool": data.get("mempool"),
        "blocked": data.get("blocked"),
        "total_blocked": total_blocked,
        "whitelist": data.get("whitelist"),
        "whitelist_one": data.get("whitelist_one"),
        "whitelist_two": data.get("whitelist_two"),
        "peers_sent": sum(1 for row in peers if row.get("accept") is True),
    }
