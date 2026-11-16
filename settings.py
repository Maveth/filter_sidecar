"""Sidecar rule fields and how a strict node still accepts the Ark whitelist.

The rules file is this program's policy. The node stays on its normal strict
settings. This module does not write bitcoin.conf.
"""
from __future__ import annotations

# Shown when whitelist_ark_zero_anchor is on. The node is not loosened.
KNOTS_FOR_ARK_WHITELIST = (
    {
        "conf": "sendrawtransaction <parent-hex> 0 0 ignore_rejects '[\"min relay fee not met\",\"dust-nonanchor\",\"dust-nonzero\",\"dust\"]'",
        "default": "strict policy, parent rejected on the public peer port",
        "why": (
            "Version 3, miner fee exactly 0, one zero-value pay-to-anchor. "
            "A strict node rejects that parent from a peer. ignore_rejects is "
            "RPC-only, so the sidecar inserts this parent locally. Peers cannot."
        ),
    },
    {
        "conf": "sendrawtransaction <child-hex> 0",
        "default": "only after the parent is in this mempool",
        "why": (
            "The child spends the anchor and pays the miner fee. It is a normal "
            "submission. submitpackage cannot carry ignore_rejects. Use that RPC "
            "only after Knots keeps the list through SingleInPackageAccept."
        ),
    },
)

RULE_FIELDS = (
    {
        "key": "whitelist_ark_zero_anchor",
        "type": "bool",
        "label": "Ark zero-anchor whitelist",
        "help": (
            "Leave unmarked a version-3 parent whose miner fee is exactly 0 and "
            "which has one zero-value pay-to-anchor. A high fee is not this shape. "
            "The child that pays the fee is not whitelisted."
        ),
    },
    {
        "key": "dust_sat_per_kvb",
        "type": "int",
        "label": "Dust line",
        "help": "Satoshis per 1000 virtual bytes. 3000 is 3 sat/vB. Empty uses no sidecar dust line.",
    },
    {
        "key": "permitephemeral",
        "type": "bool",
        "label": "Skip a zero-value anchor in the dust check",
        "help": "Does not admit the package. Knots permitephemeral does that.",
    },
    {
        "key": "minfeerate_sat_vb",
        "type": "number",
        "label": "Minimum fee rate",
        "help": "Sat/vB marked below this rate. Empty adds no sidecar fee floor.",
    },
    {
        "key": "rejectfanout",
        "type": "bool",
        "label": "Fan-out",
        "help": "Mark a transaction with few inputs and many kept outputs. Off leaves it unmarked.",
    },
    {
        "key": "fanout_outputs_min",
        "type": "int",
        "label": "Fan-out kept outputs",
        "help": "Mark when the count of non-OP_RETURN outputs is at least this.",
    },
    {
        "key": "fanout_inputs_max",
        "type": "int",
        "label": "Fan-out inputs",
        "help": "Mark only when the input count is this number or less.",
    },
    {
        "key": "rejectdustspray",
        "type": "bool",
        "label": "Dust spray",
        "help": "Mark a transaction with many outputs under a sat line. Off leaves it unmarked.",
    },
    {
        "key": "dustspray_count_min",
        "type": "int",
        "label": "Dust spray outputs",
        "help": "Mark when at least this many outputs are above zero and under the sat line.",
    },
    {
        "key": "dustspray_sat_max",
        "type": "int",
        "label": "Dust spray sat line",
        "help": "An output under this many sats counts toward the spray.",
    },
    {
        "key": "rejectopreturnstack",
        "type": "bool",
        "label": "Several OP_RETURNs",
        "help": "Mark a transaction with at least this many OP_RETURN outputs.",
    },
    {
        "key": "opreturn_count_min",
        "type": "int",
        "label": "OP_RETURN count",
        "help": "Mark when the OP_RETURN output count is at least this.",
    },
    {
        "key": "rejectheavytapscript",
        "type": "bool",
        "label": "Heavy tapscript",
        "help": "Mark a revealed tapscript at least this many bytes.",
    },
    {
        "key": "tapscript_bytes_min",
        "type": "int",
        "label": "Tapscript bytes",
        "help": "Mark when the largest revealed tapscript is at least this many bytes.",
    },
    {
        "key": "fakeoutput_count_min",
        "type": "int",
        "label": "Dust P2WSH count",
        "help": "Mark when at least this many same-value P2WSH outputs are at or under the sat cap.",
    },
    {
        "key": "fakeoutput_sat_max",
        "type": "int",
        "label": "Dust P2WSH sats",
        "help": "A P2WSH output at or under this many sats can join the run.",
    },
    {
        "key": "whitelist_empty_runestone",
        "type": "bool",
        "label": "Empty runestone",
        "help": "Leave an OP_RETURN OP_13 with no payload unmarked. A runestone with bytes stays spam.",
    },
    {
        "key": "whitelist_commitment_32",
        "type": "bool",
        "label": "32-byte commitment",
        "help": "Leave one 32-byte OP_RETURN unmarked by the data-carrier check.",
    },
    {
        "key": "whitelist_empty_opreturn",
        "type": "bool",
        "label": "Empty OP_RETURN",
        "help": "Leave one OP_RETURN with no payload unmarked by the data-carrier check.",
    },
    {
        "key": "whitelist_consolidation",
        "type": "bool",
        "label": "Consolidation",
        "help": "Leave a many-input, few-output transaction unmarked by dust, dust spray, and fan-out.",
    },
    {
        "key": "consolidation_inputs_min",
        "type": "int",
        "label": "Consolidation inputs",
        "help": "The transaction needs at least this many inputs.",
    },
    {
        "key": "consolidation_outputs_max",
        "type": "int",
        "label": "Consolidation outputs",
        "help": "The transaction may have at most this many kept outputs.",
    },
    {"key": "dust_sift", "type": "bool", "label": "Sift dust line", "help": "When on, Sift marks outputs under its own dust line. The node keeps its own dust rule either way."},
    {"key": "minfee_sift", "type": "bool", "label": "Sift minimum fee", "help": "When on, Sift marks transactions under its fee line."},
    {"key": "rejectopreturntext", "type": "bool", "label": "OP_RETURN text", "help": "Mark a short text OP_RETURN that is not one of the named rows."},
    {"key": "rejectopreturndata", "type": "bool", "label": "OP_RETURN data", "help": "Mark a short binary OP_RETURN that is not one of the named rows."},
    {"key": "rejectswapmemo", "type": "bool", "label": "Swap memo", "help": "Mark an OP_RETURN that starts with =: or to:."},
    {"key": "rejectbabylon", "type": "bool", "label": "Babylon tag", "help": "Mark an OP_RETURN that starts with bbn1."},
    {"key": "rejectcoredao", "type": "bool", "label": "Core DAO tag", "help": "Mark an OP_RETURN that starts with SAT+."},
    {"key": "rejectbareinscription", "type": "bool", "label": "Bare inscription", "help": "Mark a script that drops an ord tag with OP_2DROP and is not inside OP_FALSE OP_IF."},
    {"key": "rejectmanysigs", "type": "bool", "label": "Many signatures", "help": "Mark a transaction whose signature-check count is at least the slider."},
    {"key": "manysigs_min", "type": "int", "label": "Signature checks", "help": "Mark when the signature-check count is at least this."},
    {"key": "whitelist_lightning_anchor_sweep", "type": "bool", "label": "Lightning anchor sweep", "help": "Leave a short OP_RETURN unmarked when every input spends a BOLT 3 anchor, including one nested in P2SH."},
    {"key": "lightning_sweep_payload_max", "type": "int", "label": "Lightning sweep bytes", "help": "The single OP_RETURN may have at most this many payload bytes."},
    {"key": "whitelist_p2a_sweep", "type": "bool", "label": "Pay-to-anchor sweep", "help": "Leave a short OP_RETURN unmarked when every input spends a pay-to-anchor output, an OP_TRUE leaf, or a bare timelock leaf."},
    {"key": "p2a_sweep_payload_max", "type": "int", "label": "Pay-to-anchor sweep bytes", "help": "The single OP_RETURN may have at most this many payload bytes."},
    {"key": "whitelist_powpeg", "type": "bool", "label": "PowPeg flyover", "help": "Leave a Rootstock PowPeg spend unmarked by the fake-multisig check. Any other mark stays."},
    {"key": "whitelist_dust_sweep", "type": "bool", "label": "Dust sweep", "help": "Leave a transaction whose only output is a short OP_RETURN unmarked by the data-carrier check."},
    {"key": "dustsweep_payload_max", "type": "int", "label": "Dust sweep bytes", "help": "The single OP_RETURN may have at most this many payload bytes."},
    {"key": "whitelist_package_paid", "type": "bool", "label": "Package-paid", "help": "Leave a low-fee transaction unmarked when a descendant has lifted the package to the fee line."},
    {"key": "package_paid_sat_vb", "type": "int", "label": "Package fee", "help": "The descendant package must be at least this many sat/vB."},
    {
        "key": "datacarrier",
        "type": "bool",
        "label": "Allow data carriers",
        "help": "Off marks OP_RETURN the node has already accepted.",
    },
    {
        "key": "datacarriersize",
        "type": "int",
        "label": "Data carrier size",
        "help": "Maximum payload bytes when data carriers are allowed.",
    },
    {
        "key": "datacarrierfullcount",
        "type": "bool",
        "label": "Count the whole data script",
        "help": "On counts the script without the OP_RETURN byte.",
    },
    {
        "key": "datacarriercost",
        "type": "int",
        "label": "Data carrier cost",
        "help": "Extra weight units per data byte before the fee-rate check.",
    },
    {
        "key": "permitbaredatacarrier",
        "type": "bool",
        "label": "Allow a transaction of only data outputs",
        "help": "Off marks a transaction whose every output is OP_RETURN.",
    },
    {
        "key": "permitbareanchor",
        "type": "bool",
        "label": "Allow a transaction of only anchors",
        "help": "Off marks a transaction whose every output is the anchor script.",
    },
    {
        "key": "permitbaremultisig",
        "type": "bool",
        "label": "Allow bare multisig",
        "help": "Off marks bare multisig outputs.",
    },
    {
        "key": "permitbarepubkey",
        "type": "bool",
        "label": "Allow bare pubkey",
        "help": "Off marks legacy bare pubkey outputs.",
    },
    {
        "key": "rejectparasites",
        "type": "bool",
        "label": "Reject parasitic overlays",
        "help": "Runes, stamps, and Counterparty when the node let them in.",
    },
    {
        "key": "rejectrunestones",
        "type": "bool",
        "label": "Reject runestones",
        "help": "OP_RETURN runestone marker.",
    },
    {
        "key": "rejectstamps",
        "type": "bool",
        "label": "Reject stamps",
        "help": "Stamp overlays.",
    },
    {
        "key": "rejectcounterparty",
        "type": "bool",
        "label": "Reject Counterparty",
        "help": "Counterparty payloads.",
    },
    {
        "key": "rejecttokenmessages",
        "type": "bool",
        "label": "Reject token messages",
        "help": "Token payloads in data scripts.",
    },
    {
        "key": "rejecttokens",
        "type": "bool",
        "label": "Reject token scripts",
        "help": "Ordinal-style envelopes and similar token scripts.",
    },
    {
        "key": "rejectfakeoutputs",
        "type": "bool",
        "label": "Reject fake outputs",
        "help": "Data stuffed into a witness or script hash program.",
    },
    {
        "key": "rejectfakemultisig",
        "type": "bool",
        "label": "Reject fake multisig",
        "help": "Multisig used to carry data.",
    },
    {
        "key": "rejectbareenvelopes",
        "type": "bool",
        "label": "Reject bare envelopes",
        "help": "OP_CHECKSIG or OP_CHECKMULTISIG after only pushes.",
    },
    {
        "key": "rejectdeadbranches",
        "type": "bool",
        "label": "Reject dead branches",
        "help": "OP_FALSE OP_IF and OP_TRUE OP_NIP data branches.",
    },
    {
        "key": "bytespersigop",
        "type": "int",
        "label": "Bytes per sigop",
        "help": "Mark when virtual size is below this many bytes times the sigop count.",
    },
    {
        "key": "maxtxlegacysigops",
        "type": "int",
        "label": "Legacy sigop cap",
        "help": "Maximum legacy sigops in inputs and outputs.",
    },
    {
        "key": "maxscriptsize",
        "type": "int",
        "label": "Max script size",
        "help": "Maximum bytes of one script the sidecar will leave unmarked.",
    },
)


# Knots defaults. A line is included when Sift has it on, or the value is not this default.
KNOTS_CONF = {
    "rejectparasites": "1",
    "rejecttokens": "1",
    "rejectdeadbranches": "1",
    "datacarrier": "1",
    "datacarriersize": "83",
    "datacarriercost": "1",
    "datacarrierfullcount": "1",
    "bytespersigop": "20",
    "maxscriptsize": "1650",
    "maxtxlegacysigops": "2500",
    "permitbareanchor": "1",
    "permitbaredatacarrier": "0",
    "permitbaremultisig": "0",
    "permitbarepubkey": "0",
}


def _conf_bool(value: bool) -> str:
    return "1" if value else "0"


def bitcoin_conf_lines(rules: dict) -> list[str]:
    """Knots lines for settings Sift has on, or that differ from the Knots default.

    Sift-only checks are left out. Knots does not have a switch for them.
    """
    lines = []
    bool_keys = (
        "rejectparasites", "rejecttokens", "rejectdeadbranches", "datacarrier",
        "datacarrierfullcount", "permitbareanchor", "permitbaredatacarrier",
        "permitbaremultisig", "permitbarepubkey",
    )
    for key in bool_keys:
        if not isinstance(rules.get(key), bool):
            continue
        written = _conf_bool(rules[key])
        if rules[key] is True or written != KNOTS_CONF[key]:
            lines.append(f"{key}={written}")
    for key in ("datacarriersize", "datacarriercost", "bytespersigop", "maxscriptsize", "maxtxlegacysigops"):
        value = rules.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        if rules.get("datacarrier") is False and key == "datacarriersize":
            continue
        text = str(int(value))
        if text != KNOTS_CONF[key]:
            lines.append(f"{key}={text}")
    dust = rules.get("dust_sat_per_kvb")
    if rules.get("dust_sift") is not False and isinstance(dust, int) and dust > 0:
        lines.append(f"dustrelayfee={dust / 100_000_000:.8f}")
    fee = rules.get("minfeerate_sat_vb")
    if rules.get("minfee_sift") is True and isinstance(fee, (int, float)) and not isinstance(fee, bool) and fee > 0:
        lines.append(f"minrelaytxfee={float(fee) / 100_000:.8f}")
    return lines


def knots_notice(whitelist_on: bool) -> dict | None:
    """Operator text for the Knots startup lines. None when the whitelist is off."""
    if not whitelist_on:
        return None
    return {
        "title": "A strict node accepts this package only by local insertion",
        "summary": (
            "The node stays on its normal strict settings. This page does not "
            "write bitcoin.conf and does not restart the node. The public peer "
            "port still rejects the zero-fee parent. The sidecar inserts that "
            "parent with sendrawtransaction and ignore_rejects, then the child. "
            "Other sidecars receive that signed pair on their own port and do "
            "the same insertion, so their miners can include the exit. "
            "submitpackage is not used until it keeps ignore_rejects."
        ),
        "lines": list(KNOTS_FOR_ARK_WHITELIST),
    }


def _coerce(field: dict, value):
    kind = field["type"]
    if kind == "bool":
        if isinstance(value, bool):
            return value
        raise ValueError(f"{field['key']} must be true or false")
    if value is None or value == "":
        if field["key"] in {"dust_sat_per_kvb", "minfeerate_sat_vb"}:
            return None
        raise ValueError(f"{field['key']} is required")
    if kind == "int":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or int(value) != value:
            raise ValueError(f"{field['key']} must be a whole number")
        number = int(value)
        if number < 0:
            raise ValueError(f"{field['key']} must be zero or more")
        return number
    if kind == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{field['key']} must be a number")
        if value < 0:
            raise ValueError(f"{field['key']} must be zero or more")
        return value
    raise ValueError(f"unknown field type for {field['key']}")


def normalize_rules(incoming: dict, previous: dict | None = None) -> dict:
    """Check known fields and keep any unknown keys already in the file."""
    if not isinstance(incoming, dict):
        raise ValueError("rules must be a JSON object")
    known = {field["key"]: field for field in RULE_FIELDS}
    out = dict(previous or {})
    for key, value in incoming.items():
        if key not in known:
            out[key] = value
            continue
        out[key] = _coerce(known[key], value)
    missing = [field["key"] for field in RULE_FIELDS if field["key"] not in out]
    if missing:
        raise ValueError("missing " + ", ".join(missing))
    return out
