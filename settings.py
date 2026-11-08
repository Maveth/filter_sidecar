"""Sidecar rule fields and the Knots lines the Ark whitelist depends on.

The rules file is this program's policy. The Knots lines are a different file,
read only when Knots starts. This module does not write bitcoin.conf.
"""
from __future__ import annotations

# Shown when whitelist_ark_zero_anchor is on. Defaults are Knots 29.4.3.
KNOTS_FOR_ARK_WHITELIST = (
    {
        "conf": "permitephemeral=anchor,-send,dust",
        "default": "anchor,-send,-dust",
        "why": (
            "The package parent is version 3, miner fee exactly 0, and one "
            "zero-value pay-to-anchor. anchor allows that output. dust, without "
            "the minus, allows a dust output the child spends in the same package. "
            "The default minus on dust rejects that package before this program sees it."
        ),
    },
    {
        "conf": "subdustfeepenalty=0",
        "default": "1",
        "why": (
            "The default penalty still charges sub-dust outputs. Turning it off "
            "admits more than the whitelist. This node then relays that wider set. "
            "The sidecar can leave only the whitelist unmarked. It cannot stop the relay."
        ),
    },
    {
        "conf": "mempooltruc=enforce",
        "default": "accept",
        "why": (
            "Version 3 is limited to one parent and one child, which is the "
            "package whose child pays the fee. This is one node-wide relay and "
            "mine setting, applied at startup."
        ),
    },
    {
        "conf": "minrelaytxfee=0.00000100",
        "default": "0.00001000",
        "why": (
            "0.1 sat/vB. The default 1 sat/vB can reject the small child fee that "
            "carries the zero-fee parent. The parent alone never clears the relay floor."
        ),
    },
    {
        "conf": "dustrelayfee=0.00003000",
        "default": "0.00003000",
        "why": (
            "3 sat/vB, already the Knots default. Keep the sidecar dust line at "
            "3000 sat/kvB so the two match. A lower node dust setting lets every "
            "dust shape in, not only this package."
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


def knots_notice(whitelist_on: bool) -> dict | None:
    """Operator text for the Knots startup lines. None when the whitelist is off."""
    if not whitelist_on:
        return None
    return {
        "title": "Knots has to admit this package before the whitelist can mine it",
        "summary": (
            "The whitelist only decides which transactions this program leaves "
            "unmarked. Knots rejects the zero-fee parent until the lines below "
            "are set. Knots reads them at startup. This page does not write them "
            "and does not restart the node. After they are on, the node relays "
            "every transaction the wider policy accepts. The sidecar keeps the "
            "ones outside the whitelist out of the block only. A transaction that "
            "contains dust cannot be deprioritized: Knots refuses that priority "
            "change, so a dusty parent stays at its normal mining score."
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
