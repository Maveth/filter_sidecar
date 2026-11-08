#!/usr/bin/env python3
"""Print the three sets from SPEC.md for one Knots config and one rules file.

Knots already enforces: the node rejects it, so the sidecar never sees it.
Sidecar only: Knots accepts it, and a mark would keep it out of the block.
Knots blocks first: a whitelist wants it, and Knots rejects it today.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Knots 29.4.3 defaults. A bitcoin.conf line overrides the default.
KNOTS_DEFAULTS = {
    "bytespersigop": "20",
    "datacarrier": "1",
    "datacarriercost": "1",
    "datacarrierfullcount": "1",
    "datacarriersize": "83",
    "maxscriptsize": "1650",
    "maxtxlegacysigops": "2500",
    "mempooltruc": "accept",
    "minrelaytxfee": "0.00001",
    "permitbareanchor": "1",
    "permitbaredatacarrier": "0",
    "permitbaremultisig": "0",
    "permitbarepubkey": "0",
    "permitephemeral": "anchor,-send,-dust",
    "rejectdeadbranches": "1",
    "rejectparasites": "1",
    "rejecttokens": "1",
    "subdustfeepenalty": "1",
}


def load_conf(path: Path) -> dict[str, str]:
    values = dict(KNOTS_DEFAULTS)
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def on(value: str | None) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def num(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def add(rows: list[tuple[str, str, str]], bucket: str, name: str, detail: str) -> None:
    rows.append((bucket, name, detail))


def classify(rules: dict, knots: dict[str, str]) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []

    # Sidecar reject flags that Knots covers with one switch.
    covered = [
        ("rejectparasites", "rejectparasites", "Knots -rejectparasites refuses parasitic overlays, including runes, stamps, and Counterparty."),
        ("rejectrunestones", "rejectparasites", "Runes are a parasitic overlay. Knots -rejectparasites drops them before the sidecar."),
        ("rejectstamps", "rejectparasites", "Stamps are a parasitic overlay. Knots -rejectparasites drops them before the sidecar."),
        ("rejectcounterparty", "rejectparasites", "Counterparty is a parasitic overlay. Knots -rejectparasites drops them before the sidecar."),
        ("rejecttokenmessages", "rejecttokens", "Knots -rejecttokens refuses non-bitcoin token messages."),
        ("rejecttokens", "rejecttokens", "Knots -rejecttokens refuses non-bitcoin token transactions."),
        ("rejectdeadbranches", "rejectdeadbranches", "Knots -rejectdeadbranches counts the OP_FALSE OP_IF envelope as data."),
    ]
    for rule, knot_key, detail in covered:
        if rules.get(rule) is not True:
            continue
        if on(knots.get(knot_key)):
            add(rows, "knots", rule, detail)
        else:
            add(rows, "sidecar", rule, f"Knots -{knot_key} is off, so these reach the mempool and only a sidecar mark keeps them out of the block. They are still relayed.")

    # permit* false means the sidecar rejects that bare form.
    bare = [
        ("permitbaremultisig", "permitbaremultisig", "bare multisig outputs"),
        ("permitbarepubkey", "permitbarepubkey", "legacy pubkey outputs"),
        ("permitbaredatacarrier", "permitbaredatacarrier", "transactions whose only outputs are data carriers"),
        ("permitbareanchor", "permitbareanchor", "transactions whose only outputs are ephemeral anchors"),
    ]
    for rule, knot_key, what in bare:
        if rule not in rules:
            continue
        sidecar_rejects = rules.get(rule) is False
        knots_rejects = not on(knots.get(knot_key))
        if not sidecar_rejects and not knots_rejects:
            continue
        if knots_rejects:
            add(rows, "knots", rule, f"Knots -{knot_key}=0 already refuses {what}.")
        elif sidecar_rejects:
            add(rows, "sidecar", rule, f"Knots -{knot_key} allows {what}. A sidecar mark would keep them out of the block. They would still be relayed.")

    if rules.get("datacarrier") is False and on(knots.get("datacarrier")):
        add(rows, "sidecar", "datacarrier", f"Knots -datacarrier=1 and -datacarriersize={knots.get('datacarriersize')} still relays data carriers. The sidecar rule refuses them. They would still be relayed.")
    elif rules.get("datacarrier") is False and not on(knots.get("datacarrier")):
        add(rows, "knots", "datacarrier", "Knots -datacarrier=0 already refuses data carriers.")

    sidecar_size = num(rules.get("datacarriersize"))
    knots_size = num(knots.get("datacarriersize"))
    if rules.get("datacarrier") is not False and sidecar_size is not None and knots_size is not None:
        if sidecar_size < knots_size:
            add(rows, "sidecar", "datacarriersize", f"Sidecar limit is {sidecar_size:g} bytes. Knots limit is {knots_size:g}. The sidecar marks the sizes Knots still accepts. Those are still relayed.")
        else:
            add(rows, "knots", "datacarriersize", f"Knots limit {knots_size:g} is at least as tight as the sidecar limit {sidecar_size:g}. Larger data carriers never arrive.")

    same_number = [
        ("bytespersigop", "bytespersigop"),
        ("maxtxlegacysigops", "maxtxlegacysigops"),
        ("maxscriptsize", "maxscriptsize"),
    ]
    for rule, knot_key in same_number:
        sidecar_n = num(rules.get(rule))
        knots_n = num(knots.get(knot_key))
        if sidecar_n is None or knots_n is None:
            continue
        if sidecar_n < knots_n:
            add(rows, "sidecar", rule, f"Sidecar limit {sidecar_n:g} is tighter than Knots {knots_n:g}. Only the extra-tight band is a sidecar mark. It is still relayed.")
        else:
            add(rows, "knots", rule, f"Knots limit {knots_n:g} is at least as tight as the sidecar limit {sidecar_n:g}.")

    if rules.get("minfeerate_sat_vb") in (None, "", 0):
        add(rows, "knots", "minfeerate_sat_vb", f"Sidecar adds no fee floor. Knots -minrelaytxfee={knots.get('minrelaytxfee')} already rejects below its relay floor.")
    else:
        add(rows, "sidecar", "minfeerate_sat_vb", f"Sidecar floor is {rules.get('minfeerate_sat_vb')} sat/vB. Knots relay floor is -minrelaytxfee={knots.get('minrelaytxfee')}. Anything Knots accepts below the sidecar floor is marked and still relayed.")

    # Whitelist that this binary rejects.
    ephemeral = str(knots.get("permitephemeral") or "")
    dust_off = "-dust" in ephemeral.replace(" ", "")
    penalty = on(knots.get("subdustfeepenalty"))
    if dust_off or penalty:
        add(
            rows,
            "blocked",
            "ark-ephemeral-dust",
            "A v3 zero-fee parent with one dust anchor, spent by a paying child, is the Ark whitelist shape. "
            f"This node has -permitephemeral={ephemeral} and -subdustfeepenalty={knots.get('subdustfeepenalty')}. "
            "The exact zero-fee package check is not a startup flag. Turning -subdustfeepenalty=0 would let a wider set into the mempool, and this node would relay all of them. "
            "The sidecar can leave only the whitelist unmarked so it can be mined, and mark the rest.",
        )
    if str(knots.get("mempooltruc")) != "enforce":
        add(
            rows,
            "blocked",
            "mempooltruc-enforce",
            f"Knots -mempooltruc={knots.get('mempooltruc')}. -mempooltruc=enforce is already in this binary. It is a startup change, not a rebuild. It is one node-wide relay and mine setting.",
        )
    return rows


def main() -> int:
    here = Path(__file__).resolve().parent
    rules_path = Path(sys.argv[1] if len(sys.argv) > 1 else here / "rules.json.example")
    conf_path = Path(sys.argv[2] if len(sys.argv) > 2 else "/mnt/Chain/knots-filter/bitcoin.conf")
    rules = __import__("json").loads(rules_path.read_text())
    knots = load_conf(conf_path)
    rows = classify(rules, knots)
    titles = {
        "knots": "Knots already enforces",
        "sidecar": "Sidecar only",
        "blocked": "Knots blocks first",
    }
    print(f"rules {rules_path}")
    print(f"knots {conf_path}")
    for key in ("knots", "sidecar", "blocked"):
        chosen = [row for row in rows if row[0] == key]
        print(f"\n{titles[key]} ({len(chosen)})")
        if not chosen:
            print("  none")
            continue
        for _bucket, name, detail in chosen:
            print(f"  {name}")
            print(f"    {detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
