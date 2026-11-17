"""The sidecar decides from the rules file. It does not need a node for that."""
import json
import tempfile
import unittest
from pathlib import Path

import sidecar
import spamcore
from spamcore import tx_reject_reason, whitelist_items


def _tapscript_tx(script_len: int) -> bytes:
    script = b"\x51" * script_len
    control = b"\xc0" + b"\x11" * 32
    out = b"\x00\x14" + b"\x22" * 20
    raw = b"\x01\x00\x00\x00\x00\x01\x01"
    raw += b"\x00" * 32 + b"\x00\x00\x00\x00" + b"\x00" + b"\xff\xff\xff\xff"
    raw += b"\x01" + (1000).to_bytes(8, "little") + bytes([len(out)]) + out
    raw += b"\x02"
    raw += b"\xfd" + script_len.to_bytes(2, "little") + script
    raw += bytes([len(control)]) + control
    return raw + b"\x00\x00\x00\x00"


def _p2wsh_run(count: int, value: int) -> bytes:
    script = b"\x00\x20" + bytes(range(32))
    raw = b"\x01\x00\x00\x00" + bytes([1])
    raw += b"\x00" * 32 + b"\x00\x00\x00\x00" + b"\x00" + b"\xff\xff\xff\xff"
    raw += bytes([count])
    raw += (value.to_bytes(8, "little") + bytes([len(script)]) + script) * count
    return raw + b"\x00\x00\x00\x00"


def _item(data: bytes) -> bytes:
    size = len(data)
    if size < 0xFD:
        return bytes([size]) + data
    return b"\xfd" + size.to_bytes(2, "little") + data


def _witness_script_tx(script: bytes, output: bytes, satisfaction: list[bytes] | None = None, control: bytes | None = None) -> bytes:
    raw = b"\x02\x00\x00\x00\x00\x01\x01"
    raw += b"\x11" * 32 + b"\x00\x00\x00\x00" + b"\x00" + b"\xff\xff\xff\xff"
    raw += b"\x01" + (1000).to_bytes(8, "little") + _item(output)
    items = list(satisfaction or []) + [script]
    if control is not None:
        items.append(control)
    raw += bytes([len(items)])
    for item in items:
        raw += _item(item)
    return raw + b"\x00\x00\x00\x00"


def _sweep(payload: bytes, witnesses: list[list[bytes]], prev: tuple[bytes, int] | None = None, scriptsig: bytes = b"") -> bytes:
    prev_hash, vout = prev or (b"\x11" * 32, 0)
    raw = b"\x02\x00\x00\x00\x00\x01\x01"
    raw += prev_hash + vout.to_bytes(4, "little") + _item(scriptsig) + b"\xff\xff\xff\xff"
    script = b"\x6a" + bytes([len(payload)]) + payload
    raw += b"\x01" + (0).to_bytes(8, "little") + bytes([len(script)]) + script
    for items in witnesses:
        raw += bytes([len(items)])
        for item in items:
            raw += bytes([len(item)]) + item
    return raw + b"\x00\x00\x00\x00"


def _one_parent(scripts: list[bytes]) -> bytes:
    raw = b"\x01\x00\x00\x00\x01"
    raw += b"\x00" * 32 + b"\x00\x00\x00\x00" + b"\x00" + b"\xff\xff\xff\xff"
    raw += bytes([len(scripts)])
    for script in scripts:
        raw += (0).to_bytes(8, "little") + bytes([len(script)]) + script
    return raw + b"\x00\x00\x00\x00"


def _one_output(script: bytes) -> bytes:
    raw = b"\x01\x00\x00\x00" + bytes([1])
    raw += b"\x00" * 32 + b"\x00\x00\x00\x00" + b"\x00" + b"\xff\xff\xff\xff"
    raw += bytes([1]) + (1000).to_bytes(8, "little") + bytes([len(script)]) + script
    return raw + b"\x00\x00\x00\x00"


def _pay_many(outputs: int, inputs: int = 1, opreturns: int = 0, value: int = 1000) -> bytes:
    raw = b"\x01\x00\x00\x00" + bytes([inputs])
    raw += (b"\x00" * 32 + b"\x00\x00\x00\x00" + b"\x00" + b"\xff\xff\xff\xff") * inputs
    raw += bytes([outputs + opreturns])
    for i in range(outputs):
        script = b"\x00\x14" + bytes([i]) + b"\x11" * 19
        raw += value.to_bytes(8, "little") + bytes([len(script)]) + script
    for _ in range(opreturns):
        script = b"\x6a\x01\x01"
        raw += (0).to_bytes(8, "little") + bytes([len(script)]) + script
    return raw + b"\x00\x00\x00\x00"


class RulesTest(unittest.TestCase):
    def test_rules_file_is_what_the_checker_sees(self):
        op_return = bytes.fromhex(
            "02000000000100e1f505000000001976a914000000000000000000000000000000000000000088ac00000000"
        )
        # A one-input one-output payment is not spam under an empty ruleset.
        self.assertIsNone(tx_reject_reason(op_return, {}))

    def test_fanout_marks_many_kept_outputs_from_few_inputs(self):
        flags = {"rejectfanout": True, "fanout_outputs_min": 25, "fanout_inputs_max": 2}
        self.assertEqual(tx_reject_reason(_pay_many(25), flags), "fanout")
        self.assertIsNone(tx_reject_reason(_pay_many(24), flags))
        self.assertIsNone(tx_reject_reason(_pay_many(25, inputs=3), flags))
        self.assertIsNone(tx_reject_reason(_pay_many(24, opreturns=10), flags))
        self.assertIsNone(tx_reject_reason(_pay_many(25), {"rejectfanout": False, "fanout_outputs_min": 25, "fanout_inputs_max": 2}))

    def test_dust_spray_counts_outputs_under_the_line(self):
        flags = {"rejectdustspray": True, "dustspray_count_min": 10, "dustspray_sat_max": 1000}
        self.assertEqual(tx_reject_reason(_pay_many(10, value=999), flags), "dustspray")
        self.assertIsNone(tx_reject_reason(_pay_many(9, value=999), flags))
        self.assertIsNone(tx_reject_reason(_pay_many(10, value=1000), flags))
        self.assertIsNone(tx_reject_reason(_pay_many(10, value=0), flags))
        self.assertIsNone(tx_reject_reason(_pay_many(10, value=999), {"rejectdustspray": False}))

    def test_two_opreturns_are_a_stack(self):
        flags = {"rejectopreturnstack": True, "opreturn_count_min": 2}
        self.assertEqual(tx_reject_reason(_pay_many(0, opreturns=2), flags), "opreturnstack")
        self.assertIsNone(tx_reject_reason(_pay_many(0, opreturns=1), flags))

    def test_a_long_tapscript_is_heavy(self):
        flags = {"rejectheavytapscript": True, "tapscript_bytes_min": 521}
        self.assertEqual(tx_reject_reason(_tapscript_tx(521), flags), "heavytapscript")
        self.assertIsNone(tx_reject_reason(_tapscript_tx(520), flags))

    def test_p2wsh_run_uses_the_saved_count_and_sat_cap(self):
        flags = {"rejectfakeoutputs": True, "fakeoutput_count_min": 3, "fakeoutput_sat_max": 546}
        self.assertEqual(tx_reject_reason(_p2wsh_run(3, 546), flags), "fakeoutput")
        self.assertIsNone(tx_reject_reason(_p2wsh_run(2, 546), flags))
        self.assertIsNone(tx_reject_reason(_p2wsh_run(3, 547), flags))

    def test_empty_runestone_stays_when_the_whitelist_is_on(self):
        off = {"rejectrunestones": True, "whitelist_empty_runestone": False}
        on = {"rejectrunestones": True, "whitelist_empty_runestone": True}
        empty = _one_output(b"\x6a\x5d")
        real = _one_output(b"\x6a\x5d\x01\x00")
        self.assertEqual(tx_reject_reason(empty, off), "runestone")
        self.assertIsNone(tx_reject_reason(empty, on))
        self.assertEqual(tx_reject_reason(real, on), "runestone")

    def test_a_32_byte_commitment_is_not_data_carrier_spam(self):
        off = {"datacarrier": False, "whitelist_commitment_32": False}
        on = {"datacarrier": False, "whitelist_commitment_32": True}
        commit = _one_output(b"\x6a\x20" + b"\xab" * 32)
        self.assertEqual(tx_reject_reason(commit, off), "datacarrier")
        self.assertIsNone(tx_reject_reason(commit, on))

    def test_consolidation_is_not_dust(self):
        off = {"dust_sat_per_kvb": 3000, "whitelist_consolidation": False, "consolidation_inputs_min": 25, "consolidation_outputs_max": 3}
        on = dict(off, whitelist_consolidation=True)
        raw = _pay_many(1, inputs=25, value=1)
        self.assertEqual(tx_reject_reason(raw, off), "dust")
        self.assertIsNone(tx_reject_reason(raw, on))

    def test_sift_dust_line_can_be_turned_off(self):
        raw = _pay_many(1, value=1)
        on = {"dust_sat_per_kvb": 3000, "dust_sift": True}
        off = {"dust_sat_per_kvb": 3000, "dust_sift": False}
        self.assertEqual(tx_reject_reason(raw, on), "dust")
        self.assertIsNone(tx_reject_reason(raw, off))

    def test_swap_memo_prefix(self):
        raw = _one_output(b"\x6a\x04=:x\x00")
        self.assertEqual(tx_reject_reason(raw, {"rejectswapmemo": True}), "swapmemo")
        self.assertIsNone(tx_reject_reason(raw, {"rejectswapmemo": False}))

    def test_a_child_paying_the_package_clears_only_the_fee_mark(self):
        raw = _pay_many(1, value=10000)
        flags = {
            "minfee_sift": True,
            "minfeerate_sat_vb": 1,
            "whitelist_package_paid": True,
            "package_paid_sat_vb": 1,
        }
        self.assertEqual(tx_reject_reason(raw, flags, fee=10, weight=400), "minfeerate")
        self.assertIsNone(tx_reject_reason(
            raw, flags, fee=10, weight=400, package_fee_sat=300, package_vsize=100,
        ))
        dusty = dict(flags, dust_sift=True, dust_sat_per_kvb=3000)
        self.assertEqual(tx_reject_reason(
            _pay_many(1, value=1), dusty, fee=10, weight=400, package_fee_sat=300, package_vsize=100,
        ), "dust")
        self.assertEqual(whitelist_items(
            raw, flags, fee=10, weight=400, package_fee_sat=300, package_vsize=100,
        ), 1)

    def test_zero_fee_ark_parent_is_kept_and_a_high_fee_anchor_is_not(self):
        # version 3, one input, a 1-sat p2wpkh (dust) and one zero pay-to-anchor.
        raw = bytes.fromhex(
            "03000000"
            "01"
            + ("00" * 32)
            + "00000000"
            "00"
            "ffffffff"
            "02"
            "0100000000000000"
            "16"
            "0014"
            + ("00" * 20)
            + "0000000000000000"
            "04"
            "51024e73"
            "00000000"
        )
        flags = {"dust_sat_per_kvb": 30000, "datacarrier": False, "whitelist_ark_zero_anchor": True}
        self.assertIsNone(tx_reject_reason(raw, flags, fee=0))
        self.assertEqual(tx_reject_reason(raw, flags, fee=50_000), "dust")
        flags["whitelist_ark_zero_anchor"] = False
        self.assertEqual(tx_reject_reason(raw, flags, fee=0), "dust")

    def test_anchor_sweeps_use_the_parent_script(self):
        import hashlib
        from spamcore import ANCHOR_SCRIPT, prevout_scripts
        key = b"\x02" + b"\x11" * 32
        witness = b"\x21" + key + bytes.fromhex("ac736460b268")
        p2wsh = b"\x00\x20" + hashlib.sha256(witness).digest()
        signature = b"\x30" + b"\x22" * 70
        lightning = _sweep(b"abc", [[signature, witness]])
        on = {"datacarrier": False, "whitelist_lightning_anchor_sweep": True}
        self.assertIsNone(tx_reject_reason(lightning, on, prevouts=[p2wsh]))
        self.assertEqual(tx_reject_reason(lightning, {"datacarrier": False}, prevouts=[p2wsh]), "datacarrier")
        self.assertEqual(tx_reject_reason(lightning, on, prevouts=[ANCHOR_SCRIPT]), "datacarrier")
        self.assertEqual(tx_reject_reason(lightning, on), "datacarrier")
        self.assertEqual(tx_reject_reason(_sweep(b"abcd", [[signature, witness]]), on, prevouts=[p2wsh]), "datacarrier")
        p2a = _sweep(b"abcd", [[]])
        paid = {"datacarrier": False, "whitelist_p2a_sweep": True}
        self.assertIsNone(tx_reject_reason(p2a, paid, prevouts=[ANCHOR_SCRIPT]))
        self.assertEqual(tx_reject_reason(p2a, paid, prevouts=[p2wsh]), "datacarrier")
        self.assertEqual(tx_reject_reason(_sweep(b"abcde", [[]]), paid, prevouts=[ANCHOR_SCRIPT]), "datacarrier")
        self.assertEqual(whitelist_items(p2a, paid, prevouts=[ANCHOR_SCRIPT]), 1)
        bare = {"datacarrier": True, "permitbaredatacarrier": False, "whitelist_p2a_sweep": True}
        self.assertIsNone(tx_reject_reason(p2a, bare, prevouts=[ANCHOR_SCRIPT]))
        self.assertEqual(tx_reject_reason(p2a, {"datacarrier": True, "permitbaredatacarrier": False}, prevouts=[ANCHOR_SCRIPT]), "baredatacarrier")
        parent = _one_parent([b"\x00\x14" + b"\x22" * 20, ANCHOR_SCRIPT])
        spent = bytes.fromhex("33" * 32)
        looking = _sweep(b"ab", [[]], prev=(spent, 1))
        found = prevout_scripts(looking, lambda txid: parent.hex() if txid == spent[::-1].hex() else None)
        self.assertEqual(found, [ANCHOR_SCRIPT])
        redeem = p2wsh
        script_sig = bytes([len(redeem)]) + redeem
        nested = hashlib.new("ripemd160", hashlib.sha256(redeem).digest()).digest()
        p2sh = b"\xa9\x14" + nested + b"\x87"
        wrapped = _sweep(b"abc", [[signature, witness]], scriptsig=script_sig)
        self.assertIsNone(tx_reject_reason(wrapped, on, prevouts=[p2sh]))
        self.assertEqual(tx_reject_reason(wrapped, on, prevouts=[b"\x00"]), "datacarrier")
        control = b"\xc0" + b"\x22" * 32
        p2tr = b"\x51\x20" + b"\x33" * 32
        leaf = _sweep(b"ab", [[b"\x51", control]])
        self.assertIsNone(tx_reject_reason(leaf, paid, prevouts=[p2tr]))
        self.assertEqual(tx_reject_reason(leaf, paid, prevouts=[ANCHOR_SCRIPT]), "datacarrier")
        delay = _sweep(b"ab", [[b"\x60\xb2", control]])
        self.assertIsNone(tx_reject_reason(delay, paid, prevouts=[p2tr]))
        cltv = _sweep(b"ab", [[b"\x60\xb1", control]])
        self.assertIsNone(tx_reject_reason(cltv, paid, prevouts=[p2tr]))
        signed = _sweep(b"ab", [[b"\x11" * 64, b"\x60\xb2", control]])
        self.assertEqual(tx_reject_reason(signed, paid, prevouts=[p2tr]), "datacarrier")

    def test_powpeg_clears_only_the_fake_multisig_mark(self):
        def multisig(count: int) -> bytes:
            body = bytes([0x51])
            for n in range(count):
                body += b"\x21" + bytes([2]) + bytes([n + 1]) * 32
            return body + bytes([0x50 + count, 0xAE])

        peg = b"\x64" + multisig(11) + b"\x67\x60\xb2\x75" + multisig(2) + b"\x68"
        prefixed = b"\x20" + b"\xab" * 32 + b"\x75" + peg
        pay = b"\x00\x14" + b"\x22" * 20
        bare = multisig(11)
        on = {"rejectfakemultisig": True, "whitelist_powpeg": True, "datacarrier": True}
        self.assertIsNone(tx_reject_reason(_witness_script_tx(peg, pay), on))
        self.assertIsNone(tx_reject_reason(_witness_script_tx(prefixed, pay), on))
        self.assertEqual(tx_reject_reason(_witness_script_tx(peg, pay), {"rejectfakemultisig": True}), "fakemultisig")
        self.assertEqual(tx_reject_reason(_witness_script_tx(bare, pay), on), "fakemultisig")

    def test_an_unverified_key_is_marked_with_the_fake_multisig_check(self):
        key = b"\x21" + bytes([2]) + b"\x11" * 32
        guard = bytes.fromhex("749264") + key + bytes.fromhex("ac68") + key + bytes.fromhex("51ae")
        flags = {"sift_unverified_key": True}
        self.assertEqual(tx_reject_reason(_witness_script_tx(guard, b"\x00\x14" + b"\x22" * 20), flags), "unverifiedkey")
        dropped = key + bytes.fromhex("ac75")
        self.assertEqual(
            tx_reject_reason(_witness_script_tx(dropped, b"\x00\x14" + b"\x22" * 20, satisfaction=[b""]), flags),
            "unverifiedkey",
        )
        self.assertIsNone(tx_reject_reason(
            _witness_script_tx(dropped, b"\x00\x14" + b"\x22" * 20, satisfaction=[b"\x30" + b"\x11" * 70]),
            flags,
        ))
        leaf = b""
        for n in range(15):
            leaf += b"\x20" + bytes([n + 1]) * 32 + (b"\xac" if n == 0 else b"\xba")
        control = b"\xc0" + b"\x22" * 32
        pay = b"\x00\x14" + b"\x22" * 20
        attacked = _witness_script_tx(leaf, pay, satisfaction=[b"\x11" * 64], control=control)
        self.assertEqual(tx_reject_reason(attacked, flags), "unverifiedkey")
        honest = b"\x20" + b"\x01" * 32 + b"\xad" + b"\x20" + b"\x02" * 32 + b"\xac" + b"\x20" + b"\x03" * 32 + b"\xba"
        kept = _witness_script_tx(honest, pay, satisfaction=[b"\x11" * 64, b"\x22" * 64], control=control)
        self.assertIsNone(tx_reject_reason(kept, flags))
        self.assertIsNone(tx_reject_reason(attacked, {"rejectfakemultisig": True}))

    def test_a_low_fee_parent_with_a_paying_child_is_package_paid(self):
        self.assertTrue(spamcore.paid_by_descendant({}, 17, 155, 500, 200))
        self.assertFalse(spamcore.paid_by_descendant({}, 200, 100, 500, 200))
        on = {"whitelist_package_paid": True}
        self.assertTrue(spamcore.package_paid_clean(on, 17, 155, 500, 200, None))
        self.assertFalse(spamcore.package_paid_clean(on, 17, 155, 500, 200, "fakemultisig"))
        self.assertFalse(spamcore.package_paid_clean({}, 17, 155, 500, 200, None))

    def test_package_paid_lifts_a_clean_parent_and_not_a_spam_parent(self):
        clean = _pay_many(1, value=10000)
        spam = _pay_many(25, value=10000)
        clean_id = "aa" * 32
        spam_id = "bb" * 32
        mixed_id = "cc" * 32
        raws = {clean_id: clean.hex(), spam_id: spam.hex(), mixed_id: clean.hex()}
        kids = {clean_id: [], spam_id: [], mixed_id: [spam_id]}
        entry = {
            "fees": {"base": 0.00000017, "modified": 0.00000017, "descendant": 0.00000500},
            "vsize": 155,
            "weight": 620,
            "sigops": 1,
            "descendantcount": 2,
            "descendantsize": 200,
        }
        calls = []

        class Node:
            def call(self, method, params):
                calls.append((method, params))
                if method == "getrawmempool":
                    return [clean_id, spam_id, mixed_id]
                if method == "getmempoolentry":
                    return dict(entry)
                if method == "getrawtransaction":
                    return raws[params[0]]
                if method == "getmempooldescendants":
                    return list(kids.get(params[0], []))
                if method == "getprioritisedtransactions":
                    return {}
                return None

        flags = {
            "whitelist_package_paid": True,
            "package_paid_sat_vb": 1,
            "minfee_sift": False,
            "rejectfanout": True,
            "fanout_outputs_min": 25,
            "fanout_inputs_max": 2,
        }
        paid = []
        sidecar.scan(
            Node(), flags, sidecar.DEFAULT_DELTA, False, {}, {}, set(), set(), set(), True,
            None, paid, None, 1000,
        )
        boosts = [params for method, params in calls if method == "prioritisetransaction"]
        self.assertEqual(paid, [(clean.hex(), clean_id)])
        self.assertIn([clean_id, 0, 1000], boosts)
        self.assertNotIn([spam_id, 0, 1000], boosts)
        self.assertNotIn([mixed_id, 0, 1000], boosts)
        self.assertIn([spam_id, 0, sidecar.DEFAULT_DELTA], boosts)

    def test_a_whitelist_reverses_an_existing_spam_mark(self):
        clean = _pay_many(1, value=10000)
        clean_id = "aa" * 32
        base = 0.00000017
        marked_fee = base + sidecar.DEFAULT_DELTA / 100_000_000
        entry = {
            "fees": {"base": base, "modified": marked_fee, "descendant": 0.00000500},
            "vsize": 155,
            "weight": 620,
            "sigops": 1,
            "descendantcount": 2,
            "descendantsize": 200,
        }
        calls = []

        class Node:
            def call(self, method, params):
                calls.append((method, params))
                if method == "getrawmempool":
                    return [clean_id]
                if method == "getmempoolentry":
                    return dict(entry)
                if method == "getrawtransaction":
                    return clean.hex()
                if method == "getmempooldescendants":
                    return []
                if method == "getprioritisedtransactions":
                    return {clean_id: {"fee_delta": sidecar.DEFAULT_DELTA}}
                return None

        flags = {
            "whitelist_package_paid": True,
            "package_paid_sat_vb": 1,
            "minfee_sift": False,
        }
        sidecar.scan(
            Node(), flags, sidecar.DEFAULT_DELTA, False, {}, {}, set(), set(), set(), True,
            None, [], None, 1000,
        )
        boosts = [params for method, params in calls if method == "prioritisetransaction" and params[0] == clean_id]
        self.assertEqual(boosts, [[clean_id, 0, -sidecar.DEFAULT_DELTA + 1000]])

    def test_a_received_ark_set_is_inserted_parent_then_child(self):
        class Fake:
            def __init__(self):
                self.calls = []

            def call(self, method, params):
                self.calls.append((method, params))
                if method == "decoderawtransaction":
                    raw = params[0]
                    if raw == "aa":
                        return {"txid": "parent", "vin": [{"txid": "coin"}]}
                    return {"txid": "child", "vin": [{"txid": "parent"}]}
                if method == "sendrawtransaction":
                    return params[0]
                raise RuntimeError(f"{method}: unknown")

        node = Fake()
        result = sidecar.submit_package(node, {"shape": "WLS-1", "parent": "aa", "child": "bb", "extra": []})
        self.assertEqual(result, "added added")
        self.assertEqual(node.calls[2][0], "sendrawtransaction")
        self.assertEqual(node.calls[2][1][0], "aa")
        self.assertEqual(node.calls[2][1][3], sidecar.ARK_IGNORE)
        self.assertEqual(node.calls[3][1][0], "bb")
        self.assertEqual(node.calls[3][1][3], [])

        class Conflict(Fake):
            def call(self, method, params):
                if method == "sendrawtransaction":
                    raise RuntimeError("sendrawtransaction: txn-mempool-conflict")
                return super().call(method, params)

        stopped = sidecar.submit_package(Conflict(), {"shape": "WLS-1", "parent": "aa", "child": "bb", "extra": []})
        self.assertIn("conflict", stopped)
        self.assertTrue(stopped.endswith("stopped"))

    def test_ark_package_uses_the_anchor_child(self):
        from spamcore import ANCHOR_SCRIPT
        parent = _one_output(b"\x51\x20" + b"\x11" * 32)  # not the anchor; build a two-output tx below
        # parent spends nothing we care about; child spends vout 1 of txid 22..22
        child = _sweep(b"", [[]], prev=(bytes.fromhex("22" * 32), 1))
        parent_hex = (b"\x02\x00\x00\x00" + b"\x01" + b"\x11" * 32 + b"\x00\x00\x00\x00" + b"\x00" + b"\xff\xff\xff\xff"
            + b"\x02"
            + (1000).to_bytes(8, "little") + b"\x22" + b"\x51\x20" + b"\x33" * 32
            + (0).to_bytes(8, "little") + bytes([len(ANCHOR_SCRIPT)]) + ANCHOR_SCRIPT
            + b"\x00\x00\x00\x00").hex()

        class Fake:
            def call(self, method, params):
                return child.hex() if params[0] == "child" else "00"

        found = sidecar.anchor_child_hex(Fake(), "22" * 32, parent_hex, ["other", "child"])
        self.assertEqual(found, child.hex())

    def test_each_paid_chain_is_its_own_package(self):
        sets = sidecar.paid_sets({
            "parent-a": {"mid", "child-a"},
            "mid": {"child-a"},
            "parent-b": {"child-b"},
        })
        self.assertEqual(sets, [["parent-a", "child-a", "mid"], ["parent-b", "child-b"]])
        one = sidecar.paid_sets({"only": set()})
        self.assertEqual(one, [["only"]])

    def test_delta_must_be_negative(self):
        self.assertLess(sidecar.DEFAULT_DELTA, -(50 * 100_000_000))

    def test_whitelist_priority_tops_up_to_1000_once(self):
        self.assertEqual(sidecar.WHITELIST_DELTA, 1000)
        self.assertEqual(sidecar.priority_top_up(0, 1000), 1000)
        self.assertEqual(sidecar.priority_top_up(240, 1000), 760)
        self.assertEqual(sidecar.priority_top_up(1000, 1000), 0)
        self.assertEqual(sidecar.priority_top_up(1500, 1000), 0)
        spam = sidecar.DEFAULT_DELTA
        self.assertEqual(sidecar.whitelist_priority_add(0, 1000, spam), 1000)
        self.assertEqual(sidecar.whitelist_priority_add(-240, 1000, spam), 1240)
        self.assertEqual(sidecar.whitelist_priority_add(spam, 1000, spam), -spam + 1000)
        self.assertEqual(sidecar.whitelist_priority_add(spam * 4, 1000, spam), -spam * 4 + 1000)

    def test_a_child_is_marked_with_its_parent_and_unmarked_with_it(self):
        want = sidecar.wanted_marks(
            {"aa": "dust", "bb": None},
            {"aa": ["bb", "cc"]},
        )
        self.assertEqual(want, {"aa": "dust", "bb": "child of dust", "cc": "child of dust"})

    def test_turning_a_rule_off_removes_the_mark(self):
        txid = "ab" * 32
        calls = []

        class Node:
            def call(self, method, params):
                calls.append((method, params))
                if method == "getrawmempool":
                    return [txid]
                if method == "getmempoolentry":
                    return {"fees": {"base": 0.0001, "modified": 0.0001 - 10_000_000}, "weight": 400, "sigops": 1}
                if method == "getrawtransaction":
                    return "00"
                if method == "getmempooldescendants":
                    return []
                return None

        marked = {}
        sidecar.scan(Node(), {}, sidecar.DEFAULT_DELTA, False, {}, marked, set(), set(), set(), True)
        self.assertEqual(calls[-1][0], "prioritisetransaction")
        self.assertEqual(calls[-1][2] if False else calls[-1][1][2], -sidecar.DEFAULT_DELTA)
        self.assertEqual(marked, {})

    def test_reload_notices_a_new_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.json"
            path.write_text(json.dumps({"rejecttokens": False}))
            first = sidecar.rules_stamp(path)
            path.write_text(json.dumps({"rejecttokens": True}))
            second = sidecar.rules_stamp(path)
            self.assertNotEqual(first, second)
            self.assertTrue(sidecar.load_json(path)["rejecttokens"])


if __name__ == "__main__":
    unittest.main()
