"""The sidecar decides from the rules file. It does not need a node for that."""
import json
import tempfile
import unittest
from pathlib import Path

import sidecar
from spamcore import tx_reject_reason


class RulesTest(unittest.TestCase):
    def test_rules_file_is_what_the_checker_sees(self):
        op_return = bytes.fromhex(
            "02000000000100e1f505000000001976a914000000000000000000000000000000000000000088ac00000000"
        )
        # A one-input one-output payment is not spam under an empty ruleset.
        self.assertIsNone(tx_reject_reason(op_return, {}))

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

    def test_delta_must_be_negative(self):
        self.assertLess(sidecar.DEFAULT_DELTA, -(50 * 100_000_000))

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
