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
