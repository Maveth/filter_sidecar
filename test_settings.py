"""The settings page checks rules and explains the Knots lines."""
import json
import threading
import unittest
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

import settings
import ui


class NoticeTest(unittest.TestCase):
    def test_whitelist_off_has_no_knots_notice(self):
        self.assertIsNone(settings.knots_notice(False))

    def test_whitelist_on_names_the_startup_lines(self):
        notice = settings.knots_notice(True)
        conf = "\n".join(line["conf"] for line in notice["lines"])
        for required in (
            "permitephemeral=anchor,-send,dust",
            "subdustfeepenalty=0",
            "mempooltruc=enforce",
            "minrelaytxfee=0.00000100",
            "dustrelayfee=0.00003000",
        ):
            self.assertIn(required, conf)
        self.assertIn("does not write", notice["summary"])
        self.assertIn("relay", notice["summary"])

    def test_normalize_rejects_a_bad_whitelist_and_keeps_extra_keys(self):
        previous = {"custom": 1}
        incoming = {field["key"]: False if field["type"] == "bool" else 1 for field in settings.RULE_FIELDS}
        incoming["dust_sat_per_kvb"] = None
        incoming["minfeerate_sat_vb"] = None
        incoming["whitelist_ark_zero_anchor"] = True
        rules = settings.normalize_rules(incoming, previous)
        self.assertTrue(rules["whitelist_ark_zero_anchor"])
        self.assertEqual(rules["custom"], 1)
        incoming["dust_sat_per_kvb"] = -1
        with self.assertRaises(ValueError):
            settings.normalize_rules(incoming, previous)


class PageTest(unittest.TestCase):
    def test_page_serves_rules_and_saves_them(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.json"
            path.write_text(Path("rules.json.example").read_text())
            ui.Handler.rules_path = path
            server = ui.ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                page = urllib.request.urlopen(f"http://127.0.0.1:{port}/").read().decode()
                self.assertIn("Sidecar settings", page)
                self.assertIn("whitelist_ark_zero_anchor", page)
                meta = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/api/meta"))
                self.assertTrue(meta["rules"]["whitelist_ark_zero_anchor"])
                self.assertIn("permitephemeral=anchor,-send,dust", meta["knots"]["lines"][0]["conf"])
                body = json.dumps(meta["rules"]).encode()
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/rules",
                    data=body,
                    headers={"content-type": "application/json"},
                )
                saved = json.load(urllib.request.urlopen(request))
                self.assertIsNotNone(saved["notice"])
                self.assertIn("whitelist_ark_zero_anchor", path.read_text())
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
