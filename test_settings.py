"""The settings page checks rules and explains the Knots lines."""
import json
import threading
import unittest
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

import board
import settings
import ui


class NoticeTest(unittest.TestCase):
    def test_whitelist_off_has_no_knots_notice(self):
        self.assertIsNone(settings.knots_notice(False))

    def test_whitelist_on_names_the_startup_lines(self):
        notice = settings.knots_notice(True)
        conf = "\n".join(line["conf"] for line in notice["lines"])
        for required in (
            "sendrawtransaction <parent-hex>",
            "ignore_rejects",
            "sendrawtransaction <child-hex>",
        ):
            self.assertIn(required, conf)
        self.assertIn("does not write", notice["summary"])
        self.assertIn("strict", notice["summary"])

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


class ShapeCardTest(unittest.TestCase):
    def test_knots_defaults_stay_on_and_fees_only_rise(self):
        rules = json.loads(Path("rules.json.example").read_text())
        shapes = board.load_shapes(Path("shapes.json"))
        node = {
            "rejectparasites": True,
            "rejectdeadbranches": True,
            "dust_sat_vb": 3.0,
            "dust_line": "dustrelayfee=0.00003000",
            "relay_sat_vb": 0.1,
            "relay_line": "minrelaytxfee=0.00000100",
            "mintx_sat_vb": 0.1,
            "mintx_line": "blockmintxfee=0.00000100",
            "lines": {"rejectparasites": "1", "rejectdeadbranches": "1"},
        }
        rows = {row.get("slug") or row["id"]: row for row in board.spam_cards(shapes, rules, node)}
        self.assertEqual(rows["cat21"]["id"], "SFS-1")
        self.assertEqual(rows["cat21"]["checker"], "cat21")
        self.assertNotIn("code", rows["cat21"])
        self.assertEqual(rows["fan-out"]["checker"], "fan-out")
        self.assertEqual(set(board.LIVE_RULE), __import__("spamcore").CHECKERS)
        self.assertEqual(rows["fan-out"]["id"], "SFS-30")
        self.assertEqual(rows["dust-spray"]["id"], "SFS-29")
        self.assertEqual(rows["min-fee"]["id"], "SFS-28")
        self.assertEqual(rows["many-sigs"]["id"], "SFS-31")
        watch = [shape["id"] for shape in shapes if shape.get("kind") == "watch"]
        self.assertEqual(watch, ["WCH-1", "WCH-2", "WCH-3", "WCH-4"])
        self.assertFalse((Path(__file__).resolve().parent / "shapes" / "opreturn-marker.json").exists())
        self.assertEqual(rows["cat21"]["control"], "locked")
        self.assertEqual(rows["cat21"]["conf"][0]["line"], "rejectparasites=1")
        self.assertTrue(rows["cat21"]["source_url"].startswith("https://"))
        self.assertEqual(rows["fake-multisig"]["control"], "bool")
        self.assertEqual(rows["dust-output"]["floor_sat_vb"], 3)
        self.assertTrue(rows["min-fee"]["below_default"])
        self.assertFalse(rows["min-fee"]["catalog"])
        self.assertEqual(rows["bare-inscription"]["control"], "bool")
        self.assertTrue(rows["bare-inscription"]["test"])
        self.assertEqual(rows["witness-unnamed"]["control"], "none")
        with self.assertRaises(ValueError):
            board.change_shape(rules, "cat21", {"active": False}, node)
        self.assertFalse(board.change_shape(rules, "json-token", {"active": False}, node)["rejecttokenmessages"])
        with self.assertRaises(ValueError):
            board.change_shape(rules, "dust-output", {"sat_vb": 3}, node)
        self.assertEqual(board.change_shape(rules, "dust-output", {"sat_vb": 4}, node)["dust_sat_per_kvb"], 4000)
        with self.assertRaises(ValueError):
            board.change_shape(rules, "min-fee", {"sat_vb": 0.1}, node)
        self.assertEqual(board.change_shape(rules, "min-fee", {"sat_vb": 1}, node)["minfeerate_sat_vb"], 1)
        loose = dict(node, rejectparasites=False)
        opened = {row.get("slug") or row["id"]: row for row in board.spam_cards(shapes, rules, loose)}
        self.assertEqual(opened["cat21"]["control"], "bool")
        self.assertFalse(rows["cat21"]["test"])
        self.assertEqual(rows["cat21"]["control"], "locked")
        self.assertTrue(rows["dust-output"]["test"])
        self.assertTrue(rows["dust-output"]["test"])
        self.assertEqual(rows["dust-output"]["options"][0]["key"], "permitephemeral")
        flags, reason = board.preview_flags(rules, "dust-output", 4)
        self.assertEqual(reason, "dust")
        self.assertEqual(flags["dust_sat_per_kvb"], 4000)
        self.assertFalse(flags["rejectparasites"])
        self.assertFalse(board.change_shape(rules, "dust-output", {"options": {"permitephemeral": False}}, node)["permitephemeral"])
        fan = rows["fan-out"]
        self.assertEqual(fan["control"], "bool")
        self.assertFalse(fan["active"])
        self.assertTrue(fan["test"])
        self.assertEqual([slider["key"] for slider in fan["sliders"]], ["fanout_outputs_min", "fanout_inputs_max"])
        turned = board.change_shape(rules, "fan-out", {"active": True, "sliders": {"fanout_outputs_min": 30, "fanout_inputs_max": 1}}, node)
        self.assertTrue(turned["rejectfanout"])
        self.assertEqual(turned["fanout_outputs_min"], 30)
        self.assertEqual(turned["fanout_inputs_max"], 1)
        preview, reason = board.preview_flags(rules, "fan-out", None, {"fanout_outputs_min": 10, "fanout_inputs_max": 2})
        self.assertEqual(reason, "fanout")
        self.assertTrue(preview["rejectfanout"])
        self.assertEqual(preview["fanout_outputs_min"], 10)
        self.assertFalse(preview["rejectparasites"])
        spray = rows["dust-spray"]
        self.assertEqual(spray["control"], "bool")
        self.assertFalse(spray["active"])
        self.assertTrue(spray["test"])
        self.assertEqual([slider["value"] for slider in spray["sliders"]], [10, 1000])
        self.assertFalse(rows["opreturn-stack"]["active"])
        self.assertEqual(rows["data-heavy"]["sliders"][0]["value"], 521)
        self.assertEqual([slider["value"] for slider in rows["dust-p2wsh-run"]["sliders"]], [3, 546])
        self.assertEqual([item["id"] for item in rows["dust-output"]["exempt"]], ["ark-exit", "consolidation"])
        self.assertEqual([item["id"] for item in rows["min-fee"]["exempt"]], ["ark-exit", "package-paid"])
        self.assertEqual([item["id"] for item in rows["runestone"]["exempt"]], ["empty-runestone"])
        listed = board.whitelist_cards(shapes, rules)[0]
        ark = next(row for row in listed if row.get("slug") == "ark-exit")
        self.assertEqual(ark["id"], "WLS-1")
        self.assertTrue(ark["active"])
        self.assertTrue(ark["test"])
        stone = next(row for row in listed if row.get("slug") == "empty-runestone")
        self.assertFalse(stone["active"])
        self.assertEqual(next(row for row in listed if row.get("slug") == "consolidation")["sliders"][0]["value"], 25)
        self.assertFalse(next(row for row in listed if row.get("slug") == "powpeg-flyover")["test"])
        paid = next(row for row in listed if row.get("slug") == "package-paid")
        self.assertEqual(paid["id"], "WLS-2")
        self.assertFalse(paid["active"])
        self.assertTrue(paid["test"])
        self.assertEqual(paid["sliders"][0]["value"], 1)
        self.assertFalse(board._silence({"rejectfanout": True}, "fanout")["rejectfanout"])
        self.assertEqual(board.clean_address("192.168.0.3:8335"), "192.168.0.3:8335")
        lines = __import__("settings").bitcoin_conf_lines({"rejectparasites": True, "rejectfanout": True, "dust_sift": True, "dust_sat_per_kvb": 3000, "minfee_sift": False})
        self.assertIn("rejectparasites=1", lines)
        self.assertIn("dustrelayfee=0.00003000", lines)
        self.assertFalse(any("fanout" in line for line in lines))
        self.assertEqual(board._silence({"dust_sift": True}, "dust")["dust_sift"], False)
        self.assertIsNone(board._silence({}, "not-a-reason"))


class MarkLogTest(unittest.TestCase):
    def test_mark_lines_keep_the_reason_and_skip_dry_run(self):
        text = "\n".join([
            "marked " + "ab" * 32 + " datacarrier delta=-1",
            "marked " + "cd" * 32 + " child of runestone delta=-1",
            "would mark " + "ef" * 32 + " dust delta=-1",
            "skip not-a-mark",
        ])
        rows = board.parse_marks(text)
        self.assertEqual([row["reason"] for row in rows], ["datacarrier", "child of runestone", "dust"])
        self.assertTrue(rows[2]["dry_run"])
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "sidecar.log"
            path.write_text(text)
            stopped = board.stopped_from_log(path)
        self.assertEqual(stopped["total"], 2)
        self.assertEqual({row["reason"]: row["count"] for row in stopped["by_reason"]}, {"datacarrier": 1, "child of runestone": 1})


class PageTest(unittest.TestCase):
    def test_page_serves_rules_and_saves_them(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.json"
            path.write_text(Path("rules.json.example").read_text())
            ui.Handler.rules_path = path
            ui.Handler.log_path = Path(tmp) / "sidecar.log"
            server = ui.ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                page = urllib.request.urlopen(f"http://127.0.0.1:{port}/settings").read().decode()
                self.assertIn("Sift settings", page)
                self.assertIn("Save rules", page)
                board_page = urllib.request.urlopen(f"http://127.0.0.1:{port}/").read().decode()
                self.assertIn("a spam filter and whitelist sidecar for Bitcoin nodes", board_page)
                self.assertIn("sticky-counts", board_page)
                self.assertIn('id="gear"', board_page)
                self.assertIn('id="conf-btn"', board_page)
                self.assertIn("Show current bitcoin.conf", board_page)
                self.assertIn('class="test" disabled', board_page)
                self.assertIn('id="ver"', board_page)
                self.assertIn('"total | blocked", "home"', board_page)
                view = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/api/board"))
                self.assertTrue(any(row.get("slug") == "ark-exit" and row["id"] == "WLS-1" and row["carry"] == "package" for row in view["whitelist"]))
                self.assertEqual(view["peers"], [])
                meta = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/api/meta"))
                self.assertTrue(meta["rules"]["whitelist_ark_zero_anchor"])
                self.assertIn("sendrawtransaction <parent-hex>", meta["knots"]["lines"][0]["conf"])
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
