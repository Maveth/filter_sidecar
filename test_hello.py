"""Two sidecars on localhost accept protocol 1 and refuse a different one."""
import json
import socket
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from hello import PROTO, Directory, outbound_sidecar_addrs, package_id, probe_is_due, shareable_address, write_hello


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class HelloTest(unittest.TestCase):
    def test_outbound_probe_uses_port_plus_four_and_skips_inbound(self):
        addrs = outbound_sidecar_addrs([
            {"addr": "127.0.0.1:28333", "inbound": False},
            {"addr": "203.0.113.8:8333", "inbound": True},
        ])
        self.assertEqual(addrs, ["127.0.0.1:28337"])
        chosen = outbound_sidecar_addrs([{"addr": "203.0.113.8:8333", "inbound": False}], 2)
        self.assertEqual(chosen, ["203.0.113.8:8335"])

    def test_announced_address_is_shared_and_a_probe_waits_an_hour(self):
        self.assertFalse(shareable_address("127.0.0.1:28335"))
        self.assertFalse(shareable_address("0.0.0.0:8337"))
        self.assertTrue(shareable_address("203.0.113.5:8337"))
        self.assertFalse(probe_is_due(1000, 1000 + 3599))
        self.assertTrue(probe_is_due(1000, 1000 + 3600))
        with TemporaryDirectory() as tmp:
            directory = Directory("local", "127.0.0.1:28335", 1, Path(tmp) / "peers.json", announce="203.0.113.9:8337")
            directory.peers["34.72.58.183:8337"] = {"address": "34.72.58.183:8337", "accept": True}
            directory.set_identity("harbor", "198.51.100.8:9337")
            self.assertEqual(directory._hello()["name"], "harbor")
            self.assertEqual(directory._hello()["listen"], "198.51.100.8:9337")
            directory.set_identity("harbor", "0.0.0.0:9337")
            self.assertEqual(directory._hello()["listen"], "198.51.100.8:9337")
            self.assertEqual(directory.known_addresses(), ["198.51.100.8:9337", "34.72.58.183:8337"])
            self.assertEqual(directory._hello()["known"], ["198.51.100.8:9337", "34.72.58.183:8337"])

    def test_matching_proto_is_accepted_and_a_mismatch_is_refused(self):
        with TemporaryDirectory() as tmp:
            left_port = free_port()
            right_port = free_port()
            root = Path(tmp)
            left = Directory("local", f"127.0.0.1:{left_port}", 1, root / "local.peers.json")
            right = Directory("seed", f"127.0.0.1:{right_port}", 1, root / "seed.peers.json")
            left.inbox_path = root / "local.inbox.json"
            right.inbox_path = root / "seed.inbox.json"
            (root / "sift-local.json").write_text('{"accept_packages": true}\n')
            digest = right.add_package("WLS-1", "ab", "cd")
            left.catalog_shapes = [{"id": "cat21", "kind": "spam", "carry": "definition", "title": "CAT-21", "schema": {"locktime": 21}}]
            right.catalog_shapes = [
                {"id": "ark-exit", "kind": "whitelist", "carry": "package", "title": "Ark exit", "schema": {"parent": {"version": 3}}},
                {"id": "commitment-32", "kind": "whitelist", "carry": "definition", "title": "32-byte commitment", "schema": {}},
            ]
            left.start()
            right.start()
            time.sleep(0.2)
            self.assertTrue(right.dial(left.listen))
            time.sleep(0.3)
            got = json.loads((root / "local.inbox.json").read_text())["peers"]
            peer = next(iter(got.values()))
            self.assertEqual(peer["whitelist"][0]["id"], "ark-exit")
            self.assertIsNone(peer["whitelist"][0].get("parent"))
            self.assertEqual(left.packages[digest]["parent"], "ab")
            self.assertEqual(left.packages[digest]["id"], package_id("WLS-1", "ab", "cd"))
            left_traffic = json.loads((root / "local.peers.traffic.json").read_text())
            right_traffic = json.loads((root / "seed.peers.traffic.json").read_text())
            self.assertEqual(left_traffic["in"], [digest])
            self.assertEqual(right_traffic["out"], [digest])
            sent = right.sent_items
            self.assertGreater(sent, 0)
            self.assertTrue(right.dial(left.listen))
            time.sleep(0.3)
            self.assertEqual(right.sent_items, sent)
            bad_pkg = {"op": "package", "id": "0" * 64, "shape": "WLS-1", "parent": "ab", "child": "cd"}
            left.take_data({"listen": "203.0.113.8:8337", "name": "no"}, [bad_pkg])
            self.assertNotIn("0" * 64, left.packages)
            self.assertFalse(peer["whitelist"][0]["enabled"])
            back = json.loads((root / "seed.inbox.json").read_text())["peers"]
            returned = next(iter(back.values()))
            self.assertEqual(returned["shapes"][0]["id"], "cat21")
            self.assertFalse(returned["shapes"][0]["enabled"])
            seen = json.loads((root / "local.peers.json").read_text())
            names = {row["name"] for row in seen["peers"] if row.get("accept")}
            self.assertIn("seed", names)
            self.assertEqual(seen["self"]["proto"], PROTO)
            time.sleep(0.4)
            local_row = next(row for row in json.loads((root / "local.peers.json").read_text())["peers"] if row.get("name") == "seed")
            seed_row = next(row for row in json.loads((root / "seed.peers.json").read_text())["peers"] if row.get("name") == "local")
            self.assertEqual(local_row["directions"], ["in", "out"])
            self.assertEqual(seed_row["directions"], ["in", "out"])
            bad = socket.create_connection(("127.0.0.1", left_port), timeout=2)
            try:
                write_hello(bad, {"op": "hello", "proto": 99, "listen": "127.0.0.1:9", "name": "old", "catalog": 1, "carries": []})
                reply = json.loads(bad.recv(1024).decode().splitlines()[0])
            finally:
                bad.close()
            self.assertFalse(reply["accept"])
            self.assertEqual(reply["reason"], "proto")
            left.stop()
            right.stop()


class OfferTest(unittest.TestCase):
    def test_a_private_shape_is_not_offered(self):
        with TemporaryDirectory() as tmp:
            directory = Directory("local", "127.0.0.1:1", 1, Path(tmp) / "peers.json")
            directory.catalog_shapes = [
                {"id": "mine", "kind": "spam", "title": "Mine", "transfer": False},
                {"id": "ark-exit", "kind": "whitelist", "title": "Ark exit"},
            ]
            offer = directory.offer_for(["spam", "whitelist"])
            self.assertEqual([row["id"] for row in offer["shapes"]], [])
            self.assertEqual([row["id"] for row in offer["whitelist"]], ["ark-exit"])

    def test_shape_text_is_not_offered_as_code(self):
        with TemporaryDirectory() as tmp:
            directory = Directory("local", "127.0.0.1:1", 1, Path(tmp) / "peers.json")
            directory.catalog_shapes = [
                {
                    "id": "WLS-2",
                    "slug": "package-paid",
                    "kind": "whitelist",
                    "checker": "package-paid",
                    "code": "import os; os.system('x')",
                    "title": "Package-paid",
                },
                {
                    "id": "SFS-99",
                    "kind": "spam",
                    "checker": "print('no')",
                    "code": "exec('1')",
                    "title": "Bad",
                },
            ]
            offer = directory.offer_for(["spam", "whitelist"])
            rows = offer["shapes"] + offer["whitelist"]
            self.assertTrue(rows)
            self.assertTrue(all("code" not in row for row in rows))
            self.assertEqual(offer["whitelist"][0]["checker"], "package-paid")
            self.assertNotIn("checker", offer["shapes"][0])


if __name__ == "__main__":
    unittest.main()
