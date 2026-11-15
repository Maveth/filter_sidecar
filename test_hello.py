"""Two sidecars on localhost accept protocol 1 and refuse a different one."""
import json
import socket
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from hello import PROTO, Directory, outbound_sidecar_addrs, write_hello


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class HelloTest(unittest.TestCase):
    def test_outbound_probe_uses_port_plus_two_and_skips_inbound(self):
        addrs = outbound_sidecar_addrs([
            {"addr": "127.0.0.1:28333", "inbound": False},
            {"addr": "10.0.0.8:8333", "inbound": True},
        ])
        self.assertEqual(addrs, ["127.0.0.1:28335"])

    def test_matching_proto_is_accepted_and_a_mismatch_is_refused(self):
        with TemporaryDirectory() as tmp:
            left_port = free_port()
            right_port = free_port()
            root = Path(tmp)
            left = Directory("local", f"127.0.0.1:{left_port}", 1, root / "local.peers.json")
            right = Directory("seed", f"127.0.0.1:{right_port}", 1, root / "seed.peers.json")
            left.inbox_path = root / "local.inbox.json"
            right.inbox_path = root / "seed.inbox.json"
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
            self.assertIsNone(peer["whitelist"][0]["parent"])
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


if __name__ == "__main__":
    unittest.main()
