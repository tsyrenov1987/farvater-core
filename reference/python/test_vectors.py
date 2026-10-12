"""Cross-implementation compatibility test for the Kilvater wire format.

It loads the golden vectors that the Go reference is also checked against
(kilvater/testdata/vectors.json) and asserts the independent Python
implementation (kilvater.py) reproduces every one of them from the frozen
inputs — the tag, the v2 key derivation, the frames and the address encoding.
Because both implementations assert against the one golden file, agreement here
proves they are byte-for-byte compatible.

Run: python3 -m unittest  (from reference/python/). Standard library only.
"""

import json
import os
import unittest

import kilvater as kv

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "..", "..", "kilvater", "testdata", "vectors.json")


def load():
    with open(VECTORS, "rb") as f:
        return json.load(f)


class TestVectors(unittest.TestCase):
    def setUp(self):
        self.v = load()

    def test_v1_tag(self):
        g = self.v["v1_tag"]
        key = bytes.fromhex(g["key"])
        nonce = bytes.fromhex(g["nonce"])
        ts8 = g["ts"].to_bytes(8, "big")

        self.assertEqual(kv.mac_v1(key, ts8, nonce, g["path"]).hex(), g["mac"])
        self.assertEqual((ts8 + nonce + kv.mac_v1(key, ts8, nonce, g["path"])).hex(), g["raw"])
        self.assertEqual(kv.new_tag_v1(key, g["path"], g["ts"], nonce), g["tag"])

    def test_v2_key_derivation(self):
        g = self.v["v2"]
        master = bytes.fromhex(g["master"])
        # The key id and the derived key must match the Go reference exactly, so
        # an issuer written in Python hands out keys a Go server re-derives.
        self.assertEqual(kv.key_id_for(master, g["subscriber"].encode()).hex(), g["key_id"])
        key_id = bytes.fromhex(g["key_id"])
        self.assertEqual(kv.derive_key(master, key_id).hex(), g["derived_key"])

    def test_v2_tag(self):
        g = self.v["v2"]
        key = bytes.fromhex(g["derived_key"])
        key_id = bytes.fromhex(g["key_id"])
        nonce = bytes.fromhex(g["nonce"])
        ts8 = g["ts"].to_bytes(8, "big")

        self.assertEqual(kv.mac_v2(key, key_id, ts8, nonce, g["path"]).hex(), g["mac"])
        self.assertEqual(kv.new_tag_v2(key_id, key, g["path"], g["ts"], nonce), g["tag"])

    def test_addr(self):
        g = self.v["addr"]
        self.assertEqual(kv.append_addr(g["hostport"]).hex(), g["hex"])
        host, rest = kv.parse_addr(bytes.fromhex(g["hex"]))
        self.assertEqual(host, g["hostport"])
        self.assertEqual(rest, b"")

    def test_frames_roundtrip(self):
        for f in self.v["frames"]:
            raw = bytes.fromhex(f["hex"])
            typ, body, rest = kv.read_frame(raw)
            self.assertEqual(typ, f["type"], f["name"])
            self.assertEqual(rest, b"", f["name"] + " trailing bytes")
            # Re-encoding the decoded frame must reproduce the golden bytes.
            self.assertEqual(kv.write_frame(typ, body).hex(), f["hex"], f["name"])


class TestVerify(unittest.TestCase):
    """The accept rules (spec §3) are reproduced too, not just the encoders."""

    def setUp(self):
        self.v = load()

    def test_verify_v1_accepts_and_checks_path(self):
        g = self.v["v1_tag"]
        key = bytes.fromhex(g["key"])
        self.assertEqual(kv.verify_v1([key], g["tag"], g["path"], g["ts"]), 0)
        # A tag made for one path must fail on another.
        self.assertEqual(kv.verify_v1([key], g["tag"], "/other", g["ts"]), -1)
        # Outside the ±120 s window it fails.
        self.assertEqual(kv.verify_v1([key], g["tag"], g["path"], g["ts"] + 1000), -1)

    def test_verify_v2_accepts_and_revokes(self):
        g = self.v["v2"]
        master = bytes.fromhex(g["master"])
        self.assertEqual(kv.verify_v2(master, set(), g["tag"], g["path"], g["ts"]), g["key_id"])
        self.assertIsNone(kv.verify_v2(master, {g["key_id"]}, g["tag"], g["path"], g["ts"]))
        self.assertIsNone(kv.verify_v2(master, set(), g["tag"], "/other", g["ts"]))


if __name__ == "__main__":
    unittest.main()
