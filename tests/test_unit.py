"""Unit tests: Ed25519 vectors, canonical JSON, chain rules, store semantics."""

import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from app import demo
from app.chain import evaluate, format_time
from app.crypto import (
    JsonError,
    canonical,
    ed25519_public_key,
    ed25519_sign,
    ed25519_verify,
    sha256_hex,
    strict_loads,
)
from app.store import Store

NOW = datetime.now(timezone.utc)


class Ed25519Test(unittest.TestCase):
    def test_rfc8032_vector_2_sign_and_derive(self):
        seed = bytes.fromhex(
            "4ccd089b28ff96da9db6c346ec114e0f"
            "5b8a319f35aba624da8cf6ed4fb8a6fb"
        )
        public = ed25519_public_key(seed)
        self.assertEqual(
            public.hex(),
            "3d4017c3e843895a92b70aa74d1b7ebc"
            "9c982ccf2ec4968cc0cd55f12af4660c",
        )
        sig = ed25519_sign(seed, bytes.fromhex("72"))
        self.assertEqual(
            sig.hex(),
            "92a009a9f0d4cab8720e820b5f642540"
            "a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c"
            "387b2eaeb4302aeeb00d291612bb0c00",
        )

    def test_rfc8032_vector_1_verify(self):
        public = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a"
            "0ee172f3daa62325af021a68f707511a"
        )
        sig = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a"
            "84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46b"
            "d25bf5f0595bbe24655141438e7a100b"
        )
        self.assertTrue(ed25519_verify(public, sig, b""))
        self.assertFalse(ed25519_verify(public, sig, b"x"))

    def test_roundtrip_and_tamper(self):
        seed = os.urandom(32)
        public = ed25519_public_key(seed)
        sig = ed25519_sign(seed, b"hello")
        self.assertTrue(ed25519_verify(public, sig, b"hello"))
        self.assertFalse(ed25519_verify(public, sig, b"hellp"))
        bad = bytearray(sig)
        bad[10] ^= 1
        self.assertFalse(ed25519_verify(public, bytes(bad), b"hello"))


class JsonTest(unittest.TestCase):
    def test_canonical_sorted_and_utf8(self):
        obj = {"b": 1, "a": "泵"}
        self.assertEqual(canonical(obj), '{"a":"泵","b":1}'.encode("utf-8"))

    def test_strict_loads_rejects_duplicate_keys(self):
        with self.assertRaises(JsonError):
            strict_loads(b'{"a":1,"a":2}')

    def test_strict_loads_rejects_bad_utf8(self):
        with self.assertRaises(JsonError):
            strict_loads(b'{"a":"\xff\xfe"}')

    def test_strict_loads_rejects_nan(self):
        with self.assertRaises(JsonError):
            strict_loads(b'{"a":NaN}')

    def test_strict_loads_ok(self):
        self.assertEqual(strict_loads('{"x":[1,2]}'.encode()), {"x": [1, 2]})


def valid_package():
    return demo.build_scenarios()["valid"]


class ChainEvalTest(unittest.TestCase):
    def setUp(self):
        self.roots = {demo.DEMO_ROOT_KEY}

    def evaluate(self, pkg, req):
        return evaluate(pkg, req, self.roots, now=NOW)

    def test_valid_chain_passes(self):
        sc = valid_package()
        rep = self.evaluate(sc["package"], sc["request"])
        self.assertTrue(rep.ok, rep.first_error)
        self.assertEqual(len(rep.levels), 3)
        self.assertTrue(all(l["signature_valid"] for l in rep.levels))
        self.assertIsNotNone(rep.verdict_key)

    def test_tampered_signed_field_rejected(self):
        sc = demo.build_scenarios()["tampered"]
        rep = self.evaluate(sc["package"], sc["request"])
        self.assertFalse(rep.ok)
        self.assertIn("签名", rep.first_error)

    def test_out_of_scope_command_rejected(self):
        sc = demo.build_scenarios()["out_of_scope"]
        rep = self.evaluate(sc["package"], sc["request"])
        self.assertFalse(rep.ok)
        self.assertIn("越权", rep.first_error)

    def test_out_of_scope_device_rejected(self):
        sc = valid_package()
        rep = self.evaluate(sc["package"], {"device": "pump-02", "command": "restart"})
        self.assertFalse(rep.ok)
        self.assertIn("超出叶级范围", rep.first_error)

    def test_expired_rejected(self):
        sc = demo.build_scenarios()["expired"]
        rep = self.evaluate(sc["package"], sc["request"])
        self.assertFalse(rep.ok)
        self.assertIn("过期", rep.first_error)

    def test_revoked_rejected(self):
        sc = demo.build_scenarios()["revoked"]
        rep = self.evaluate(sc["package"], sc["request"])
        self.assertFalse(rep.ok)
        self.assertIn("撤销", rep.first_error)

    def test_invalid_revocation_ignored(self):
        sc = valid_package()
        pkg = json.loads(json.dumps(sc["package"]))
        pkg["revocations"] = [
            {
                "payload": {
                    "type": "revocation",
                    "target_digest": rep_target(pkg),
                    "issued_at": format_time(NOW),
                },
                "public_key": demo.DEMO_ROOT_KEY,
                "signature": "00" * 64,
            }
        ]
        rep = self.evaluate(pkg, sc["request"])
        self.assertTrue(rep.ok, rep.first_error)
        self.assertEqual(len(rep.revocations), 1)
        self.assertFalse(rep.revocations[0]["valid"])

    def test_untrusted_root_rejected(self):
        sc = valid_package()
        rep = evaluate(sc["package"], sc["request"], {"ff" * 32}, now=NOW)
        self.assertFalse(rep.ok)
        self.assertIn("根公钥", rep.first_error)

    def test_widened_devices_rejected(self):
        sc = valid_package()
        pkg = json.loads(json.dumps(sc["package"]))
        # Re-sign leaf with widened device scope using the leaf seed so the
        # signature itself is valid; narrowing rule must still reject it.
        leaf = pkg["chain"][2]
        leaf["payload"]["devices"] = ["pump-01", "pump-02"]
        leaf["signature"] = __import__("app.crypto", fromlist=["ed25519_sign"]).ed25519_sign(
            demo.DEMO_LEAF_SEED, canonical(leaf["payload"])
        ).hex()
        rep = self.evaluate(pkg, sc["request"])
        self.assertFalse(rep.ok)
        self.assertIn("设备范围越界扩大", rep.first_error)

    def test_broken_parent_digest_rejected(self):
        sc = valid_package()
        pkg = json.loads(json.dumps(sc["package"]))
        pkg["chain"][1]["payload"]["parent_digest"] = "ab" * 32
        rep = self.evaluate(pkg, sc["request"])
        self.assertFalse(rep.ok)

    def test_verdict_key_depends_on_request(self):
        sc = valid_package()
        r1 = self.evaluate(sc["package"], sc["request"])
        other = dict(sc["request"], params={"delay_seconds": 6})
        r2 = self.evaluate(sc["package"], other)
        self.assertNotEqual(r1.verdict_key, r2.verdict_key)
        self.assertEqual(r1.leaf_key, r2.leaf_key)


def rep_target(pkg):
    from app.chain import item_digest

    return item_digest(pkg["chain"][1])


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = Store(self.dir)

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.dir)

    def _record(self, vk="v1", lk="l1"):
        return {
            "verdict_key": vk,
            "leaf_key": lk,
            "root_key": "r",
            "chain_digest": "c",
            "leaf_id": "leaf",
            "request": {"device": "d", "command": "c"},
            "request_hash": "h",
            "receipt": {"execution_id": "exec-1"},
            "created_at": "2026-10-06T00:00:00Z",
        }

    def test_insert_and_lookup(self):
        self.store.insert_verdict(self._record())
        self.assertEqual(self.store.get_by_verdict_key("v1"), {"execution_id": "exec-1"})
        self.assertTrue(self.store.leaf_used("l1"))
        self.assertFalse(self.store.leaf_used("nope"))

    def test_duplicate_verdict_key_rejected(self):
        import sqlite3

        self.store.insert_verdict(self._record())
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.insert_verdict(self._record())

    def test_duplicate_leaf_key_rejected(self):
        import sqlite3

        self.store.insert_verdict(self._record())
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.insert_verdict(self._record(vk="v2"))

    def test_persistence_across_reopen(self):
        self.store.insert_verdict(self._record())
        self.store.close()
        self.store = Store(self.dir)
        self.assertEqual(self.store.count(), 1)
        self.assertEqual(self.store.get_by_verdict_key("v1"), {"execution_id": "exec-1"})


if __name__ == "__main__":
    unittest.main()
