"""fxpool_bridge 的离线单元测试（stdlib/unittest，无网络、无浏览器依赖）。

覆盖 Go 导入器依赖的字节级契约：bundle 的键与顺序、indent=2 + 结尾换行、
renewal_credentials.json 的紧凑 JSON 与数字 schema、0600/0700 权限、
同 uid 覆盖、不同 uid 拒绝、损坏文件改名、以及 ~ 展开。
"""
import json
import os
import stat
import tempfile
import unittest
from unittest import mock

import fxpool_bridge

EMAIL = "user@example.org"
UID = "00112233445566778899aabbccddeeff"
UID2 = "ffeeddccbbaa99887766554433221100"
TOKEN = "0123456789abcdef" * 4  # 64 hex chars
TOKEN2 = "fedcba9876543210" * 4


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class TestBuildBundle(unittest.TestCase):
    def test_exact_keys_and_order(self):
        bundle = fxpool_bridge.build_bundle(EMAIL, UID.upper(), TOKEN.upper())
        self.assertEqual(list(bundle.keys()), ["schema", "email", "uid", "session_token"])
        self.assertEqual(bundle["schema"], fxpool_bridge.BUNDLE_SCHEMA)
        self.assertEqual(bundle["email"], EMAIL)
        self.assertEqual(bundle["uid"], UID)
        self.assertEqual(bundle["session_token"], TOKEN)
        self.assertNotIn("password", bundle)

    def test_invalid_inputs_raise_and_never_echo_token(self):
        bad_token = "zz" * 32
        with self.assertRaises(fxpool_bridge.BridgeError) as ctx:
            fxpool_bridge.build_bundle(EMAIL, UID, bad_token)
        self.assertNotIn(bad_token, str(ctx.exception))
        with self.assertRaises(fxpool_bridge.BridgeError):
            fxpool_bridge.build_bundle(EMAIL, "nothex", TOKEN)
        with self.assertRaises(fxpool_bridge.BridgeError):
            fxpool_bridge.build_bundle("no-at-sign", UID, TOKEN)


class TestWriteBundle(unittest.TestCase):
    def test_bytes_and_mode(self):
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "bundles", UID + ".json")
            out = fxpool_bridge.write_bundle(target, EMAIL, UID, TOKEN)
            self.assertEqual(out, os.path.abspath(target))
            with open(target, "rb") as handle:
                raw = handle.read()
            expected = (
                json.dumps(
                    fxpool_bridge.build_bundle(EMAIL, UID, TOKEN),
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n"
            ).encode("utf-8")
            self.assertEqual(raw, expected)
            self.assertEqual(_mode(target), 0o600)
            # 目录由模块创建时必须没有 group/other 权限。
            self.assertEqual(_mode(os.path.dirname(target)) & 0o077, 0)

    def test_expanduser_bundle_dir(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"HOME": td}):
                paths = fxpool_bridge.publish_credentials(
                    EMAIL, UID, TOKEN, bundle_dir="~/pool-bundles"
                )
            self.assertEqual(
                paths["bundle_path"],
                os.path.join(td, "pool-bundles", UID + ".json"),
            )
            self.assertTrue(os.path.isfile(paths["bundle_path"]))


class TestPublishRenewalCredentials(unittest.TestCase):
    def test_compact_bytes_numeric_schema_and_modes(self):
        with tempfile.TemporaryDirectory() as td:
            root = os.path.join(td, "fxpool")
            path = fxpool_bridge.publish_renewal_credentials(
                root, EMAIL, UID, TOKEN
            )
            self.assertEqual(
                path, os.path.join(os.path.abspath(root), "tokens", "renewal_credentials.json")
            )
            with open(path, "rb") as handle:
                raw = handle.read()
            payload = {
                "schema": 1,
                "email": EMAIL,
                "uid": UID,
                "session_token": TOKEN,
            }
            expected = (
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
            ).encode("utf-8")
            self.assertEqual(raw, expected)
            decoded = json.loads(raw)
            self.assertIsInstance(decoded["schema"], int)
            self.assertEqual(decoded["schema"], 1)
            self.assertEqual(_mode(path), 0o600)
            self.assertEqual(_mode(root) & 0o077, 0)
            self.assertEqual(_mode(os.path.join(root, "tokens")) & 0o077, 0)

    def test_same_uid_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            root = os.path.join(td, "fxpool")
            first = fxpool_bridge.publish_renewal_credentials(root, EMAIL, UID, TOKEN)
            second = fxpool_bridge.publish_renewal_credentials(root, EMAIL, UID, TOKEN2)
            self.assertEqual(first, second)
            with open(second, encoding="utf-8") as handle:
                decoded = json.load(handle)
            self.assertEqual(decoded["session_token"], TOKEN2)

    def test_different_uid_is_refused_and_file_untouched(self):
        with tempfile.TemporaryDirectory() as td:
            root = os.path.join(td, "fxpool")
            path = fxpool_bridge.publish_renewal_credentials(root, EMAIL, UID, TOKEN)
            with open(path, "rb") as handle:
                before = handle.read()
            with self.assertRaises(fxpool_bridge.BridgeError) as ctx:
                fxpool_bridge.publish_renewal_credentials(root, EMAIL, UID2, TOKEN2)
            self.assertIn(UID, str(ctx.exception))
            self.assertNotIn(TOKEN, str(ctx.exception))
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), before)

    def test_invalid_existing_file_is_renamed_aside(self):
        with tempfile.TemporaryDirectory() as td:
            root = os.path.join(td, "fxpool")
            tokens = os.path.join(root, "tokens")
            os.makedirs(tokens, mode=0o700)
            target = os.path.join(tokens, "renewal_credentials.json")
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("{not json")
            path = fxpool_bridge.publish_renewal_credentials(root, EMAIL, UID, TOKEN)
            self.assertEqual(path, target)
            backups = [
                name
                for name in os.listdir(tokens)
                if name.startswith("renewal_credentials.json.bak-invalid-")
            ]
            self.assertEqual(len(backups), 1)
            with open(path, encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["uid"], UID)

    def test_expanduser_fxpool_root(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"HOME": td}):
                path = fxpool_bridge.publish_renewal_credentials(
                    "~/pool", EMAIL, UID, TOKEN
                )
            self.assertEqual(
                path,
                os.path.join(td, "pool", "tokens", "renewal_credentials.json"),
            )
            self.assertTrue(os.path.isfile(path))

    def test_publish_credentials_requires_a_target(self):
        with self.assertRaises(fxpool_bridge.BridgeError):
            fxpool_bridge.publish_credentials(EMAIL, UID, TOKEN)


if __name__ == "__main__":
    unittest.main()
