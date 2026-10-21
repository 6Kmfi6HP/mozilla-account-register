"""import_bundles 的 argv 组装测试（不执行真正的 fxpool-proxy）。"""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import import_bundles

_UID = "0123456789abcdef0123456789abcdef"


class TestImportArgv(unittest.TestCase):
    def _bundle(self, directory: str) -> Path:
        path = Path(directory) / f"{_UID}.json"
        path.write_text(
            json.dumps(
                {
                    "schema": import_bundles._SCHEMA,
                    "email": "a@example.com",
                    "uid": _UID,
                    "session_token": "0" * 64,
                }
            ),
            encoding="utf-8",
        )
        return path

    def _run(self, argv):
        captured = []

        def _fake_run(args, capture_output=True, text=True, timeout=120):
            captured.append(args)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("import_bundles.subprocess.run", _fake_run):
            code = import_bundles.main(argv)
        return code, captured

    def test_account_mode_is_forwarded(self):
        with tempfile.TemporaryDirectory() as td:
            bundle_dir = os.path.join(td, "bundles")
            root = os.path.join(td, "root")
            os.makedirs(bundle_dir)
            os.makedirs(root)
            self._bundle(bundle_dir)
            code, captured = self._run(
                [
                    "--bundle-dir",
                    bundle_dir,
                    "--fxpool-root",
                    root,
                    "--fxpool-bin",
                    os.path.join(td, "fxpool-proxy"),
                    "--account-mode",
                    "rr",
                    "--keep",
                ]
            )
        self.assertEqual(code, 0)
        self.assertEqual(len(captured), 1)
        args = captured[0]
        self.assertEqual(args[args.index("--account-mode") + 1], "rr")
        self.assertIn("--no-verify", args)
        self.assertNotIn("--delete-source", args)

    def test_account_mode_is_absent_by_default(self):
        # 单账号模式保持原有行为：不额外传 --account-mode
        with tempfile.TemporaryDirectory() as td:
            bundle_dir = os.path.join(td, "bundles")
            root = os.path.join(td, "root")
            os.makedirs(bundle_dir)
            os.makedirs(root)
            self._bundle(bundle_dir)
            _code, captured = self._run(
                [
                    "--bundle-dir",
                    bundle_dir,
                    "--fxpool-root",
                    root,
                    "--fxpool-bin",
                    os.path.join(td, "fxpool-proxy"),
                ]
            )
        self.assertNotIn("--account-mode", captured[0])
        self.assertIn("--delete-source", captured[0])


if __name__ == "__main__":
    unittest.main()
