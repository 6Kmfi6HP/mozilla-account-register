"""app_config / app_paths / account_outputs 的单元测试。"""
import os
import tempfile
import unittest

import app_config
import app_paths


class TestAppPaths(unittest.TestCase):
    def test_user_path_joins(self):
        p = app_paths.user_path("foo", "bar.txt")
        self.assertTrue(p.endswith(os.path.join("foo", "bar.txt")))

    def test_default_accounts_path(self):
        p = app_paths.default_accounts_path("20260802_100000")
        self.assertTrue(p.endswith("accounts_20260802_100000.txt"))


class TestConfig(unittest.TestCase):
    def tearDown(self):
        app_config.config = app_config.DEFAULT_CONFIG.copy()

    def test_load_missing_returns_defaults(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "config.json")
            cfg = app_config.load_config(path=path, validate=True)
            self.assertEqual(cfg["email_provider"], "cloudmail")

    def test_invalid_provider_rejected(self):
        app_config.config = dict(app_config.DEFAULT_CONFIG)
        app_config.config["email_provider"] = "bogus"
        with self.assertRaises(app_config.ConfigError):
            app_config.validate_config()

    def test_merge_with_defaults(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "config.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write('{"register_count": 7}')
            cfg = app_config.load_config(path=path)
            self.assertEqual(cfg["register_count"], 7)
            self.assertEqual(cfg["email_provider"], "cloudmail")


if __name__ == "__main__":
    unittest.main()
