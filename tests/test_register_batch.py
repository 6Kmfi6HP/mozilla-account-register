"""Network-free browser batch registration to fxpool bundle integration tests."""
import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from unittest import mock

import import_bundles
import mail_service
import register
import register_browser
import fxpool_bridge


EMAILS = ["first@example.test", "second@example.test"]
ACCOUNTS = {
    EMAILS[0]: {
        "uid": "00112233445566778899aabbccddeeff",
        "sessionToken": "0123456789abcdef" * 4,
    },
    EMAILS[1]: {
        "uid": "ffeeddccbbaa99887766554433221100",
        "sessionToken": "fedcba9876543210" * 4,
    },
}


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def _fake_register_one_browser(
    email,
    password,
    config,
    log_callback,
    on_account_created=None,
    **options,
):
    if on_account_created:
        on_account_created(email, password)
    account = ACCOUNTS[email]
    result = {
        "email": email,
        "password": password,
        "uid": account["uid"],
        "session_token": account["sessionToken"],
        "enrolled": False,
        "bundle_path": None,
        "credentials_path": None,
    }
    if options.get("bridge") and options.get("bundle_dir"):
        try:
            paths = fxpool_bridge.publish_credentials(
                email,
                account["uid"],
                account["sessionToken"],
                bundle_dir=options["bundle_dir"],
                fxpool_root=options.get("fxpool_root"),
            )
            result["bundle_path"] = paths.get("bundle_path")
        except Exception as exc:
            log_callback(f"[!] bridge: {exc}")
    return result


class TestRegisterBatchBundles(unittest.TestCase):
    def _config(self):
        return {
            "email_provider": "manual",
            "mail_timeout": 1,
            "mail_poll_interval": 1,
            "register_max_attempts": 1,
        }

    def _run_batch(self, temp_dir, fxpool_options, logs=None):
        if logs is None:
            logs = []
        with mock.patch.object(
            register_browser, "register_one_browser", side_effect=_fake_register_one_browser
        ), mock.patch.object(mail_service, "prepare_mail_baseline"):
            count = register.register_batch(
                EMAILS,
                self._config(),
                logs.append,
                account_path=os.path.join(temp_dir, "accounts.txt"),
                mail_credential_dir=temp_dir,
                threads=1,
                thread_start_interval=0,
                fxpool_options=fxpool_options,
            )
        return count

    def test_browser_batch_writes_importable_bundles(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = os.path.join(temp_dir, "bundles")
            fxpool_root = os.path.join(temp_dir, "fxpool")
            os.makedirs(fxpool_root)
            logs = []

            count = self._run_batch(
                temp_dir,
                {"bridge": True, "bundle_dir": bundle_dir},
                logs,
            )

            self.assertEqual(count, 2)
            expected_names = sorted(
                account["uid"] + ".json" for account in ACCOUNTS.values()
            )
            self.assertEqual(sorted(os.listdir(bundle_dir)), expected_names)
            for email in EMAILS:
                account = ACCOUNTS[email]
                path = os.path.join(bundle_dir, account["uid"] + ".json")
                with open(path, encoding="utf-8") as handle:
                    payload = json.load(handle)
                self.assertEqual(
                    set(payload), {"schema", "email", "uid", "session_token"}
                )
                self.assertEqual(
                    payload,
                    {
                        "schema": fxpool_bridge.BUNDLE_SCHEMA,
                        "email": email,
                        "uid": account["uid"],
                        "session_token": account["sessionToken"],
                    },
                )
                self.assertNotIn("password", payload)
                self.assertEqual(_mode(path), 0o600)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(
                    import_bundles.main(
                        [
                            "--bundle-dir",
                            bundle_dir,
                            "--fxpool-root",
                            fxpool_root,
                            "--dry-run",
                        ]
                    ),
                    0,
                )
            dry_run_output = output.getvalue()
            for name in expected_names:
                self.assertIn(name, dry_run_output)

    def test_disabled_bridge_and_no_target_do_not_write_bundles(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            for options in (
                {"bridge": False, "bundle_dir": os.path.join(temp_dir, "disabled")},
                {"bridge": True, "bundle_dir": None},
            ):
                with self.subTest(options=options):
                    if options["bundle_dir"]:
                        os.makedirs(options["bundle_dir"])
                    self.assertEqual(self._run_batch(temp_dir, options), 2)
                    if options["bundle_dir"]:
                        self.assertEqual(os.listdir(options["bundle_dir"]), [])

    def test_bundle_write_failure_keeps_registration_success(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_target = os.path.join(temp_dir, "not-a-directory")
            with open(bundle_target, "w", encoding="utf-8") as handle:
                handle.write("fixture")
            logs = []

            count = self._run_batch(
                temp_dir,
                {"bridge": True, "bundle_dir": bundle_target},
                logs,
            )

            self.assertEqual(count, 2)
            self.assertTrue(any("[!] bridge:" in line for line in logs))
            combined_logs = "\n".join(logs)
            for account in ACCOUNTS.values():
                self.assertNotIn(account["sessionToken"], combined_logs)


if __name__ == "__main__":
    unittest.main()
