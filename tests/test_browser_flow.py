"""浏览器后端的纯逻辑离线测试（不启动浏览器、不访问网络）。

覆盖：
- ``select_account_entry`` 的 uid/email/currentAccountUid/lastLogin 选择规则；
- ``_read_accounts_file`` 对 ``email----password[----extra]`` 的解析；
- 开通台账的一次性语义与 ``started`` 先于终态写入；
- ``register_backend`` 配置校验；
- ``register.py`` 不再因为 config 里的 fxpool_root 在 api 后端退出 2；
- 新增的验证码形状提取（6 位数字 / 8 位字母数字）。
"""
import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from unittest import mock

import account_outputs
import app_config
import mail_service
import register
import register_browser

UID_A = "00112233445566778899aabbccddeeff"
UID_B = "ffeeddccbbaa99887766554433221100"
TOKEN = "0123456789abcdef" * 4  # 64 hex chars


def _entry(uid, email="user@example.org", **extra):
    data = {"uid": uid, "email": email, "sessionToken": TOKEN}
    data.update(extra)
    return data


class TestSelectAccountEntry(unittest.TestCase):
    def test_sole_entry_fallback(self):
        raw = json.dumps({UID_A: _entry(UID_A)})
        got = register_browser.select_account_entry(raw)
        self.assertEqual(got["uid"], UID_A)
        self.assertEqual(got["email"], "user@example.org")
        self.assertEqual(got["session_token"], TOKEN)

    def test_uid_match_is_case_insensitive(self):
        raw = json.dumps({UID_A: _entry(UID_A), UID_B: _entry(UID_B, "b@example.org")})
        got = register_browser.select_account_entry(raw, uid=UID_A.upper())
        self.assertEqual(got["uid"], UID_A)

    def test_email_match_is_case_insensitive(self):
        raw = json.dumps({UID_A: _entry(UID_A, "User@Example.org")})
        got = register_browser.select_account_entry(raw, email="user@example.ORG")
        self.assertEqual(got["uid"], UID_A)

    def test_ambiguous_email_without_tiebreak_raises(self):
        raw = json.dumps(
            {
                UID_A: _entry(UID_A, "same@example.org"),
                UID_B: _entry(UID_B, "same@example.org"),
            }
        )
        with self.assertRaises(register_browser.BrowserRegisterError) as ctx:
            register_browser.select_account_entry(raw, email="same@example.org")
        self.assertIn("multiple stored accounts match email", str(ctx.exception))

    def test_last_login_breaks_email_tie(self):
        raw = json.dumps(
            {
                UID_A: _entry(UID_A, "same@example.org", lastLogin=100),
                UID_B: _entry(UID_B, "same@example.org", lastLogin=200),
            }
        )
        got = register_browser.select_account_entry(raw, email="same@example.org")
        self.assertEqual(got["uid"], UID_B)

    def test_current_uid_wins_even_with_older_last_login(self):
        raw = json.dumps(
            {
                UID_A: _entry(UID_A, "same@example.org", lastLogin=100),
                UID_B: _entry(UID_B, "same@example.org", lastLogin=200),
            }
        )
        got = register_browser.select_account_entry(
            raw, email="same@example.org", current_uid=UID_A
        )
        self.assertEqual(got["uid"], UID_A)

    def test_current_uid_without_email_field_still_matches(self):
        entry = _entry(UID_A)
        entry.pop("email")
        raw = json.dumps({UID_A: entry})
        got = register_browser.select_account_entry(
            raw, email="user@example.org", current_uid=UID_A
        )
        self.assertEqual(got["uid"], UID_A)

    def test_current_uid_may_be_json_quoted(self):
        raw = json.dumps({UID_A: _entry(UID_A), UID_B: _entry(UID_B)})
        got = register_browser.select_account_entry(
            raw, current_uid=json.dumps(UID_A)
        )
        self.assertEqual(got["uid"], UID_A)

    def test_sole_entry_without_email_field_falls_back(self):
        entry = _entry(UID_A)
        entry.pop("email")
        raw = json.dumps({UID_A: entry})
        got = register_browser.select_account_entry(raw, email="user@example.org")
        self.assertEqual(got["uid"], UID_A)
        self.assertEqual(got["email"], "user@example.org")

    def test_multiple_entries_without_hint_raises(self):
        raw = json.dumps({UID_A: _entry(UID_A), UID_B: _entry(UID_B)})
        with self.assertRaises(register_browser.BrowserRegisterError) as ctx:
            register_browser.select_account_entry(raw)
        self.assertIn("multiple stored accounts", str(ctx.exception))

    def test_bad_uid_hex_raises(self):
        raw = json.dumps({"nothex": {"uid": "nothex", "sessionToken": TOKEN}})
        with self.assertRaises(register_browser.BrowserRegisterError) as ctx:
            register_browser.select_account_entry(raw)
        self.assertIn("uid", str(ctx.exception))

    def test_bad_token_raises_without_echoing_it(self):
        bad_token = "zz" * 32
        raw = json.dumps({UID_A: {"uid": UID_A, "sessionToken": bad_token}})
        with self.assertRaises(register_browser.BrowserRegisterError) as ctx:
            register_browser.select_account_entry(raw)
        self.assertNotIn(bad_token, str(ctx.exception))

    def test_non_object_raises(self):
        with self.assertRaises(register_browser.BrowserRegisterError):
            register_browser.select_account_entry("[]")


class TestReadAccountsFile(unittest.TestCase):
    def _read(self, *lines):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "accounts.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + "\n")
            return register._read_accounts_file(path)

    def test_plain_pair(self):
        self.assertEqual(
            self._read("user@example.org----password"),
            [("user@example.org", "password")],
        )

    def test_splits_on_first_separator(self):
        self.assertEqual(
            self._read("user@example.org----pa----ss"),
            [("user@example.org", "pa----ss")],
        )

    def test_strips_browser_marker(self):
        self.assertEqual(
            self._read("user@example.org----password----browser-verified"),
            [("user@example.org", "password")],
        )

    def test_strips_created_unverified_marker(self):
        self.assertEqual(
            self._read("user@example.org----password----created-unverified"),
            [("user@example.org", "password")],
        )

    def test_strips_uid_marker(self):
        self.assertEqual(
            self._read(f"user@example.org----password----{UID_A}"),
            [("user@example.org", "password")],
        )

    def test_password_containing_separator_keeps_marker_stripping(self):
        self.assertEqual(
            self._read("user@example.org----pa----ss----browser-verified"),
            [("user@example.org", "pa----ss")],
        )

    def test_round_trip_with_append_account_line(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "accounts.txt")
            account_outputs.append_account_line(
                path, "user@example.org", "pa----ss", "browser-verified"
            )
            self.assertEqual(
                register._read_accounts_file(path),
                [("user@example.org", "pa----ss")],
            )

    def test_missing_separator_names_line(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "accounts.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("# comment\nuser@example.org\n")
            with self.assertRaises(ValueError) as ctx:
                register._read_accounts_file(path)
            self.assertIn("第 2 行", str(ctx.exception))


class TestEnrollmentLedger(unittest.TestCase):
    def test_one_shot_semantics_and_started_first(self):
        with tempfile.TemporaryDirectory() as td:
            ledger = os.path.join(td, "enrollment_attempts.txt")
            self.assertFalse(register_browser._enrollment_attempted(UID_A, ledger))
            register_browser._record_enrollment(UID_A, "started", ledger)
            self.assertTrue(register_browser._enrollment_attempted(UID_A, ledger))
            register_browser._record_enrollment(UID_A, "ok", ledger)
            self.assertTrue(register_browser._enrollment_attempted(UID_A, ledger))
            with open(ledger, encoding="utf-8") as handle:
                statuses = [line.rstrip("\n").split("\t")[1] for line in handle]
            self.assertEqual(statuses, ["started", "ok"])
            self.assertEqual(stat.S_IMODE(os.stat(ledger).st_mode), 0o600)

    def test_invalid_status_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError):
                register_browser._record_enrollment(
                    UID_A, "maybe", os.path.join(td, "ledger.txt")
                )


class TestConfigBackend(unittest.TestCase):
    def tearDown(self):
        app_config.config = app_config.DEFAULT_CONFIG.copy()

    def test_invalid_register_backend_rejected(self):
        cfg = dict(app_config.DEFAULT_CONFIG)
        cfg["register_backend"] = "chromium"
        with self.assertRaises(app_config.ConfigError):
            app_config.validate_config(cfg)

    def test_browser_backend_accepted(self):
        cfg = dict(app_config.DEFAULT_CONFIG)
        cfg["register_backend"] = "browser"
        app_config.validate_config(cfg)


class TestCliGuard(unittest.TestCase):
    def tearDown(self):
        app_config.config = app_config.DEFAULT_CONFIG.copy()

    def _run(self, config_data, *extra):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "config.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(config_data, handle)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = register.main(["--config", path, "--dry-run", *extra])
            return code, err.getvalue()

    def test_config_fxpool_root_is_inert_on_api_backend(self):
        code, _ = self._run({"fxpool_root": "/tmp/pool"})
        self.assertEqual(code, 0)

    def test_explicit_fxpool_root_requires_browser_backend(self):
        code, err = self._run({}, "--fxpool-root", "/tmp/pool")
        self.assertEqual(code, 2)
        self.assertIn("--backend browser", err)

    def test_config_enroll_requires_browser_backend(self):
        code, err = self._run({"fxpool_enroll": True})
        self.assertEqual(code, 2)
        self.assertIn("fxpool_enroll", err)


class _FakeResponse:
    def __init__(self, status=200, text=""):
        self.status = status
        self._text = text

    def text(self):
        return self._text


class _FakeEnrollPage:
    """最小 Playwright Page 替身：只实现 enroll_entitlement 用到的接口。"""

    def __init__(
        self,
        *,
        goto_response=None,
        goto_error=None,
        body="",
        final_url="https://vpn.mozilla.org/oauth/success?code=x&state=y",
    ):
        self._goto_response = goto_response
        self._goto_error = goto_error
        self._body = body
        self._final_url = final_url
        self.url = "https://accounts.firefox.com/authorization"
        self.goto_calls = 0

    def goto(self, url, timeout=None, wait_until=None):
        self.goto_calls += 1
        if self._goto_error is not None:
            raise self._goto_error
        return self._goto_response

    def wait_for_url(self, matcher, timeout=None):
        self.url = self._final_url
        if callable(matcher) and not matcher(self.url):
            raise RuntimeError("timeout")

    def inner_text(self, selector):
        return self._body


class TestEnrollEntitlement(unittest.TestCase):
    ENTITLEMENT = (
        '{"uid":8761116,"created_at":"2026-10-20T22:10:01.968Z",'
        '"limited_bandwidth":true}'
    )

    def _run(self, page):
        with tempfile.TemporaryDirectory() as td:
            ledger = os.path.join(td, "enrollment_attempts.txt")
            with mock.patch.object(
                register_browser, "_enrollment_ledger_path", return_value=ledger
            ):
                result = register_browser.enroll_entitlement(
                    page, UID_A, log_callback=lambda msg: None
                )
            with open(ledger, encoding="utf-8") as handle:
                statuses = [line.rstrip("\n").split("\t")[1] for line in handle]
            return result, statuses

    def test_parses_page_body_not_the_goto_html_response(self):
        # goto 返回的是 accounts.firefox.com 的 SPA HTML（非空），旧实现会先
        # 解析它并失败；正确实现读取 /oauth/success 的文档正文。
        page = _FakeEnrollPage(
            goto_response=_FakeResponse(200, "<html>accounts SPA</html>"),
            body=self.ENTITLEMENT,
        )
        result, statuses = self._run(page)
        self.assertTrue(result["enrolled"])
        self.assertEqual(result["entitlement"]["uid"], 8761116)
        self.assertTrue(result["entitlement"]["limited_bandwidth"])
        self.assertEqual(statuses, ["started", "ok"])

    def test_interrupted_goto_is_not_a_failure(self):
        page = _FakeEnrollPage(
            goto_error=RuntimeError(
                "Navigation to /api/v1/fpn/auth is interrupted by another navigation"
            ),
            body=self.ENTITLEMENT,
        )
        result, statuses = self._run(page)
        self.assertTrue(result["enrolled"])
        self.assertEqual(statuses, ["started", "ok"])

    def test_429_records_rate_limited_without_retry(self):
        page = _FakeEnrollPage(goto_response=_FakeResponse(429, ""))
        with tempfile.TemporaryDirectory() as td:
            ledger = os.path.join(td, "enrollment_attempts.txt")
            with mock.patch.object(
                register_browser, "_enrollment_ledger_path", return_value=ledger
            ):
                with self.assertRaises(register_browser.EnrollmentRateLimited):
                    register_browser.enroll_entitlement(
                        page, UID_A, log_callback=lambda msg: None
                    )
            self.assertEqual(page.goto_calls, 1)
            with open(ledger, encoding="utf-8") as handle:
                statuses = [line.rstrip("\n").split("\t")[1] for line in handle]
            self.assertEqual(statuses, ["started", "rate_limited"])

    def test_non_success_url_records_failed(self):
        page = _FakeEnrollPage(
            goto_response=_FakeResponse(200, "<html>accounts SPA</html>"),
            body="",
            final_url="https://accounts.firefox.com/authorization?prompt=none",
        )
        with tempfile.TemporaryDirectory() as td:
            ledger = os.path.join(td, "enrollment_attempts.txt")
            with mock.patch.object(
                register_browser, "_enrollment_ledger_path", return_value=ledger
            ):
                with self.assertRaises(register_browser.BrowserRegisterError) as ctx:
                    register_browser.enroll_entitlement(
                        page, UID_A, log_callback=lambda msg: None
                    )
            self.assertIn("stage=enroll", str(ctx.exception))
            with open(ledger, encoding="utf-8") as handle:
                statuses = [line.rstrip("\n").split("\t")[1] for line in handle]
            self.assertEqual(statuses, ["started", "failed"])


class TestMailBaseline(unittest.TestCase):
    OLD = {
        "emailId": "old-1",
        "toEmail": "user@example.org",
        "subject": "Use 111111 to confirm your account",
        "text": "Use 111111 to confirm your account",
    }
    NEW = {
        "emailId": "new-2",
        "toEmail": "user@example.org",
        "subject": "Use 222222 to sign in",
        "text": "Use 222222 to sign in",
    }

    def test_ignore_ids_skips_codes_already_in_the_mailbox(self):
        with mock.patch.object(
            mail_service, "cloudmail_get_messages", return_value=[self.OLD, self.NEW]
        ):
            code = mail_service.cloudmail_get_oai_code(
                None,
                "user@example.org",
                timeout=1,
                poll_interval=0,
                ignore_ids={"old-1"},
                code_shape="digits6",
            )
        self.assertEqual(code, "222222")

    def test_ignore_codes_skips_already_tried_codes(self):
        with mock.patch.object(
            mail_service, "cloudmail_get_messages", return_value=[self.OLD, self.NEW]
        ):
            code = mail_service.cloudmail_get_oai_code(
                None,
                "user@example.org",
                timeout=1,
                poll_interval=0,
                ignore_codes={"111111"},
                code_shape="digits6",
            )
        self.assertEqual(code, "222222")

    def test_snapshot_mail_ids(self):
        with mock.patch.object(
            mail_service, "cloudmail_get_messages", return_value=[self.OLD, self.NEW]
        ):
            ids = mail_service.snapshot_mail_ids("user@example.org")
        self.assertEqual(ids, {"old-1", "new-2"})


class TestExtractCodeShapes(unittest.TestCase):
    def test_digits6_accepts_signin_subject(self):
        self.assertEqual(
            mail_service.extract_code("", "Use 123456 to sign in", "digits6"),
            "123456",
        )

    def test_digits6_rejects_longer_number(self):
        self.assertIsNone(
            mail_service.extract_code("code is 12345678", "", "digits6")
        )

    def test_alnum8_unblock_body(self):
        text = "here is the authorization code you need: AB12CD34"
        self.assertEqual(mail_service.extract_code(text, "", "alnum8"), "AB12CD34")

    def test_alnum8_unblock_subject(self):
        self.assertEqual(
            mail_service.extract_code("", "Use AB12CD34 to sign in", "alnum8"),
            "AB12CD34",
        )

    def test_alnum8_grouped_form_is_compact(self):
        self.assertEqual(
            mail_service.extract_code("Use AB12-CD34 to sign in", "", "alnum8"),
            "AB12CD34",
        )

    def test_alnum8_does_not_match_plain_words(self):
        self.assertIsNone(
            mail_service.extract_code("Welcome to accounts", "", "alnum8")
        )

    def test_alnum8_rejects_numeric_dates(self):
        self.assertIsNone(mail_service.extract_code("sent 2026-1020", "", "alnum8"))


if __name__ == "__main__":
    unittest.main()
