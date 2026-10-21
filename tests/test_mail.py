"""mail_service 验证码提取与 emailnator 状态管理的单元测试。"""
import json
import os
import re
import tempfile
import unittest
from unittest import mock

import mail_service
from mail_service import (
    extract_verification_code,
    normalize_mail_body,
    _is_transient_emailnator_error,
)


class TestExtractVerificationCode(unittest.TestCase):
    def test_mozilla_style_contextual(self):
        text = "Your Mozilla account verification code is 123456. It expires in 5 minutes."
        self.assertEqual(extract_verification_code(text, ""), "123456")

    def test_subject_contains_code(self):
        subject = "Verify your email: code 654321"
        self.assertEqual(extract_verification_code("", subject), "654321")

    def test_naked_six_digit(self):
        text = "Use this code to confirm: 987654"
        self.assertEqual(extract_verification_code(text, ""), "987654")

    def test_rejects_tracking_segment(self):
        # 不应把 URL/追踪段里的数字当验证码
        text = "Visit https://example.com/156-OFN to confirm. code is 555555"
        self.assertEqual(extract_verification_code(text, ""), "555555")

    def test_html_stripped(self):
        text = "<html><body>Your code is <b>333333</b></body></html>"
        self.assertEqual(extract_verification_code(text, ""), "333333")

    def test_no_code_returns_none(self):
        self.assertIsNone(extract_verification_code("Just a welcome email", "Welcome"))


class TestNormalizeMailBody(unittest.TestCase):
    def test_strips_html_and_urls(self):
        raw = {
            "html": "<html><style>.x{}</style><a href='https://example.com/foo'>click</a> Your code 123456</html>",
        }
        out = normalize_mail_body(raw)
        self.assertNotIn("https://", out)
        self.assertIn("123456", out)

    def test_multiple_sources_combined(self):
        raw = {"text": "part1", "snippet": "part2"}
        out = normalize_mail_body(raw)
        self.assertIn("part1", out)
        self.assertIn("part2", out)


class TestTransientErrorClassification(unittest.TestCase):
    def test_403_is_transient(self):
        # 代理出口突发 403：CLI 内部已重试 3 次，换进程再试是有效恢复
        self.assertTrue(
            _is_transient_emailnator_error("HTTPError: HTTP Error 403: Forbidden")
        )
        self.assertTrue(_is_transient_emailnator_error("Client Error: Forbidden"))

    def test_business_error_is_not_transient(self):
        self.assertFalse(
            _is_transient_emailnator_error("HTTPError: HTTP Error 422: Unprocessable")
        )
        self.assertFalse(_is_transient_emailnator_error("emailnator 未返回邮箱"))


class _StateDirMixin:
    """把 emailnator 状态目录指到临时目录。"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._saved = mail_service.config
        mail_service.config = {
            **mail_service.config,
            "email_provider": "emailnator",
            "emailnator_state_dir": self._tmp.name,
        }

    def tearDown(self):
        mail_service.config = self._saved
        self._tmp.cleanup()


class TestEmailnatorStateFiles(_StateDirMixin, unittest.TestCase):
    def test_state_file_is_per_address(self):
        a = mail_service.emailnator_state_file("jhnbsomers+apagu@gmail.com")
        b = mail_service.emailnator_state_file("kian.a.t.a.b.i.on@gmail.com")
        self.assertNotEqual(a, b)
        self.assertEqual(os.path.dirname(a), self._tmp.name)
        # 同一地址必须稳定（重试/换线程后仍能找到基线）
        self.assertEqual(a, mail_service.emailnator_state_file("jhnbsomers+apagu@gmail.com"))

    def test_distinct_addresses_never_share_a_file(self):
        # 清洗后可能同形（a.b / a+b），短哈希保证不撞名
        paths = {
            mail_service.emailnator_state_file(addr)
            for addr in (
                "a.b@gmail.com",
                "a+b@gmail.com",
                "ab@gmail.com",
                "A.B@GMAIL.COM",
            )
        }
        self.assertEqual(len(paths), 3)

    def test_seed_baseline_then_recorded(self):
        addr = "seed@gmail.com"
        self.assertFalse(mail_service.emailnator_baseline_recorded(addr))
        self.assertTrue(mail_service.emailnator_seed_baseline(addr, ["m1", "m2"]))
        self.assertTrue(mail_service.emailnator_baseline_recorded(addr))
        with open(mail_service.emailnator_state_file(addr), encoding="utf-8") as f:
            state = json.load(f)
        self.assertEqual(state[addr]["baseline"], ["m1", "m2"])
        self.assertEqual(state[addr]["codes"], [])

    def test_seed_does_not_overwrite_existing_baseline(self):
        addr = "keep@gmail.com"
        mail_service.emailnator_seed_baseline(addr, ["old"])
        self.assertFalse(mail_service.emailnator_seed_baseline(addr, ["new"]))
        with open(mail_service.emailnator_state_file(addr), encoding="utf-8") as f:
            self.assertEqual(json.load(f)[addr]["baseline"], ["old"])

    def test_empty_baseline_counts_as_recorded(self):
        # 全新地址本来就可能 0 封旧邮件：空列表也是合法基线
        addr = "virgin@gmail.com"
        mail_service.emailnator_seed_baseline(addr, [])
        self.assertTrue(mail_service.emailnator_baseline_recorded(addr))

    def test_missing_entry_is_not_a_baseline(self):
        # CLI 快照失败时不写条目 —— 必须能被区分出来
        addr = "nostate@gmail.com"
        with open(mail_service.emailnator_state_file(addr), "w", encoding="utf-8") as f:
            json.dump({}, f)
        self.assertFalse(mail_service.emailnator_baseline_recorded(addr))


class TestCodePattern(_StateDirMixin, unittest.TestCase):
    """严格模式必须命中 Mozilla 确认邮件、拒绝营销邮件。"""

    def _code(self, text, subject=""):
        pattern = mail_service.emailnator_code_pattern()
        for source in (subject, text):
            match = re.search(pattern, source, re.IGNORECASE)
            if match:
                return match.group(1) if match.groups() else match.group(0)
        return None

    def test_matches_subject_form(self):
        self.assertEqual(self._code("", "Use 445233 to confirm your account"), "445233")

    def test_matches_body_form(self):
        text = "Use this confirmation code: 445233 It expires in 5 minutes."
        self.assertEqual(self._code(text), "445233")

    def test_rejects_marketing_subject(self):
        # 真实事故：从这封营销邮件里抓出 018982 当注册码
        self.assertIsNone(self._code("", "All under 10 | Budget-Friendly Picks for Everyone"))

    def test_rejects_seven_digit_number(self):
        self.assertIsNone(self._code("Use 1000000 points"))

    def test_pattern_can_be_disabled(self):
        mail_service.config["emailnator_code_pattern"] = ""
        self.assertEqual(mail_service.emailnator_code_pattern(), "")
        # 空串时 CLI 回退通用规则（这里只验证配置透传）
        mail_service.config.pop("emailnator_code_pattern")
        self.assertEqual(
            mail_service.emailnator_code_pattern(),
            mail_service.DEFAULT_EMAILNATOR_CODE_PATTERN,
        )


class TestNewEmailBaselineGuard(_StateDirMixin, unittest.TestCase):
    """new-email 返回成功但基线快照失败时必须换地址重试，不能带病放行。"""

    def setUp(self):
        super().setUp()
        self._saved_call_once = mail_service._emailnator_call_once
        self._saved_script = mail_service.config.get("emailnator_script")
        # _emailnator_cmd 要求脚本存在；这里塞一个假路径
        mail_service.config["emailnator_script"] = os.path.join(self._tmp.name, "cli.py")
        open(mail_service.config["emailnator_script"], "w").close()
        mail_service.config["mail_retry_count"] = 2
        self.calls = []
        # 重试退避不必真的等
        patcher = unittest.mock.patch("mail_service.time.sleep", lambda *_: None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        mail_service._emailnator_call_once = self._saved_call_once
        mail_service.config.pop("emailnator_script", None)
        if self._saved_script is not None:
            mail_service.config["emailnator_script"] = self._saved_script
        super().tearDown()

    def _fake(self, baseline=True):
        def _call(cmd, subcommand, *, timeout, log_callback=None):
            state = cmd[cmd.index("--state") + 1]
            self.calls.append(state)
            address = f"user{len(self.calls)}@gmail.com"
            if baseline:
                with open(state, "w", encoding="utf-8") as f:
                    json.dump({address: {"codes": [], "baseline": ["old-1"]}}, f)
            return {"address": address, "baseline_count": 1 if baseline else 0}

        return _call

    def test_baseline_is_persisted_per_address(self):
        mail_service._emailnator_call_once = self._fake(baseline=True)
        address, credential = mail_service.emailnator_get_email_and_token()
        self.assertEqual(credential, f"emailnator:{address}")
        self.assertTrue(mail_service.emailnator_baseline_recorded(address))
        with open(mail_service.emailnator_state_file(address), encoding="utf-8") as f:
            self.assertEqual(json.load(f)[address]["baseline"], ["old-1"])
        # 临时状态文件必须清理掉
        leftovers = [n for n in os.listdir(self._tmp.name) if n.startswith("_new-email-")]
        self.assertEqual(leftovers, [])

    def test_missing_baseline_retries_with_new_address(self):
        calls = {"n": 0}

        def _call(cmd, subcommand, *, timeout, log_callback=None):
            state = cmd[cmd.index("--state") + 1]
            calls["n"] += 1
            self.calls.append(state)
            if calls["n"] == 1:
                return {"address": "broken@gmail.com", "baseline_count": 0}
            with open(state, "w", encoding="utf-8") as f:
                json.dump({"ok@gmail.com": {"codes": [], "baseline": []}}, f)
            return {"address": "ok@gmail.com", "baseline_count": 0}

        mail_service._emailnator_call_once = _call
        address, _ = mail_service.emailnator_get_email_and_token()
        self.assertEqual(address, "ok@gmail.com")
        self.assertEqual(calls["n"], 2)
        self.assertFalse(
            mail_service.emailnator_baseline_recorded("broken@gmail.com")
        )
        # 每次尝试用不同的临时状态文件（并发安全）
        self.assertEqual(len(set(self.calls)), 2)

    def test_baseline_failure_is_bounded(self):
        mail_service._emailnator_call_once = self._fake(baseline=False)
        with self.assertRaises(Exception):
            mail_service.emailnator_get_email_and_token()
        self.assertEqual(len(self.calls), 2)  # mail_retry_count


class TestWaitCodeGuards(_StateDirMixin, unittest.TestCase):
    """wait-code 必须带按地址的状态文件和严格 pattern，并核对发件人。"""

    def setUp(self):
        super().setUp()
        self._saved_call = mail_service._emailnator_call
        self.cmds = []
        patcher = mock.patch("mail_service.time.sleep", lambda *_: None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        mail_service._emailnator_call = self._saved_call
        super().tearDown()

    def _install(self, payloads, senders):
        def _call(subcommand, *args, **kwargs):
            self.cmds.append((subcommand, args, kwargs.get("state")))
            return payloads.pop(0)

        mail_service._emailnator_call = _call
        mail_service.emailnator_mail_sender = lambda addr, mid: senders.pop(0)

    def test_state_and_pattern_are_forwarded(self):
        self._install(
            [{"code": "445233", "subject": "Use 445233 to confirm your account", "message_id": "m1"}],
            ["Mozilla <accounts@firefox.com>"],
        )
        code = mail_service.emailnator_get_oai_code(None, "a@gmail.com", timeout=30)
        self.assertEqual(code, "445233")
        subcommand, args, state = self.cmds[0]
        self.assertEqual(subcommand, "wait-code")
        self.assertEqual(state, mail_service.emailnator_state_file("a@gmail.com"))
        self.assertIn("--pattern", args)
        self.assertEqual(
            args[args.index("--pattern") + 1],
            mail_service.DEFAULT_EMAILNATOR_CODE_PATTERN,
        )

    def test_non_mozilla_sender_is_rejected(self):
        self._install(
            [
                {"code": "018982", "subject": "All under 10 | Budget-Friendly Picks", "message_id": "m1"},
                {"code": "445233", "subject": "Use 445233 to confirm your account", "message_id": "m2"},
            ],
            ["AI TOOLS", "Mozilla <accounts@firefox.com>"],
        )
        logs = []
        code = mail_service.emailnator_get_oai_code(
            None, "b@gmail.com", timeout=30, log_callback=logs.append
        )
        self.assertEqual(code, "445233")
        self.assertEqual(len(self.cmds), 2)
        self.assertTrue(any("忽略非 Mozilla 邮件的验证码" in line for line in logs))

    def test_unknown_sender_does_not_block(self):
        # 查不到发件人（列表拉取失败/字段缺失）时放行：pattern 已经过滤过
        self._install(
            [{"code": "123456", "subject": "Use 123456 to confirm your account", "message_id": "m1"}],
            [None],
        )
        self.assertEqual(
            mail_service.emailnator_get_oai_code(None, "c@gmail.com", timeout=30), "123456"
        )

    def test_ignore_ids_seed_baseline_for_external_email(self):
        self._install(
            [{"code": "445233", "subject": "Use 445233 to confirm your account", "message_id": "m2"}],
            ["Mozilla <accounts@firefox.com>"],
        )
        mail_service.emailnator_get_oai_code(
            None, "d@gmail.com", timeout=30, ignore_ids={"old-1", "old-2"}
        )
        with open(mail_service.emailnator_state_file("d@gmail.com"), encoding="utf-8") as f:
            entry = json.load(f)["d@gmail.com"]
        self.assertEqual(sorted(entry["baseline"]), ["old-1", "old-2"])


if __name__ == "__main__":
    unittest.main()
