"""mail_service 验证码提取逻辑的单元测试。"""
import unittest

from mail_service import extract_verification_code, normalize_mail_body


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


if __name__ == "__main__":
    unittest.main()
