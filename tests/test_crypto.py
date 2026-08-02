"""mozilla_crypto / mozilla_api 的单元测试。

对 authPW 派生的验证依赖官方 onepw 测试向量（见 test_vectors 变量），
可在子代理取回权威向量后更新。
"""
import unittest

from mozilla_crypto import get_auth_pw, get_unwrap_bkey


class TestAuthPwDerivation(unittest.TestCase):
    def test_length_and_hex(self):
        auth_pw = get_auth_pw("test@example.com", "password123")
        self.assertEqual(len(auth_pw), 64)
        int(auth_pw, 16)  # 必须是合法 hex

    def test_deterministic(self):
        a1 = get_auth_pw("test@example.com", "password123")
        a2 = get_auth_pw("test@example.com", "password123")
        self.assertEqual(a1, a2)

    def test_email_case_sensitive_salt(self):
        # email 大小写会改变 PBKDF2 盐，从而改变 authPW
        lo = get_auth_pw("test@example.com", "password123")
        hi = get_auth_pw("TEST@example.com", "password123")
        self.assertNotEqual(lo, hi)

    def test_password_change_changes_authpw(self):
        self.assertNotEqual(
            get_auth_pw("test@example.com", "password123"),
            get_auth_pw("test@example.com", "password456"),
        )

    def test_unwrap_bkey_differs_from_authpw(self):
        auth_pw = get_auth_pw("test@example.com", "password123")
        unwrap = get_unwrap_bkey("test@example.com", "password123")
        self.assertEqual(len(unwrap), 64)
        self.assertNotEqual(auth_pw, unwrap)

    def test_official_vector_andre(self):
        # 官方权威向量（PyFxA test_crypto + fxa-auth-client crypto.ts 双实现交叉验证）
        # https://github.com/mozilla/PyFxA fxa/tests/test_crypto.py
        email = "andré@example.org"
        password = "pässwörd"
        self.assertEqual(
            get_auth_pw(email, password),
            "247b675ffb4c46310bc87e26d712153abe5e1c90ef00a4784594f97ef54f2375",
        )
        self.assertEqual(
            get_unwrap_bkey(email, password),
            "de6a2648b78284fcb9ffa81ba95803309cfba7af583c01a8a1a63e567234dd28",
        )


if __name__ == "__main__":
    unittest.main()
