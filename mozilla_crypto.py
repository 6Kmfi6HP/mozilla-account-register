"""Mozilla 账号 onepw 协议 v1 客户端密钥派生。

严格对齐 mozilla/fxa 仓库 fxa-auth-client/lib/crypto.ts 与 salt.ts：
    salt            = "identity.mozilla.com/picl/v1/quickStretch:{email}"
    quickStretched  = PBKDF2-SHA256(password, salt, iterations=1000, dkLen=32)
    authPW          = HKDF-SHA256(quickStretched, salt=空, info=NAMESPACE+"authPW", L=32)

只用 Python 标准库（hashlib / hmac），无第三方依赖。
"""
from __future__ import annotations

import hashlib
import hmac

NAMESPACE = "identity.mozilla.com/picl/v1/"

PBKDF2_ITERATIONS = 1000


def _pbkdf2_sha256(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen)


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF，SHA-256 单轮 Extract+Expand。

    WebCrypto 的 HKDF deriveBits 用的是 RFC 5869 标准构造（无 skip），
    与 Node crypto.hkdf 一致。注意与 Chrome 某些实现默认带额外 salt 的
    版本不同——FxA 官方客户端传的是空 salt Uint8Array(0)。
    """
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    # Extract
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    # Expand（length <= 255 * hashlen 时单块即可；这里始终 32/64 字节）
    if length <= 32:
        return _hkdf_expand_block(prk, info, 1)[:length]
    return b"".join(_hkdf_expand_block(prk, info, i) for i in range(1, (length + 31) // 32 + 1))[:length]


def _hkdf_expand_block(prk: bytes, info: bytes, counter: int) -> bytes:
    t = b"" if counter == 1 else prk
    return hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()


def get_auth_pw(email: str, password: str) -> str:
    """派生 authPW（64 位 hex 小写）。

    email 参与 PBKDF2 盐的构建，必须与注册时提交的 email 大小写一致。
    """
    email = email.strip()
    salt = f"{NAMESPACE}quickStretch:{email}".encode("utf-8")
    quick_stretched = _pbkdf2_sha256(
        password.encode("utf-8"), salt, PBKDF2_ITERATIONS, 32
    )
    auth_pw = _hkdf_sha256(
        quick_stretched, b"", f"{NAMESPACE}authPW".encode("utf-8"), 32
    )
    return auth_pw.hex()


def get_unwrap_bkey(email: str, password: str) -> str:
    """派生 unwrapBKey（64 位 hex 小写）。

    与 authPW 同源（同一 quickStretched），仅 HKDF info 不同。注册流程
    用不到，但在需要 Sync 密钥时有用。
    """
    email = email.strip()
    salt = f"{NAMESPACE}quickStretch:{email}".encode("utf-8")
    quick_stretched = _pbkdf2_sha256(
        password.encode("utf-8"), salt, PBKDF2_ITERATIONS, 32
    )
    unwrap = _hkdf_sha256(
        quick_stretched, b"", f"{NAMESPACE}unwrapBkey".encode("utf-8"), 32
    )
    return unwrap.hex()
