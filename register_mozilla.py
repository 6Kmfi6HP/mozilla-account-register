"""单账号 Mozilla 账号注册流程编排。

流程（onepw 协议 v1 + cloudmail 验证码）：
    1. 派生 authPW（PBKDF2 1000 轮 + HKDF）
    2. POST /account/create -> uid + sessionToken
    3. cloudmail 轮询验证码（6 位数字）
    4. POST /recovery_email/verify_code -> 账号 verified

采用可注入 log 回调、取消回调、重发回调的编排方式。
"""
from __future__ import annotations

import time
from typing import Callable, Optional

from account_outputs import append_account_line, save_mail_credential
import mail_service
import mozilla_api
from mozilla_crypto import get_auth_pw


def _default_log(message: str) -> None:
    print(message)


class RegisterCancelled(Exception):
    pass


def register_one(
    email: Optional[str] = None,
    password: Optional[str] = None,
    config: Optional[dict] = None,
    auth_client: Optional[mozilla_api.MozillaAuthClient] = None,
    log_callback: Optional[Callable[[str], None]] = None,
    cancel_callback: Optional[Callable[[], None]] = None,
    account_path: Optional[str] = None,
    mail_credential_dir: Optional[str] = None,
) -> dict:
    """注册一个 Mozilla 账号。

    email/password 为 None 时，从 config 生成（cloudmail 随机邮箱 +
    随机密码）。返回注册结果 dict；验证失败时 raise 相应异常。
    """
    log = log_callback or _default_log
    cancel = cancel_callback or (lambda: None)
    cfg = config or mail_service.config

    provider = mail_service.get_email_provider()
    if email is None:
        if provider in ("cloudmail", "emailnator"):
            email, credential = mail_service.get_email_and_token()
            log(f"[*] 已生成临时邮箱: {email}")
        else:
            raise ValueError(f"provider={provider} 需要调用方显式传入 email")
    else:
        credential = None

    if password is None:
        password = _generate_password()
        log(f"[*] 已生成随机密码")

    cancel()
    try:
        auth_pw = get_auth_pw(email, password)
    except Exception as exc:
        raise RuntimeError(f"authPW 派生失败: {exc}") from exc

    client = auth_client or mozilla_api.MozillaAuthClient(
        base=cfg.get("auth_base", mozilla_api.AUTH_BASE),
        user_agent=cfg.get("user_agent", ""),
        proxy=cfg.get("proxy", ""),
        timeout=int(cfg.get("request_timeout", 30) or 30),
    )
    own_client = auth_client is None
    try:
        created = client.account_create(
            email, auth_pw, service=cfg.get("service", "sync")
        )
    except mozilla_api.MozillaAuthError as exc:
        if exc.errno == mozilla_api.ERRNO["INCORRECT_EMAIL_CASE"] and "email" in (exc.response or {}):
            # 服务器返回规范邮箱大小写，用规范邮箱重试一次
            normalized = (exc.response or {}).get("email")
            if normalized and normalized != email:
                log(f"[*] 邮箱大小写不一致，改用 {normalized} 重试")
                email = normalized
                auth_pw = get_auth_pw(email, password)
                created = client.account_create(email, auth_pw, service=cfg.get("service", "sync"))
            else:
                raise
        else:
            raise
    uid = created.get("uid")
    session_token = created.get("sessionToken")
    log(f"[+] 账号已创建: {email} uid={uid}")

    if credential:
        if mail_credential_dir:
            save_mail_credential(mail_credential_dir, email, credential)
        else:
            save_mail_credential(".", email, credential)

    code = None
    try:
        code = mail_service.get_oai_code(
            session_token,
            email,
            timeout=int(cfg.get("mail_timeout", 180) or 180),
            poll_interval=float(cfg.get("mail_poll_interval", 3) or 3),
            log_callback=log,
            cancel_callback=cancel,
            resend_callback=None,
        )
    except Exception as exc:
        if isinstance(exc, RegisterCancelled):
            raise
        raise RuntimeError(f"验证码获取失败: {exc}") from exc

    if code is None:
        raise RuntimeError(f"{email} 未在超时内收到验证码")

    try:
        client.recovery_email_verify_code(uid, code)
    except mozilla_api.MozillaAuthError as exc:
        raise RuntimeError(f"{email} 验证码提交失败: {exc}") from exc

    result = {
        "email": email,
        "password": password,
        "uid": uid,
        "session_token": session_token,
        "verified": True,
        "auth_at": created.get("authAt"),
    }
    log(f"[+] {email} 邮箱已验证 (code={code})")

    if account_path:
        append_account_line(account_path, email, password, uid or "")
    return result


def _generate_password(length: int = 16) -> str:
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits + "!@#_-"
    return "".join(secrets.choice(alphabet) for _ in range(length))
