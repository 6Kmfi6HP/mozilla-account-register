"""Mozilla 账号 Auth Server v1 客户端 API。

端点基于 https://mozilla.github.io/ecosystem-platform/api 官方文档：
    POST {base}/account/create           创建账号（同时返回 sessionToken）
    POST {base}/recovery_email/verify_code  用邮件验证码验证邮箱
    GET  {base}/recovery_email/status    查询验证状态

用 requests.Session 保持 Cookie，以通过生产环境前的 Fastly WAF
（官方 auth-client 对 https 设置了 credentials='include'）。
"""
from __future__ import annotations

import json
import time
from typing import Optional

import requests

AUTH_BASE = "https://api.accounts.firefox.com/v1"

# auth-server 已知 errno（与 fxa-auth-server error.js 一致）
ERRNO = {
    "UNKNOWN_ACCOUNT": 102,
    "INVALID_PARAMETER": 106,
    "UNVERIFIED_ACCOUNT": 104,
    "THROTTLED": 114,
    "INCORRECT_EMAIL_CASE": 120,
    "REQUEST_BLOCKED": 125,
    "INVALID_TOKEN": 110,
}


class MozillaAuthError(RuntimeError):
    def __init__(self, message, errno=None, code=None, retry_after=None, response=None):
        super().__init__(message)
        self.message = message
        self.errno = errno
        self.code = code
        self.retry_after = retry_after
        self.response = response


class MozillaAuthClient:
    def __init__(
        self,
        base: str = AUTH_BASE,
        user_agent: Optional[str] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
    ):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        if user_agent:
            self.session.headers["User-Agent"] = user_agent
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        # WAF 期望浏览器式头；官方客户端对注册路径设置 credentials='include'
        self.session.headers.setdefault("Accept", "application/json")
        self.session.headers.setdefault("Accept-Language", "en-US,en;q=0.9")

    def _request(self, method: str, path: str, payload=None, extra_headers=None):
        url = f"{self.base}{path}"
        headers = dict(extra_headers or {})
        headers.setdefault("Content-Type", "application/json")
        try:
            resp = self.session.request(
                method, url, json=payload, headers=headers, timeout=self.timeout
            )
        except requests.RequestException as exc:
            raise MozillaAuthError(f"请求失败: {url}: {exc}") from exc

        text = resp.text
        data = None
        try:
            data = resp.json()
        except ValueError:
            # Fastly WAF 返回 406/429 且非 JSON
            if resp.status_code == 429:
                raise MozillaAuthError(
                    "WAF/限速 (429)", errno=ERRNO["THROTTLED"], code=429, response=resp
                )
            if resp.status_code == 406:
                raise MozillaAuthError(
                    "WAF 拦截 (406)", errno=ERRNO["REQUEST_BLOCKED"], code=406, response=resp
                )
            raise MozillaAuthError(
                f"非 JSON 响应 {resp.status_code}: {text[:300]}", code=resp.status_code, response=resp
            )

        if resp.status_code >= 400 or (isinstance(data, dict) and data.get("errno")):
            errno = data.get("errno") if isinstance(data, dict) else None
            retry_after = data.get("retryAfter") if isinstance(data, dict) else None
            message = data.get("message") if isinstance(data, dict) else str(data)
            raise MozillaAuthError(
                f"{path} 失败: HTTP {resp.status_code} errno={errno} message={message}",
                errno=errno,
                code=resp.status_code,
                retry_after=retry_after,
                response=resp,
            )
        return data

    def account_create(self, email: str, auth_pw: str, service: str = "sync") -> dict:
        """POST /account/create，返回 { uid, sessionToken, authAt }。"""
        payload = {"email": email, "authPW": auth_pw}
        if service:
            payload["service"] = service
        data = self._request("POST", "/account/create", payload=payload)
        if not isinstance(data, dict) or not data.get("uid"):
            raise MozillaAuthError(f"/account/create 返回缺少 uid: {json.dumps(data)[:300]}")
        return data

    def recovery_email_verify_code(self, uid: str, code: str) -> dict:
        """POST /recovery_email/verify_code，成功返回 {}。"""
        data = self._request(
            "POST",
            "/recovery_email/verify_code",
            payload={"uid": uid, "code": code},
        )
        return data or {}

    def recovery_email_status(self, session_token: str, uid: str) -> dict:
        """GET /recovery_email/status，用 sessionToken 查询验证状态。

        返回 { email, verified, emailVerified } 等字段。
        """
        headers = {
            "Authorization": f"Bearer {session_token}",
        }
        return self._request("GET", "/recovery_email/status", extra_headers=headers)

    def close(self):
        self.session.close()
