"""接入临时邮箱服务：邮箱生成、邮件轮询和验证码提取。

聚焦 cloudmail（HTTP API）与验证码正则提取；HTTP 客户端抽象成可替换
（requests / curl_cffi），避免对本机不存在的依赖强绑定。
"""
from __future__ import annotations

import re
import secrets
import string
import threading
import time
from typing import Callable, Dict, Optional

import requests

# curl_cffi 存在时用其 TLS 指纹请求类，否则退回 requests（弱指纹）。
try:
    from curl_cffi import requests as cffi_requests
except Exception:  # pragma: no cover - 依赖可选
    cffi_requests = None

config = {}

_cloudmail_domain_index = 0
_domain_index_lock = threading.Lock()

_http_get = None
_http_post = None


def bind_runtime(namespace: dict) -> None:
    """绑定外部注入的运行时（config、http_get、http_post）。

    http_get/http_post 若未注入，则使用模块内默认实现。
    """
    global config, _http_get, _http_post
    cfg = namespace.get("config")
    if cfg is not None:
        config = cfg
    for name in ("http_get", "http_post"):
        if name in namespace and namespace[name] is not None:
            if name == "http_get":
                _http_get = namespace[name]
            else:
                _http_post = namespace[name]


def _default_session() -> requests.Session:
    session = requests.Session()
    proxy = str(config.get("proxy", "") or "").strip()
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    ua = str(config.get("user_agent", "") or "").strip()
    if ua:
        session.headers["User-Agent"] = ua
    return session


def http_get(url, headers=None, params=None, timeout=20):
    if _http_get is not None:
        return _http_get(url, headers=headers, params=params, timeout=timeout)
    return _default_session().get(url, headers=headers, params=params, timeout=timeout)


def http_post(url, headers=None, json=None, params=None, timeout=20):
    if _http_post is not None:
        return _http_post(
            url, headers=headers, json=json, params=params, timeout=timeout
        )
    return _default_session().post(
        url, headers=headers, json=json, params=params, timeout=timeout
    )


def sleep_with_cancel(seconds: float, cancel_callback: Optional[Callable] = None) -> None:
    """可被取消回调打断的 sleep，轮询循环中用于交还控制权。"""
    deadline = time.time() + max(0.0, float(seconds))
    while time.time() < deadline:
        if cancel_callback:
            raise_if_cancelled(cancel_callback)
        time.sleep(min(0.2, max(0.05, deadline - time.time())))


def raise_if_cancelled(cancel_callback: Optional[Callable] = None) -> None:
    if cancel_callback:
        cancel_callback()


def normalize_mail_body(*sources) -> str:
    """从各邮箱提供商的 payload 中提取并规范化邮件正文。

    去掉 style/script/URL/标签，避免追踪参数冒充验证码。
    """
    parts = []
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key in ("text", "raw", "content", "intro", "body", "snippet"):
            value = source.get(key)
            values = value if isinstance(value, (list, tuple)) else [value]
            for item in values:
                if isinstance(item, str) and item.strip():
                    parts.append(item)
        html_value = source.get("html")
        html_items = html_value if isinstance(html_value, (list, tuple)) else [html_value]
        for item in html_items:
            if isinstance(item, str) and item.strip():
                parts.append(item)
    joined = "\n".join(parts)
    joined = re.sub(r"<style[\s\S]*?</style>", " ", joined, flags=re.IGNORECASE)
    joined = re.sub(r"<script[\s\S]*?</script>", " ", joined, flags=re.IGNORECASE)
    # 只剥 URL 本身，停到引号/尖括号/空白，避免贪婪吃掉后续正文导致标签跨段
    joined = re.sub(r"https?://[^\s'\"<>]+", " ", joined, flags=re.IGNORECASE)
    joined = re.sub(r"<[^>]+>", " ", joined)
    return re.sub(r"\s+", " ", joined).strip()


def _pick_list_payload(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("results"), list):
            return data.get("results")
        if isinstance(data.get("hydra:member"), list):
            return data.get("hydra:member")
        if isinstance(data.get("data"), list):
            return data.get("data")
        if isinstance(data.get("messages"), list):
            return data.get("messages")
        if isinstance(data.get("data"), dict):
            nested = data.get("data")
            if isinstance(nested.get("messages"), list):
                return nested.get("messages")
    return []


# ---------------------------------------------------------------- cloudmail

def get_cloudmail_api_base() -> str:
    return str(config.get("cloudmail_api_base", "") or "").strip().rstrip("/")


def get_cloudmail_path() -> str:
    raw = str(
        config.get("cloudmail_path_messages", "/api/public/emailList")
        or "/api/public/emailList"
    ).strip()
    return raw if raw.startswith("/") else "/" + raw


def get_cloudmail_public_token() -> str:
    return str(config.get("cloudmail_public_token", "") or "").strip()


def cloudmail_next_domain() -> str:
    global _cloudmail_domain_index
    domains = [
        item.strip().lstrip("@")
        for item in str(config.get("cloudmail_domains", "") or "").split(",")
        if item.strip().lstrip("@")
    ]
    if not domains:
        return ""
    with _domain_index_lock:
        domain = domains[_cloudmail_domain_index % len(domains)]
        _cloudmail_domain_index += 1
    return domain


def cloudmail_get_email_and_token() -> tuple:
    """生成一个无需预创建账号的 Cloud Mail 收件地址。"""
    if not get_cloudmail_api_base():
        raise Exception("Cloud Mail API Base 未配置")
    if not get_cloudmail_public_token():
        raise Exception("Cloud Mail Public Token 未配置")
    domain = cloudmail_next_domain()
    if not domain:
        raise Exception("Cloud Mail 收件域名未配置")
    address = f"{generate_username(12)}@{domain}"
    # 公共 Token 只从 config.json 读取，返回值中不带敏感凭证。
    return address, f"cloudmail:{address}"


def cloudmail_get_messages(address: str) -> list:
    api_base = get_cloudmail_api_base()
    public_token = get_cloudmail_public_token()
    if not api_base:
        raise Exception("Cloud Mail API Base 未配置")
    if not public_token:
        raise Exception("Cloud Mail Public Token 未配置")
    payload = {
        "toEmail": address,
        "type": 0,
        "isDel": 0,
        "timeSort": "desc",
        "num": 1,
        "size": 20,
    }
    resp = http_post(
        f"{api_base}{get_cloudmail_path()}",
        headers={
            "Authorization": public_token,
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=20,
    )
    resp.raise_for_status()
    try:
        data = resp.json()
    except Exception:
        raise Exception(f"Cloud Mail 邮件接口返回非JSON: {resp.text[:300]}")
    if not isinstance(data, dict):
        raise Exception(f"Cloud Mail 邮件接口返回格式错误: {data}")
    result_code = data.get("code")
    if result_code not in (None, 200, "200"):
        raise Exception(
            f"Cloud Mail 邮件接口失败: code={result_code}, message={data.get('message', '')}"
        )
    messages = data.get("data")
    if isinstance(messages, list):
        return messages
    return _pick_list_payload(data)


def cloudmail_get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
    ignore_ids=None,
    ignore_codes=None,
    code_shape=None,
) -> str:
    """轮询 Cloud Mail，返回邮件正文中提取到的验证码。

    ``ignore_ids`` / ``ignore_codes`` 用于登录已有账号时排除流程开始前就已在
    邮箱里的旧验证码（旧注册邮件与新登录码都是 6 位数字）。集合按引用使用，
    重发回调可以在轮询过程中继续往里加 id。``code_shape`` 指定期望的验证码
    形状（``digits6`` / ``alnum8``），None 保持原有 6 位数字提取逻辑。
    """
    _ = dev_token  # cloudmail 使用配置中的公共 Token
    ignored_ids = ignore_ids if ignore_ids is not None else ()
    ignored_codes = ignore_codes if ignore_codes is not None else ()
    deadline = time.time() + timeout
    seen_attempts: Dict[str, int] = {}
    next_resend_at = time.time() + 35
    resends = 0
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        if resend_callback and time.time() >= next_resend_at:
            clicked = False
            try:
                clicked = bool(resend_callback())
                if log_callback and clicked:
                    log_callback("[*] 已触发重新发送验证码")
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] 触发重发验证码失败: {exc}")
            if clicked:
                resends += 1
                if resends <= 2:
                    # 重发会作废旧码，同时把截止时间顺延一个窗口。
                    deadline = max(deadline, time.time() + min(float(timeout), 120.0))
            next_resend_at = time.time() + 35
        try:
            messages = cloudmail_get_messages(email)
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] Cloud Mail 拉取邮件列表失败: {exc}")
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        if log_callback:
            log_callback(f"[Debug] Cloud Mail 本轮邮件数量: {len(messages)}")
        for msg in messages:
            msg_id = msg.get("emailId") or msg.get("email_id") or msg.get("id")
            if not msg_id:
                continue
            if str(msg_id) in ignored_ids:
                # 流程开始前（或重发前）就存在的邮件：其中的码已经失效。
                continue
            attempt = int(seen_attempts.get(msg_id, 0))
            if attempt >= 5:
                continue
            seen_attempts[msg_id] = attempt + 1
            target_address = str(
                msg.get("toEmail") or msg.get("to_email") or ""
            ).strip().lower()
            if target_address and target_address != email.lower():
                continue
            code_value = str(msg.get("code", "") or "").strip()
            combined = normalize_mail_body(msg)
            if code_value and (
                re.fullmatch(r"[A-Za-z0-9]{3}-[A-Za-z0-9]{3}", code_value)
                or re.fullmatch(r"\d{4,8}", code_value)
            ):
                combined = f"verification code: {code_value}\n{combined}"
            subject = str(msg.get("subject", "") or "")
            if log_callback:
                log_callback(f"[Debug] Cloud Mail 收到邮件: {subject}")
            code = extract_code(combined, subject, code_shape)
            if code and code in ignored_codes:
                if log_callback:
                    log_callback(f"[Debug] 跳过已尝试过的验证码 id={msg_id}")
                continue
            if code:
                if log_callback:
                    log_callback(f"[*] Cloud Mail 从邮件中提取到验证码: {code}")
                return code
            if log_callback:
                log_callback(
                    f"[Debug] Cloud Mail 邮件已解析但未提取到验证码 "
                    f"id={msg_id} attempt={seen_attempts[msg_id]}"
                )
        sleep_with_cancel(poll_interval, cancel_callback)
    raise Exception(f"Cloud Mail 在 {timeout}s 内未收到验证码邮件")


def snapshot_mail_ids(email: str) -> set:
    """返回邮箱中当前已有邮件的 id 集合（尽力而为，失败时返回空集）。

    登录已有账号前先做快照，轮询时用 ``ignore_ids`` 排除旧邮件，避免把上次
    注册/登录留下的验证码当成新码提交。
    """
    provider = get_email_provider()
    if provider != "cloudmail":
        return set()
    try:
        messages = cloudmail_get_messages(email)
    except Exception:
        return set()
    ids = set()
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        msg_id = msg.get("emailId") or msg.get("email_id") or msg.get("id")
        if msg_id:
            ids.add(str(msg_id))
    return ids


# ---------------------------------------------------------------- dispatch

def get_email_provider() -> str:
    return str(config.get("email_provider", "cloudmail") or "cloudmail").strip().lower()


def get_email_and_token(api_key=None):
    """按配置的 provider 返回 (email, credential)。"""
    provider = get_email_provider()
    if provider == "cloudmail":
        return cloudmail_get_email_and_token()
    if provider == "manual":
        # 手动模式：调用方负责提供邮箱，credential 占位。
        raise Exception("manual provider 需要由调用方直接传入邮箱，不应调用 get_email_and_token")
    raise Exception(f"未实现的 email_provider: {provider}")


def get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
    ignore_ids=None,
    ignore_codes=None,
    code_shape=None,
) -> str:
    provider = get_email_provider()
    if provider == "cloudmail":
        return cloudmail_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            resend_callback=resend_callback,
            ignore_ids=ignore_ids,
            ignore_codes=ignore_codes,
            code_shape=code_shape,
        )
    raise Exception(f"未实现的 email_provider: {provider}")


# ---------------------------------------------------------------- extraction

def extract_verification_code(text: str, subject: str = "") -> Optional[str]:
    """从邮件正文/主题中提取 6 位数字验证码。

    Mozilla 账号（accounts.firefox.com）的确认码是 6 位纯数字。
    contextual 优先，再兜底 6 位数字。
    为减小误抓追踪段，优先匹配带 "code"/"verification" 上下文的码。
    """
    subject = str(subject or "")
    text = str(text or "")
    subject = re.sub(r"https?://[^\s'\"<>]+", " ", subject, flags=re.IGNORECASE)
    text = re.sub(r"https?://[^\s'\"<>]+", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"<style[\s\S]*?</style>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"<script[\s\S]*?</script>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)

    digit_contextual = [
        r"(?:confirmation|verification|confirm)\s+code(?:\s+is)?[:\s]+(\d{4,8})",
        r"your\s+(?:verification\s+)?code(?:\s+is)?[:\s]+(\d{4,8})",
        r"use\s+(?:this\s+)?code(?:\s+is)?[:\s]+(\d{4,8})",
        r"code(?:\s+is)?[:\s]+(\d{4,8})",
        r"\b(\d{6})\b",
    ]

    def _pick(source, patterns):
        for pattern in patterns:
            match = re.search(pattern, source, re.MULTILINE | re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    # 主题优先（Mozilla 主题常直接带码），正文其次。
    for source in (subject, text):
        code = _pick(source, digit_contextual)
        if code:
            return code
    return None


def extract_code(text: str, subject: str = "", shape: Optional[str] = None) -> Optional[str]:
    """按页面要求的形状提取验证码。

    ``shape=None`` 时保持原有行为（委托 ``extract_verification_code``）。
    ``digits6``：恰好 6 位数字（confirm_signup_code / signin_token_code）。
    ``alnum8``：8 位字母数字（signin_unblock 的 authorization code），
    输入框只接受 8 位，所以 4-4 分组会去掉连字符。
    """
    if shape is None:
        return extract_verification_code(text, subject)

    subject = str(subject or "")
    text = str(text or "")
    subject = re.sub(r"https?://[^\s'\"<>]+", " ", subject, flags=re.IGNORECASE)
    text = re.sub(r"https?://[^\s'\"<>]+", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"<style[\s\S]*?</style>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"<script[\s\S]*?</script>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)

    if shape == "digits6":
        patterns = [
            r"(?:confirmation|verification|confirm|sign[- ]?in)\s+code(?:\s+is)?[:\s]+(\d{6})\b",
            r"your\s+(?:verification\s+)?code(?:\s+is)?[:\s]+(\d{6})\b",
            r"use\s+(?:this\s+)?code(?:\s+is)?[:\s]+(\d{6})\b",
            r"code(?:\s+is)?[:\s]+(\d{6})\b",
            r"\b(\d{6})\b",
        ]
    elif shape == "alnum8":
        # 至少含一个数字和一个字母，避免把普通英文单词当成验证码。
        alnum8 = r"(?=[A-Za-z0-9]{0,7}\d)(?=[A-Za-z0-9]{0,7}[A-Za-z])[A-Za-z0-9]{8}"
        patterns = [
            r"authorization\s+code(?:\s+(?:is|you\s+need))?[:\s]+(" + alnum8 + r")\b",
            r"here\s+is\s+the\s+authorization\s+code[^A-Za-z0-9]{0,30}(" + alnum8 + r")\b",
            r"use\s+([A-Za-z0-9]{4}-[A-Za-z0-9]{4})\s+to\s+sign\s+in",
            r"use\s+(" + alnum8 + r")\s+to\s+sign\s+in",
            r"code(?:\s+is)?[:\s]+(" + alnum8 + r")\b",
            r"\b([A-Za-z0-9]{4}-[A-Za-z0-9]{4})\b",
        ]
    else:
        return extract_verification_code(text, subject)

    for source in (subject, text):
        for pattern in patterns:
            match = re.search(pattern, source, re.MULTILINE | re.IGNORECASE)
            if match:
                value = match.group(1)
                if shape == "alnum8":
                    # 授权码必须字母数字混合；纯数字（如 2026-1020 日期）不是码。
                    if not (re.search(r"[A-Za-z]", value) and re.search(r"\d", value)):
                        continue
                    return re.sub(r"[^A-Za-z0-9]", "", value)
                return value
    return None


def generate_username(length=10) -> str:
    chars = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))
