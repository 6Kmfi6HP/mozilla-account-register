"""浏览器注册后端（cloakbrowser 自动化）。

生产环境对 auth API 的 POST 走 Fastly WAF 拦截（纯 HTTP /account/create 会
406），因此提供浏览器后端：用反检测浏览器走真实注册页完成注册，再从
localStorage 采集 FxA 会话（uid + sessionToken），可选地做一次性开通，最后
交给 ``fxpool_bridge`` 生成 fxpool-proxy 可直接导入的凭据。

当前线上注册流程（2026-10 实测 DOM）：
    1. /signup 填邮箱 -> 提交
    2. 密码页 ``input[name=newPassword]``（被 ``span[data-testid=input-label]``
       覆盖，必须 ``force=True``）-> 点 "Create account"：账号在服务端创建，
       同时发送 6 位验证码邮件
    3. ``input[name=code]`` 填验证码 -> 提交 -> 落地 /settings
    4. ``localStorage['__fxa_storage.accounts']`` 采集会话（WAF 下唯一可行的
       取 sessionToken 方式，不依赖 Firefox 安装）
    5. 可选：一次 ``GET https://vpn.mozilla.org/api/v1/fpn/auth`` 完成免费额度
       开通（Guardian 对重复请求会 429，因此每个账号只允许一次）

旧的 "先验证码后设密码"、``/settings/create_password``、``confirmationCode``
流程已随官方前端改版失效，全部删除。

公开入口：
    - ``register_one_browser(...)``：签名与旧版兼容（新增参数均为 keyword-only），
      register.py 可继续按原方式调用。
    - ``ensure_session_browser(...)``：对已有账号登录一次，只为采集会话。

依赖（可选，未安装时调用会给出明确错误）：
    cloakbrowser>=0.4   （反检测 Chromium，内部依赖 playwright）

本模块在没有 cloakbrowser 时仍可导入；``select_account_entry`` /
``harvest_session`` / 开通台账辅助函数均可离线单测。
"""
from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Callable, NoReturn, Optional
from urllib.parse import urlparse

import app_paths
import fxpool_bridge
import mail_service

# 可选依赖：cloakbrowser 未安装时给出明确提示
try:
    import cloakbrowser
except Exception as exc:  # pragma: no cover - 依赖可选
    cloakbrowser = None
    _CLOAK_IMPORT_ERROR = exc
else:
    _CLOAK_IMPORT_ERROR = None

SIGNUP_URL = "https://accounts.firefox.com/signup"
SIGNIN_URL = "https://accounts.firefox.com/signin"
SETTINGS_URL_GLOB = "**/settings**"

_SEL_EMAIL = "input[name=email]"
_SEL_NEW_PASSWORD = "input[name=newPassword]"
_SEL_CONFIRM_PASSWORD = "input[name=confirmPassword]"  # optional, filled only if present
_SEL_CODE = "input[name=code]"
_SEL_SUBMIT = "button[type=submit]"
_SEL_SUBMIT_ENABLED = "button[type=submit]:not([disabled])"
_TXT_CREATE_ACCOUNT = 'button:has-text("Create account")'
_TXT_CONFIRM = 'button:has-text("Confirm")'

NAV_TIMEOUT_MS = 90000
SELECTOR_TIMEOUT_MS = 60000
CLICK_TIMEOUT_MS = 10000
ENABLED_TIMEOUT_MS = 15000
SETTINGS_TIMEOUT_MS = 60000
ENROLL_URL_TIMEOUT_MS = 60000
HARVEST_TIMEOUT_MS = 10000
HARVEST_INTERVAL_S = 0.5

STORAGE_ACCOUNTS_KEY = "__fxa_storage.accounts"
STORAGE_CURRENT_UID_KEY = "__fxa_storage.currentAccountUid"
ENROLL_URL = "https://vpn.mozilla.org/api/v1/fpn/auth"
ENROLL_SUCCESS_PATH = "/oauth/success"

_MAX_CODE_ATTEMPTS = 3

_ENROLL_LEDGER_NAME = "enrollment_attempts.txt"
_ENROLL_STATUSES = ("started", "ok", "rate_limited", "failed")

_UID_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_TOKEN_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# 注册请求的"账号已存在/请求过多"页面上会出现的特征文案（FxA 风控提示）。
# 命中这些文案说明该出口 IP 已被限速，重试同一个 IP 没有意义。
_RATE_LIMIT_HINTS = (
    "too many times",
    "tried too many",
    "try again in a day",
    "请稍后再试",
    "请求过于频繁",
    "too many requests",
)

# 账号建好之前 FxA 可能直接报错并弹回首页（服务端没有这个账号）。
_SIGNUP_ERROR_HINTS = (
    "unexpected error",
    "something went wrong",
    "an error occurred",
    "we're sorry",
    "发生错误",
    "出错了",
)


def _browser_proxy(cfg: dict) -> Optional[str]:
    """浏览器后端使用的代理地址。

    优先级：``browser_proxy`` > ``proxy`` > ``$BROWSER_PROXY``。
    FxA 对注册限速是按出口 IP 计的，批量注册必须走代理才能绕开单 IP 配额。
    """
    for value in (
        cfg.get("browser_proxy", ""),
        cfg.get("proxy", ""),
        os.environ.get("BROWSER_PROXY", ""),
    ):
        text = str(value or "").strip()
        if text:
            return text
    return None


class BrowserRegisterError(RuntimeError):
    pass


class RegisterCancelled(Exception):
    pass


class EnrollmentRateLimited(BrowserRegisterError):
    """Guardian 对 /fpn/auth 返回 429（每个账号只尝试一次，不重试）。"""


class SignupRateLimited(BrowserRegisterError):
    """FxA 对注册请求按出口 IP 限速（"tried too many times ... in a day"）。

    账号尚未在服务端创建，重试必须换一个出口 IP（换代理）才有意义。
    """


class SignupNotCreated(BrowserRegisterError):
    """注册流程在"账号建好之前"失败（页面报错、被弹回首页等）。

    服务端没有这个账号，所以换一个邮箱 + 换一个出口 IP 重试是安全的。
    典型场景：提交邮箱后页面出现 "Unexpected error" 并退回首页。
    """


def _ensure_cloakbrowser() -> None:
    if cloakbrowser is None:
        raise BrowserRegisterError(
            "浏览器后端需要 cloakbrowser，请安装: "
            "pip install cloakbrowser  (或复用已装 cloakbrowser 的虚拟环境)；"
            f"导入错误: {_CLOAK_IMPORT_ERROR}"
        )


# ---------------------------------------------------------------- failure

def _body_snippet(page) -> str:
    try:
        text = page.inner_text("body")
    except Exception:
        return ""
    return re.sub(r"\s+", " ", text)[:200]


def _is_rate_limited(body: str) -> bool:
    """页面文案是否命中 FxA 的限速提示。"""
    lowered = (body or "").lower()
    return any(hint in lowered for hint in _RATE_LIMIT_HINTS)


def _is_signup_error_page(body: str) -> bool:
    """页面是否显示 FxA 的通用错误（账号还没建好就被弹回首页/错误页）。"""
    lowered = (body or "").lower()
    return any(hint in lowered for hint in _SIGNUP_ERROR_HINTS)


def _fail(page, stage: str, detail: str) -> NoReturn:
    """统一的失败出口：带 stage、当前 URL 和页面正文片段。

    - 命中限速文案 → ``SignupRateLimited``（换出口 IP 重试）
    - 命中通用错误页 → ``SignupNotCreated``（账号没建好，换邮箱重试）
    - 其他 → ``BrowserRegisterError``，原样上报
    """
    body = _body_snippet(page)
    message = f"[stage={stage}] {detail}; url={page.url}; body={body}"
    if _is_rate_limited(body):
        raise SignupRateLimited(message)
    if _is_signup_error_page(body):
        raise SignupNotCreated(message)
    raise BrowserRegisterError(message)


# ---------------------------------------------------------------- signup helpers

def _wait_code(
    email: str,
    timeout: float,
    poll_interval: float,
    log,
    cancel,
    *,
    ignore_ids=None,
    ignore_codes=None,
    code_shape=None,
    resend_callback=None,
) -> str:
    """轮询邮箱验证码；委托给 mail_service，便于接入 mail_providers 插件。

    ``ignore_ids`` / ``ignore_codes`` 排除流程开始前就在邮箱里的旧验证码
    （登录已有账号时的关键：旧注册码与新登录码都是 6 位数字）。
    """
    return mail_service.get_oai_code(
        None,
        email,
        timeout=timeout,
        poll_interval=poll_interval,
        log_callback=log,
        cancel_callback=cancel,
        resend_callback=resend_callback,
        ignore_ids=ignore_ids,
        ignore_codes=ignore_codes,
        code_shape=code_shape,
    )


def _make_resend_callback(page, email: str, ignore_ids: set, log):
    """返回一个只在 ``#resend`` 可用时点击的重发回调。

    点击成功后把邮箱里现有的邮件 id 全部标记为失效：重发会让旧验证码作废，
    后续轮询必须只接受重发之后到达的邮件。
    """

    def _resend() -> bool:
        # 先快照再点击：点击之后到达的邮件才是新码，必须保留。
        try:
            ignore_ids.update(mail_service.snapshot_mail_ids(email))
        except Exception:
            pass
        try:
            page.wait_for_selector("#resend:not([disabled])", timeout=1500)
            page.click("#resend", timeout=CLICK_TIMEOUT_MS)
        except Exception:
            return False
        log("[*] 已请求重新发送验证码")
        return True

    return _resend


_ERROR_HINTS = ("invalid", "expired", "incorrect", "wrong", "无效", "过期", "错误")


def _code_rejected(page) -> bool:
    """验证码提交后页面上是否出现了明确的错误提示（tooltip）。

    只认 tooltip 且文本包含错误关键词：FxA 成功时也会短暂显示 alert
    （"Account confirmed successfully"），不能把成功提示误判成拒绝。
    """
    for selector in ('[role="tooltip"]', '[data-testid="tooltip"]', ".tooltip"):
        try:
            element = page.query_selector(selector)
            if element is None or not element.is_visible():
                continue
            try:
                text = (element.inner_text() or "").strip().lower()
            except Exception:
                text = ""
            if text and any(hint in text for hint in _ERROR_HINTS):
                return True
        except Exception:
            continue
    return False


def _wait_settings_or_rejected(page, timeout_ms: int) -> str:
    """等待 /settings 或明确的验证码错误，返回 settings/rejected/timeout。"""
    deadline = time.monotonic() + timeout_ms / 1000.0
    while time.monotonic() < deadline:
        try:
            if "/settings" in (page.url or ""):
                return "settings"
        except Exception:
            pass
        if _code_rejected(page):
            return "rejected"
        time.sleep(HARVEST_INTERVAL_S)
    return "timeout"


def _is_unblock_screen(page) -> bool:
    """当前验证码页是否是 /signin_unblock（8 位字母数字授权码）。"""
    try:
        if "signin_unblock" in (page.url or ""):
            return True
    except Exception:
        pass
    try:
        return page.query_selector("text=Enter authorization code") is not None
    except Exception:
        return False


def _click_submit_or(page, fallback_text: str, log) -> None:
    """优先点 type=submit 的启用按钮，失败则按文本兜底（force）。"""
    try:
        page.wait_for_selector(_SEL_SUBMIT_ENABLED, timeout=ENABLED_TIMEOUT_MS)
        page.click(_SEL_SUBMIT, timeout=CLICK_TIMEOUT_MS)
    except Exception:
        page.click(f'button:has-text("{fallback_text}")', timeout=CLICK_TIMEOUT_MS, force=True)


def _wait_for_signin_outcome(page, timeout_ms: int) -> str:
    """登录提交后等待 /settings 或验证码页，返回 settings/code/timeout。"""
    deadline = time.monotonic() + timeout_ms / 1000.0
    while time.monotonic() < deadline:
        try:
            if page.query_selector(_SEL_CODE) is not None:
                return "code"
        except Exception:
            pass
        try:
            if "signin_unblock" in (page.url or ""):
                return "code"
        except Exception:
            pass
        try:
            if "/settings" in (page.url or ""):
                return "settings"
        except Exception:
            pass
        time.sleep(HARVEST_INTERVAL_S)
    return "timeout"


# ---------------------------------------------------------------- session harvest

def _last_login(entry: dict) -> float:
    """StoredAccountData.lastLogin 可能是数字或字符串；无法解析时视为 0。"""
    try:
        return float(entry.get("lastLogin"))
    except (TypeError, ValueError):
        return 0.0


def _normalize_uid_hint(value) -> str:
    """规范化 localStorage 里的 uid 提示（可能被 JSON 序列化成带引号的字符串）。"""
    text = str(value or "").strip()
    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        try:
            parsed = json.loads(text)
        except Exception:
            parsed = text.strip('"')
        if isinstance(parsed, str):
            text = parsed.strip()
    return text.lower()


def select_account_entry(
    raw: str,
    email: Optional[str] = None,
    uid: Optional[str] = None,
    current_uid: Optional[str] = None,
) -> dict:
    """从 ``__fxa_storage.accounts`` 的原始值中选出目标账号。

    选择顺序：指定 uid -> ``currentAccountUid``（FxA 登录后同步写入，最可靠）
    -> 指定 email（同名时取 lastLogin 最新的一条）-> 唯一条目。
    返回 ``{"email", "uid", "session_token"}``（uid/token 均小写）。
    """
    try:
        accounts = json.loads(raw)
    except Exception:
        raise BrowserRegisterError(
            "[stage=harvest] __fxa_storage.accounts is not a JSON object"
        )
    if not isinstance(accounts, dict):
        raise BrowserRegisterError(
            "[stage=harvest] __fxa_storage.accounts is not a JSON object"
        )

    selected_key = None
    entry = None

    def _stored_email(value: dict) -> str:
        return str(value.get("email") or "").strip().lower()

    if uid:
        wanted = uid.strip().lower()
        for key, value in accounts.items():
            if isinstance(key, str) and key.strip().lower() == wanted:
                selected_key, entry = key, value
                break
        if entry is None:
            raise BrowserRegisterError(f"[stage=harvest] no stored account for uid {uid}")
    else:
        candidates = [
            (key, value) for key, value in accounts.items() if isinstance(value, dict)
        ]
        # FxA 的 storeAccountData 会同步写入 currentAccountUid：优先它，
        # 这样即使同一邮箱有多条记录（复用的 profile）也能选对。
        if current_uid:
            wanted_current = _normalize_uid_hint(current_uid)
            for key, value in candidates:
                if str(key).strip().lower() != wanted_current:
                    continue
                stored = _stored_email(value)
                # StoredAccountData.email 是可选的：没有 email 字段时不应因为
                # 调用方传了 email 就否掉 currentAccountUid 指向的条目。
                if email and stored and stored != email.strip().lower():
                    break
                selected_key, entry = key, value
                break

        if entry is None and email:
            wanted_email = email.strip().lower()
            matches = [
                (key, value)
                for key, value in candidates
                if _stored_email(value) == wanted_email
            ]
            if not matches:
                # StoredAccountData.email 是可选的：只有一个条目且没有 email
                # 字段时，它就是当前登录的账号（例如旧版本写入的数据）。
                if len(candidates) == 1 and not _stored_email(candidates[0][1]):
                    selected_key, entry = candidates[0]
                else:
                    raise BrowserRegisterError(
                        f"[stage=harvest] no stored account for email {email}"
                    )
            else:
                if len(matches) > 1:
                    ranked = sorted(
                        matches, key=lambda kv: _last_login(kv[1]), reverse=True
                    )
                    if _last_login(ranked[0][1]) > _last_login(ranked[1][1]):
                        matches = [ranked[0]]
                if len(matches) > 1:
                    uids = ", ".join(str(key) for key, _ in matches)
                    raise BrowserRegisterError(
                        f"[stage=harvest] multiple stored accounts match email {email}: {uids}"
                    )
                selected_key, entry = matches[0]

        if entry is None and not email:
            if len(accounts) != 1:
                uids = ", ".join(str(key) for key in accounts)
                raise BrowserRegisterError(
                    f"[stage=harvest] multiple stored accounts; pass uid or email: {uids}"
                )
            selected_key, entry = next(iter(accounts.items()))

    if not isinstance(entry, dict):
        raise BrowserRegisterError(
            "[stage=harvest] stored account entry is not a JSON object"
        )

    entry_uid = entry.get("uid")
    valid_entry_uid = isinstance(entry_uid, str) and bool(_UID_RE.match(entry_uid.strip()))
    valid_key_uid = isinstance(selected_key, str) and bool(_UID_RE.match(selected_key.strip()))
    if not (valid_entry_uid or valid_key_uid):
        raise BrowserRegisterError(
            "[stage=harvest] stored account uid is not 32 hex characters"
        )
    resolved_uid = (entry_uid if valid_entry_uid else selected_key).strip().lower()

    token = entry.get("sessionToken")
    if not isinstance(token, str) or not _TOKEN_RE.match(token.strip()):
        raise BrowserRegisterError(
            "[stage=harvest] stored account sessionToken is not 64 hex characters"
        )

    stored_email = entry.get("email")
    if stored_email and "@" not in str(stored_email):
        raise BrowserRegisterError("[stage=harvest] stored account email is invalid")

    return {
        "email": str(stored_email or email or ""),
        "uid": resolved_uid,
        "session_token": token.strip().lower(),
    }


def harvest_session(
    page, email: Optional[str] = None, uid: Optional[str] = None
) -> dict:
    """轮询 localStorage，读取 FxA 会话（不依赖 cookies / Firefox profile）。"""
    deadline = time.monotonic() + HARVEST_TIMEOUT_MS / 1000.0
    script = "() => window.localStorage.getItem('%s')" % STORAGE_ACCOUNTS_KEY
    current_script = "() => window.localStorage.getItem('%s')" % STORAGE_CURRENT_UID_KEY
    while time.monotonic() < deadline:
        try:
            raw = page.evaluate(script)
        except Exception:
            raw = None
        if isinstance(raw, str) and raw.strip():
            current_uid = None
            try:
                current = page.evaluate(current_script)
                if isinstance(current, str) and current.strip():
                    current_uid = current.strip()
            except Exception:
                current_uid = None
            return select_account_entry(
                raw, email=email, uid=uid, current_uid=current_uid
            )
        time.sleep(HARVEST_INTERVAL_S)
    raise BrowserRegisterError(
        "[stage=harvest] __fxa_storage.accounts missing; "
        "the sign-in did not persist a session"
    )


# ---------------------------------------------------------------- enrollment

def _enrollment_ledger_path(path: Optional[str] = None) -> str:
    return path or app_paths.user_path(_ENROLL_LEDGER_NAME)


def _enrollment_attempted(uid: str, path: Optional[str] = None) -> bool:
    """该 uid 是否已经有过开通尝试（任何状态都算）。"""
    ledger = _enrollment_ledger_path(path)
    wanted = str(uid).strip().lower()
    try:
        with open(ledger, "r", encoding="utf-8") as handle:
            for line in handle:
                fields = line.rstrip("\n").split("\t")
                if fields and fields[0].strip().lower() == wanted:
                    return True
    except FileNotFoundError:
        return False
    return False


def _record_enrollment(uid: str, status: str, path: Optional[str] = None) -> None:
    """追加一条开通台账（append + fsync），新文件权限 0600。"""
    if status not in _ENROLL_STATUSES:
        raise ValueError(f"invalid enrollment status: {status}")
    ledger = _enrollment_ledger_path(path)
    directory = os.path.dirname(os.path.abspath(ledger))
    if directory:
        os.makedirs(directory, exist_ok=True)
    line = "{}\t{}\t{}\n".format(
        str(uid).strip().lower(), status, datetime.now(timezone.utc).isoformat()
    )
    fd = os.open(ledger, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())


def enroll_entitlement(
    page,
    uid: str,
    log_callback: Optional[Callable[[str], None]] = None,
    cancel_callback: Optional[Callable[[], None]] = None,
) -> dict:
    """一次性开通：GET /api/v1/fpn/auth，成功判定为 /oauth/success + 权益 JSON。

    每个账号永远只允许一次尝试：导航前先写 ``started`` 台账，进程崩溃也不会
    导致重试。Guardian 返回 429 时记录 ``rate_limited`` 并抛
    ``EnrollmentRateLimited``，不重试、不 reload、不预检 /fpn/status。
    """
    log = log_callback or (lambda msg: print(msg))
    cancel = cancel_callback or (lambda: None)

    if _enrollment_attempted(uid):
        log(
            f"[!] enrollment already attempted for uid {uid}; "
            "refusing to retry (one attempt per account)"
        )
        return {"enrolled": False, "skipped": "already_attempted", "entitlement": None}

    cancel()
    # 写前标记：先落盘再导航，崩溃也不会重试。
    _record_enrollment(uid, "started")

    resp = None
    try:
        resp = page.goto(ENROLL_URL, timeout=NAV_TIMEOUT_MS, wait_until="domcontentloaded")
    except RegisterCancelled:
        raise
    except Exception as exc:
        # FxA 在 React 里用 window.location 硬跳转（prompt=none 成功后跳到
        # vpn.mozilla.org/oauth/success），Playwright 会把原始 goto 报成
        # "interrupted by another navigation"。这正是成功路径，继续等待。
        if "interrupted by another navigation" not in str(exc).lower():
            _record_enrollment(uid, "failed")
            _fail(page, "enroll", f"could not open {ENROLL_URL}: {exc}")

    if resp is not None and resp.status == 429:
        _record_enrollment(uid, "rate_limited")
        log("[!] Guardian rate-limited /fpn/auth (429); not retrying")
        raise EnrollmentRateLimited(
            "[stage=enroll] Guardian rate-limited /fpn/auth (429); not retrying"
        )

    try:
        # 按路径匹配而不是 **/oauth/success** glob：redirect_uri 查询参数里也
        # 含有 oauth/success，glob 可能匹配到 accounts.firefox.com/authorization。
        page.wait_for_url(
            lambda url: urlparse(str(url)).path == ENROLL_SUCCESS_PATH,
            timeout=ENROLL_URL_TIMEOUT_MS,
        )
    except RegisterCancelled:
        raise
    except Exception:
        _record_enrollment(uid, "failed")
        try:
            final_url = page.url or ""
        except Exception:
            final_url = ""
        if "accounts.firefox.com" in final_url or "/signin" in final_url:
            _fail(
                page,
                "enroll",
                "enrollment did not auto-continue; the FxA session was not accepted",
            )
        _fail(page, "enroll", "enrollment did not reach /oauth/success")

    # 权益 JSON 是 /oauth/success 的文档正文；Chromium 会把 JSON 文档渲染成
    # 纯文本。goto 的 resp 是 accounts.firefox.com 的 SPA HTML（或为 None），
    # 绝不能先解析它，否则永远读不到 JSON。
    text = ""
    data = None
    parse_error = None
    body_deadline = time.monotonic() + 5.0
    while time.monotonic() < body_deadline:
        try:
            text = page.inner_text("body")
        except Exception:
            text = ""
        if text.strip():
            try:
                data = json.loads(text.strip())
                break
            except Exception as exc:
                parse_error = exc
                # SPA 可能还在替换文档，短暂重试。
        time.sleep(HARVEST_INTERVAL_S)

    if data is None and resp is not None:
        # 兜底：极少数情况下页面正文不可读，但导航响应体就是 JSON。
        try:
            fallback = resp.text() or ""
        except Exception:
            fallback = ""
        if fallback.strip():
            try:
                data = json.loads(fallback.strip())
                text = fallback
            except Exception as exc:
                parse_error = exc

    if data is None:
        _record_enrollment(uid, "failed")
        _fail(
            page,
            "enroll",
            f"entitlement body is not JSON ({parse_error}): {text.strip()[:200]}",
        )

    try:
        final_url = page.url or ""
    except Exception:
        final_url = ""

    if (
        ENROLL_SUCCESS_PATH in final_url
        and isinstance(data, dict)
        and isinstance(data.get("limited_bandwidth"), bool)
        and "uid" in data
    ):
        _record_enrollment(uid, "ok")
        return {
            "enrolled": True,
            "entitlement": {
                "uid": data.get("uid"),
                "created_at": data.get("created_at"),
                "limited_bandwidth": data["limited_bandwidth"],
            },
            "skipped": None,
        }

    _record_enrollment(uid, "failed")
    status = resp.status if resp is not None else "?"
    _fail(
        page,
        "enroll",
        f"unexpected enrollment response (http={status}): {text.strip()[:200]}",
    )


# ---------------------------------------------------------------- shared tail

def _finish_session(
    page,
    email: str,
    *,
    log: Callable[[str], None],
    cancel: Callable[[], None],
    enroll: bool,
    fxpool_root: Optional[str],
    bundle_dir: Optional[str],
    bridge: bool,
    harvest_required: bool,
) -> dict:
    """登录/注册成功后的公共收尾：采集会话 -> 开通 -> 发布凭据。

    开通失败与凭据发布失败只记录、不推翻已创建的账号。
    """
    result = {
        "uid": None,
        "session_token": None,
        "enrolled": False,
        "entitlement": None,
        "enrollment_skipped": None,
        "bundle_path": None,
        "credentials_path": None,
        "bridge_error": None,
    }

    session = None
    if harvest_required:
        log("[*] 读取 FxA 会话 (localStorage)")
        session = harvest_session(page, email=email)
        result["uid"] = session["uid"]
        result["session_token"] = session["session_token"]
        log(f"[*] 已获取 FxA 会话 uid={session['uid']}")

    if enroll and session is not None:
        try:
            outcome = enroll_entitlement(
                page, session["uid"], log_callback=log, cancel_callback=cancel
            )
        except RegisterCancelled:
            raise
        except EnrollmentRateLimited as exc:
            result["enrollment_skipped"] = "rate_limited"
            log(f"[!] 开通失败: {exc}")
        except Exception as exc:
            result["enrollment_skipped"] = "failed"
            log(f"[!] 开通失败: {exc}")
        else:
            result["enrolled"] = bool(outcome.get("enrolled"))
            result["entitlement"] = outcome.get("entitlement")
            result["enrollment_skipped"] = outcome.get("skipped")

    if bridge and (fxpool_root or bundle_dir) and session is not None:
        try:
            paths = fxpool_bridge.publish_credentials(
                email,
                session["uid"],
                session["session_token"],
                fxpool_root=fxpool_root,
                bundle_dir=bundle_dir,
            )
        except fxpool_bridge.BridgeError as exc:
            result["bridge_error"] = str(exc)
            log(f"[!] bridge: {exc}")
        except Exception as exc:
            result["bridge_error"] = str(exc)
            log(f"[!] bridge: {exc}")
        else:
            result["bundle_path"] = paths.get("bundle_path")
            result["credentials_path"] = paths.get("credentials_path")

    return result


def _close(browser, page) -> None:
    if page is not None:
        try:
            page.close()
        except Exception:
            pass
    if browser is not None:
        try:
            browser.close()
        except Exception:
            pass


# ---------------------------------------------------------------- signup

def register_one_browser(
    email: str,
    password: str,
    config: Optional[dict] = None,
    log_callback: Optional[Callable[[str], None]] = None,
    cancel_callback: Optional[Callable[[], None]] = None,
    account_path: Optional[str] = None,  # still unused
    mail_credential_dir: Optional[str] = None,  # still unused
    *,
    enroll: bool = False,
    fxpool_root: Optional[str] = None,
    bundle_dir: Optional[str] = None,
    bridge: bool = True,
    on_account_created: Optional[Callable[[str, str], None]] = None,
) -> dict:
    """用浏览器注册一个 Mozilla 账号，返回结果 dict。

    签名与旧版兼容（新增参数均为 keyword-only），register.py 可继续按
    ``register_one_browser(email=..., password=..., config=..., log_callback=...)``
    调用。email/password 必须由调用方显式传入。

    ``on_account_created(email, password)`` 在**到达验证码输入页**后才调用：
    只有到达该页才说明账号已在服务端创建（被限速或校验失败时页面会退回密码页，
    账号并不存在）。调用方应立刻持久化凭据，避免后续收码或收尾失败导致账号丢失。

    返回值在原有 ``email/password/verified/password_set`` 之外新增
    ``uid/session_token/enrolled/entitlement/enrollment_skipped/bundle_path/
    credentials_path/bridge_error``。
    """
    _ensure_cloakbrowser()
    log = log_callback or (lambda msg: print(msg))
    cancel = cancel_callback or (lambda: None)
    cfg = config or mail_service.config

    timeout = int(cfg.get("mail_timeout", 180) or 180)
    poll_interval = float(cfg.get("mail_poll_interval", 3) or 3)

    browser = None
    page = None
    try:
        proxy = _browser_proxy(cfg)
        log(f"[*] 启动反检测浏览器 (cloakbrowser) 代理={proxy or '直连'}")
        try:
            browser = cloakbrowser.launch(headless=True, humanize=True, proxy=proxy)
            page = browser.new_page()
        except Exception as exc:
            raise BrowserRegisterError(f"浏览器启动失败: {exc}") from exc

        cancel()
        log("[*] 打开 Mozilla 账号注册页")
        try:
            page.goto(SIGNUP_URL, timeout=NAV_TIMEOUT_MS, wait_until="domcontentloaded")
        except RegisterCancelled:
            raise
        except Exception as exc:
            _fail(page, "challenge", f"cannot open the signup page: {exc}")

        # 绕过 Client Challenge 后到达真实注册页
        try:
            page.wait_for_selector(_SEL_EMAIL, timeout=SELECTOR_TIMEOUT_MS)
        except RegisterCancelled:
            raise
        except Exception:
            _fail(
                page,
                "challenge",
                "signup page did not show the email field (Client Challenge?)",
            )
        log("[*] 已到达注册页")

        cancel()
        try:
            page.fill(_SEL_EMAIL, email)
            page.click(_SEL_SUBMIT, timeout=CLICK_TIMEOUT_MS)
        except RegisterCancelled:
            raise
        except Exception as exc:
            _fail(page, "email", f"could not submit the email: {exc}")
        log("[*] 已提交邮箱，等待密码设置页")

        # 线上流程：邮箱之后是 "Create a password" 页，而不是验证码页。
        try:
            page.wait_for_selector(
                _SEL_NEW_PASSWORD, state="visible", timeout=SELECTOR_TIMEOUT_MS
            )
        except RegisterCancelled:
            raise
        except Exception:
            _fail(page, "password", "signup page did not show the password field")

        cancel()
        # force=True 是强制的：input-label span 覆盖了输入框，普通 fill 会超时。
        try:
            page.fill(_SEL_NEW_PASSWORD, password, force=True)
        except RegisterCancelled:
            raise
        except Exception as exc:
            _fail(page, "password", f"could not fill the password: {exc}")

        try:
            confirm_field = page.query_selector(_SEL_CONFIRM_PASSWORD)
        except Exception:
            confirm_field = None
        if confirm_field is not None:
            try:
                page.fill(_SEL_CONFIRM_PASSWORD, password, force=True)
            except RegisterCancelled:
                raise
            except Exception as exc:
                _fail(page, "password", f"could not fill the confirm password: {exc}")

        # "Create account" 在密码输入事件前保持 disabled；仍 disabled 时不要点死按钮。
        try:
            page.wait_for_selector(_SEL_SUBMIT_ENABLED, timeout=ENABLED_TIMEOUT_MS)
        except RegisterCancelled:
            raise
        except Exception:
            _fail(
                page,
                "password",
                "the Create account button stayed disabled after the password was filled",
            )

        try:
            page.click(_SEL_SUBMIT, timeout=CLICK_TIMEOUT_MS)
        except RegisterCancelled:
            raise
        except Exception:
            try:
                page.click(_TXT_CREATE_ACCOUNT, timeout=CLICK_TIMEOUT_MS, force=True)
            except RegisterCancelled:
                raise
            except Exception as exc:
                _fail(page, "password", f"could not click Create account: {exc}")
        log("[*] 已提交密码，等待验证码输入页")

        try:
            page.wait_for_selector(_SEL_CODE, timeout=SELECTOR_TIMEOUT_MS)
        except RegisterCancelled:
            raise
        except Exception:
            _fail(page, "code", "signup did not reach the verification code screen")

        # 到达验证码页才说明账号在服务端真的建好了（限速/校验失败时页面会退回
        # 密码页，账号并不存在）。此时立刻让调用方持久化 email/password。
        log("[*] 账号已创建，等待验证码")
        if on_account_created is not None:
            # 回调失败不能中断注册（账号已经存在），但必须大声记录。
            try:
                on_account_created(email, password)
            except Exception as exc:
                log(f"[!] on_account_created 回调失败: {exc}")

        cancel()
        ignore_ids: set = set()
        ignore_codes: set = set()
        resend = _make_resend_callback(page, email, ignore_ids, log)
        try:
            code = _wait_code(
                email,
                timeout,
                poll_interval,
                log,
                cancel,
                ignore_ids=ignore_ids,
                ignore_codes=ignore_codes,
                code_shape="digits6",
                resend_callback=resend,
            )
        except RegisterCancelled:
            raise
        except Exception as exc:
            _fail(page, "code", f"could not obtain the signup code: {exc}")
        log(f"[*] 注册验证码: {code}")

        attempts = 0
        while True:
            attempts += 1
            cancel()
            try:
                # force=True：验证码输入框同样被 input-label span 覆盖。
                page.fill(_SEL_CODE, code, force=True)
                _click_submit_or(page, "Confirm", log)
            except RegisterCancelled:
                raise
            except Exception as exc:
                _fail(page, "code", f"could not submit the signup code: {exc}")
            log("[*] 已提交验证码，等待 /settings")

            # 验证码通过后落到 /settings 是唯一成功信号；若页面明确提示
            # 验证码无效，则重新取一个未用过的码（有上限，避免死循环）。
            outcome = _wait_settings_or_rejected(page, SETTINGS_TIMEOUT_MS)
            if outcome == "settings":
                break
            if outcome == "rejected" and attempts < _MAX_CODE_ATTEMPTS:
                ignore_codes.add(code)
                log("[!] 注册验证码被拒绝，重新等待新验证码")
                try:
                    code = _wait_code(
                        email,
                        timeout,
                        poll_interval,
                        log,
                        cancel,
                        ignore_ids=ignore_ids,
                        ignore_codes=ignore_codes,
                        code_shape="digits6",
                        resend_callback=resend,
                    )
                except RegisterCancelled:
                    raise
                except Exception as exc:
                    _fail(
                        page,
                        "code",
                        f"the signup code was rejected and no new code arrived: {exc}",
                    )
                log(f"[*] 新的注册验证码: {code}")
                continue
            _fail(page, "settings", "account creation did not land on /settings")
        log("[*] 账号已创建并登录 (/settings)")

        harvest_required = bool(enroll or (bridge and (fxpool_root or bundle_dir)))
        tail = _finish_session(
            page,
            email,
            log=log,
            cancel=cancel,
            enroll=enroll,
            fxpool_root=fxpool_root,
            bundle_dir=bundle_dir,
            bridge=bridge,
            harvest_required=harvest_required,
        )

        result = {
            "email": email,
            "password": password,
            "verified": True,
            "password_set": True,
        }
        result.update(tail)
        return result
    finally:
        _close(browser, page)


# ---------------------------------------------------------------- sign-in

def ensure_session_browser(
    email: str,
    password: str,
    config: Optional[dict] = None,
    log_callback: Optional[Callable[[str], None]] = None,
    cancel_callback: Optional[Callable[[], None]] = None,
    *,
    enroll: bool = False,
    fxpool_root: Optional[str] = None,
    bundle_dir: Optional[str] = None,
    bridge: bool = True,
) -> dict:
    """登录一个已存在的账号，仅为采集 FxA 会话（及可选开通/发布凭据）。

    返回 ``register_one_browser`` 同形状的 dict，但不含
    ``password/verified/password_set``（可能包含 ``email``）。
    TOTP-only 账号在浏览器路径下不支持：需要验证码而邮件没到时明确报错。
    """
    _ensure_cloakbrowser()
    log = log_callback or (lambda msg: print(msg))
    cancel = cancel_callback or (lambda: None)
    cfg = config or mail_service.config

    timeout = int(cfg.get("mail_timeout", 180) or 180)
    poll_interval = float(cfg.get("mail_poll_interval", 3) or 3)

    browser = None
    page = None
    try:
        proxy = _browser_proxy(cfg)
        log(f"[*] 启动反检测浏览器 (cloakbrowser) 代理={proxy or '直连'}")
        try:
            browser = cloakbrowser.launch(headless=True, humanize=True, proxy=proxy)
            page = browser.new_page()
        except Exception as exc:
            raise BrowserRegisterError(f"浏览器启动失败: {exc}") from exc

        cancel()
        log("[*] 打开 Mozilla 账号登录页")
        try:
            page.goto(SIGNIN_URL, timeout=NAV_TIMEOUT_MS, wait_until="domcontentloaded")
        except RegisterCancelled:
            raise
        except Exception as exc:
            _fail(page, "signin", f"cannot open the sign-in page: {exc}")

        try:
            page.wait_for_selector(_SEL_EMAIL, timeout=SELECTOR_TIMEOUT_MS)
        except RegisterCancelled:
            raise
        except Exception:
            _fail(page, "signin", "sign-in page did not show the email field")

        cancel()
        try:
            page.fill(_SEL_EMAIL, email)
            page.click(_SEL_SUBMIT, timeout=CLICK_TIMEOUT_MS)
        except RegisterCancelled:
            raise
        except Exception as exc:
            _fail(page, "signin", f"could not submit the email: {exc}")
        log("[*] 已提交邮箱，等待密码输入页")

        try:
            page.wait_for_selector(
                "input[name=password]", state="visible", timeout=SELECTOR_TIMEOUT_MS
            )
        except RegisterCancelled:
            raise
        except Exception:
            _fail(page, "signin", "sign-in page did not show the password field")

        cancel()
        # 与注册页相同的 input-label 覆盖问题：必须 force=True。
        try:
            page.fill("input[name=password]", password, force=True)
        except RegisterCancelled:
            raise
        except Exception as exc:
            _fail(page, "signin", f"could not fill the password: {exc}")

        try:
            page.wait_for_selector(_SEL_SUBMIT_ENABLED, timeout=ENABLED_TIMEOUT_MS)
            # 提交密码会触发登录验证码邮件；先快照邮箱里已有的邮件 id，
            # 轮询时只接受快照之后到达的新码，避免旧注册码被当成新登录码。
            ignore_ids = mail_service.snapshot_mail_ids(email)
            ignore_codes: set = set()
            page.click(_SEL_SUBMIT, timeout=CLICK_TIMEOUT_MS)
        except RegisterCancelled:
            raise
        except Exception as exc:
            _fail(page, "signin", f"could not submit the password: {exc}")
        log("[*] 已提交密码，等待 /settings 或验证码")

        outcome = _wait_for_signin_outcome(page, SELECTOR_TIMEOUT_MS)
        if outcome == "code":
            unblock = _is_unblock_screen(page)
            if unblock:
                log("[*] 登录被风控拦截，需要 8 位授权码（signin_unblock），等待邮件")
            else:
                log("[*] 登录要求邮箱验证码，等待邮件")
            shape = "alnum8" if unblock else "digits6"
            resend = _make_resend_callback(page, email, ignore_ids, log)
            try:
                code = _wait_code(
                    email,
                    timeout,
                    poll_interval,
                    log,
                    cancel,
                    ignore_ids=ignore_ids,
                    ignore_codes=ignore_codes,
                    code_shape=shape,
                    resend_callback=resend,
                )
            except RegisterCancelled:
                raise
            except Exception:
                if unblock:
                    _fail(
                        page,
                        "signin",
                        "sign-in required an unblock code (8-character authorization "
                        "code) and none arrived; check the mailbox",
                    )
                _fail(
                    page,
                    "signin",
                    "sign-in required a code and none arrived; "
                    "TOTP-only accounts are unsupported in the browser path",
                )

            attempts = 0
            while True:
                attempts += 1
                cancel()
                try:
                    # force=True：验证码输入框同样被 input-label span 覆盖。
                    page.fill(_SEL_CODE, code, force=True)
                    _click_submit_or(page, "Confirm", log)
                except RegisterCancelled:
                    raise
                except Exception as exc:
                    _fail(page, "signin", f"could not submit the sign-in code: {exc}")
                outcome = _wait_settings_or_rejected(page, SETTINGS_TIMEOUT_MS)
                if outcome == "settings":
                    break
                if outcome == "rejected" and attempts < _MAX_CODE_ATTEMPTS:
                    ignore_codes.add(code)
                    log("[!] 登录验证码被拒绝，重新等待新验证码")
                    try:
                        code = _wait_code(
                            email,
                            timeout,
                            poll_interval,
                            log,
                            cancel,
                            ignore_ids=ignore_ids,
                            ignore_codes=ignore_codes,
                            code_shape=shape,
                            resend_callback=resend,
                        )
                    except RegisterCancelled:
                        raise
                    except Exception as exc:
                        _fail(
                            page,
                            "signin",
                            f"the sign-in code was rejected and no new code arrived: {exc}",
                        )
                    log(f"[*] 新的登录验证码: {code}")
                    continue
                _fail(page, "signin", "sign-in did not reach /settings")
        elif outcome == "timeout":
            _fail(page, "signin", "sign-in did not reach /settings or a code screen")

        try:
            page.wait_for_url(SETTINGS_URL_GLOB, timeout=SETTINGS_TIMEOUT_MS)
        except RegisterCancelled:
            raise
        except Exception:
            _fail(page, "signin", "sign-in did not reach /settings")
        log("[*] 登录成功，已到达 /settings")

        # 登录路径总是采集会话（这正是本函数存在的意义）。
        tail = _finish_session(
            page,
            email,
            log=log,
            cancel=cancel,
            enroll=enroll,
            fxpool_root=fxpool_root,
            bundle_dir=bundle_dir,
            bridge=bridge,
            harvest_required=True,
        )

        result = {"email": email}
        result.update(tail)
        return result
    finally:
        _close(browser, page)
