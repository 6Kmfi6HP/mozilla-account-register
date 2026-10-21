"""接入临时邮箱服务：邮箱生成、邮件轮询和验证码提取。

聚焦 cloudmail（HTTP API）与验证码正则提取；HTTP 客户端抽象成可替换
（requests / curl_cffi），避免对本机不存在的依赖强绑定。

另外支持 emailnator（临时 Gmail）作为 provider：通过子进程调用
``~/.claude/skills/emailnator/emailnator.py``，复用它的代理、TLS 指纹、
基线快照（新地址生成时刻的旧邮件一律忽略）和"已用验证码"状态。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import string
import subprocess
import sys
import threading
import time
import uuid
from typing import Callable, Dict, List, Optional

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

    emailnator 下这个快照同时被写成该地址的基线状态文件：外部提供的邮箱
    （``--emails`` / ``--signin``）没有经过 ``new-email``，不补基线的话
    ``wait-code`` 会把收件箱里的营销邮件当成新邮件。已有基线时不覆盖
    （重发回调里的快照只是扩大 ignore_ids）。
    """
    provider = get_email_provider()
    if provider == "emailnator":
        try:
            messages = emailnator_get_messages(email)
        except Exception:
            return set()
        ids = {
            str(msg.get("messageID") or msg.get("id"))
            for msg in messages
            if msg.get("messageID") or msg.get("id")
        }
        try:
            emailnator_seed_baseline(email, sorted(ids))
        except OSError:
            pass
        return ids
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


def prepare_mail_baseline(email: str) -> None:
    """在触发验证码邮件之前记录该地址的基线（emailnator 专用，其他 provider 无操作）。

    自动生成的地址由 ``new-email`` 自己写基线；只有外部提供的邮箱
    （``--emails`` / ``--signin``）需要调用方在提交表单前显式补一次。
    """
    if get_email_provider() != "emailnator":
        return
    snapshot_mail_ids(email)


# ---------------------------------------------------------------- emailnator

DEFAULT_EMAILNATOR_SCRIPT = "~/.claude/skills/emailnator/emailnator.py"
DEFAULT_EMAILNATOR_STATE_DIR = "~/.emailnator/states"
# 只从"确认邮件"上下文里取码。CLI 用 --pattern 时严格匹配、不回退通用规则，
# 因此营销邮件里的数字不会再被当成验证码（曾把 "All under 10 ..." 里的
# 018982 当成注册码提交）。主题形如 "Use 445233 to confirm your account"，
# 正文形如 "Use this confirmation code: 445233"，两种写法都能命中。
DEFAULT_EMAILNATOR_CODE_PATTERN = r"(?:confirmation\s+code:\s*|use\s+)(\d{6})\b"


def emailnator_script() -> str:
    raw = str(config.get("emailnator_script", "") or "").strip() or DEFAULT_EMAILNATOR_SCRIPT
    return os.path.expanduser(raw)


def emailnator_proxy() -> str:
    """emailnator 后端强制走代理：emailnator_proxy > proxy > $EMAILNATOR_PROXY。"""
    for value in (
        config.get("emailnator_proxy", ""),
        config.get("proxy", ""),
        os.environ.get("EMAILNATOR_PROXY", ""),
    ):
        text = str(value or "").strip()
        if text:
            return text
    return ""


def emailnator_state_dir() -> str:
    """每个邮箱一个状态文件的目录。

    共享一个状态文件时 ``_update_state`` 的"读整个 dict → 改 → 写回"会丢条目，
    丢的正好是基线；没有基线的地址会把收件箱里的营销邮件当成新邮件，从里面
    抓出 6 位数字当验证码。按地址分文件后每个文件只被一个注册流程读写。
    """
    raw = str(config.get("emailnator_state_dir", "") or "").strip()
    return os.path.expanduser(raw or DEFAULT_EMAILNATOR_STATE_DIR)


def emailnator_state_file(address: str) -> str:
    """地址 → 状态文件路径（文件名可读，带短哈希避免清洗后撞名）。"""
    key = str(address or "").strip().lower()
    slug = re.sub(r"[^a-z0-9]+", "_", key).strip("_")[:60] or "address"
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:8]
    return os.path.join(emailnator_state_dir(), f"{slug}-{digest}.json")


def emailnator_code_pattern() -> str:
    """传给 ``wait-code --pattern`` 的正则；配置成空串则退回 CLI 通用规则。"""
    if "emailnator_code_pattern" not in config:
        return DEFAULT_EMAILNATOR_CODE_PATTERN
    return str(config.get("emailnator_code_pattern", "") or "").strip()


def _read_emailnator_state(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_emailnator_state(path: str, state: dict) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.{uuid.uuid4().hex}.tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(state, handle, ensure_ascii=False)
    os.replace(tmp, path)


def emailnator_baseline_recorded(address: str) -> bool:
    """该地址的基线是否已落盘。

    ``new-email`` 的基线快照失败时不写条目，因此"有条目"就说明快照跑过了；
    空白收件箱记录的是空列表，也是合法基线。不能用 baseline_count 判断：
    全新的地址本来就可能 0 封旧邮件。
    """
    key = str(address or "").strip().lower()
    entry = _read_emailnator_state(emailnator_state_file(address)).get(key)
    return isinstance(entry, dict) and isinstance(entry.get("baseline"), list)


def emailnator_seed_baseline(address: str, message_ids) -> bool:
    """把一组邮件 id 写成该地址的基线（已有基线时不覆盖）。"""
    if get_email_provider() != "emailnator" or emailnator_baseline_recorded(address):
        return False
    key = str(address or "").strip().lower()
    path = emailnator_state_file(address)
    state = _read_emailnator_state(path)
    entry = state.get(key)
    if not isinstance(entry, dict):
        entry = {"codes": []}
    entry["baseline"] = [str(mid) for mid in (message_ids or ()) if str(mid)]
    state[key] = entry
    _write_emailnator_state(path, state)
    return True


def _emailnator_scratch_state_file() -> str:
    """``new-email`` 用的临时状态文件：地址是 CLI 生成的，事后才知道。"""
    directory = emailnator_state_dir()
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, f"_new-email-{uuid.uuid4().hex}.json")


def _emailnator_scratch_baseline(path: str, address: str) -> Optional[List[str]]:
    """从临时状态文件读回该地址的基线；没有条目返回 None（快照失败）。"""
    entry = _read_emailnator_state(path).get(str(address).strip().lower())
    if not isinstance(entry, dict) or not isinstance(entry.get("baseline"), list):
        return None
    return [str(mid) for mid in entry["baseline"] if str(mid)]


def _emailnator_cmd(subcommand: str, *args, state: Optional[str] = None) -> List[str]:
    script = emailnator_script()
    if not os.path.isfile(script):
        raise Exception(
            f"emailnator 脚本不存在: {script}（用配置项 emailnator_script 指定路径）"
        )
    cmd = [sys.executable, script, subcommand, *args]
    proxy = emailnator_proxy()
    if proxy:
        cmd.extend(["--proxy", proxy])
    if state:
        cmd.extend(["--state", os.path.expanduser(str(state))])
    return cmd


def _emailnator_call(
    subcommand: str,
    *args,
    timeout: float = 60,
    log_callback: Optional[Callable[[str], None]] = None,
    attempts: int = 1,
    state: Optional[str] = None,
) -> dict:
    """调用 emailnator CLI 并解析其 stdout 上的 JSON 结果。

    CLI 的进度日志写在 stderr，stdout 只有一行 JSON；这里把它转给
    log_callback（降级为 [Debug]，避免刷屏），失败时抛出带错误信息的异常。

    ``state`` 指定本次调用使用的状态文件（按地址隔离，见
    ``emailnator_state_file``）；不传时由 CLI 用它自己的默认值。

    ``attempts`` > 1 时重试"传输层"失败（连接被重置、SSL 错误、超时、
    403）：代理出口偶发 SSL_ERROR_SYSCALL / 403 属于瞬时故障，重试即可恢复。
    业务失败（如"邮箱已存在"）不重试。
    """
    cmd = _emailnator_cmd(subcommand, *args, state=state)
    total = max(1, int(attempts))
    last_error: Optional[Exception] = None
    for attempt in range(1, total + 1):
        try:
            return _emailnator_call_once(
                cmd,
                subcommand,
                timeout=timeout,
                log_callback=log_callback,
            )
        except _EmailnatorTransportError as exc:
            last_error = exc
            if attempt >= total:
                break
            delay = min(20.0, 3.0 * attempt)
            if log_callback:
                log_callback(
                    f"[Debug] emailnator {subcommand} 传输失败({exc})，"
                    f"{delay:.0f}s 后重试 ({attempt}/{total})"
                )
            time.sleep(delay)
    raise Exception(f"emailnator {subcommand} 失败: {last_error}")


class _EmailnatorTransportError(Exception):
    """emailnator CLI 的传输层失败（连接/SSL/超时），可以重试。"""


# emailnator CLI 把所有异常都包成 {"ok": false, "error": "..."}，
# 所以传输层错误必须按错误文本分类。
_TRANSIENT_ERROR_MARKERS = (
    "sslerror",
    "sslfailure",
    "ssl_connect",
    "ssl_error",
    "connectionerror",
    "connection reset",
    "connection refused",
    "connection closed",
    "connection aborted",
    "remotedisconnected",
    "curl: (28)",
    "curl: (35)",
    "curl: (56)",
    "curl: (7)",
    "timed out",
    "timeout",
    "temporarily unavailable",
    "network is unreachable",
    "empty reply from server",
    "bad gateway",
    "service unavailable",
    # emailnator 后端在并发突发时会回 403（不是业务错误：同一次突发里
    # 59/60 次调用成功）。CLI 内部已重试 3 次，这里换新进程 = 新会话/TLS
    # 指纹再试，是有效的恢复手段。
    "http error 403",
    "403 forbidden",
    "forbidden",
)


def _is_transient_emailnator_error(text: str) -> bool:
    """错误文本是否属于可重试的传输层故障。"""
    lowered = (text or "").lower()
    return any(marker in lowered for marker in _TRANSIENT_ERROR_MARKERS)


def _emailnator_call_once(
    cmd: List[str],
    subcommand: str,
    *,
    timeout: float,
    log_callback: Optional[Callable[[str], None]] = None,
) -> dict:
    """执行一次 emailnator CLI 调用并解析结果。"""
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(5.0, float(timeout)),
        )
    except subprocess.TimeoutExpired as exc:
        raise _EmailnatorTransportError(f"超时 ({timeout}s)") from exc
    except Exception as exc:
        raise _EmailnatorTransportError(f"执行失败: {exc}") from exc

    if log_callback:
        for line in (completed.stderr or "").splitlines():
            if line.strip():
                log_callback(f"[Debug] {line.strip()}")
    data = None
    for line in reversed((completed.stdout or "").splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                data = json.loads(line)
            except ValueError:
                data = None
            if isinstance(data, dict):
                break
    if not isinstance(data, dict):
        raise _EmailnatorTransportError(
            f"返回非 JSON: {(completed.stdout or completed.stderr or '')[:300]}"
        )
    if not data.get("ok"):
        error = str(data.get("error", "") or "")
        if _is_transient_emailnator_error(error):
            raise _EmailnatorTransportError(error)
        raise Exception(f"emailnator {subcommand} 失败: {error}")
    return data


def emailnator_retry_count() -> int:
    """emailnator CLI 传输失败时的重试次数（``mail_retry_count``，默认 3）。"""
    try:
        value = int(config.get("mail_retry_count", 3) or 3)
    except (TypeError, ValueError):
        return 3
    return max(1, min(10, value))


def emailnator_get_email_and_token() -> tuple:
    """生成一个临时 Gmail 地址，并把它的旧邮件基线落到该地址的状态文件。

    基线由 CLI 的 ``new-email`` 写入我们给的临时状态文件（地址是它生成的，
    调用前拿不到），成功后再搬到 ``emailnator_state_file(address)`` 供
    ``wait-code`` 读取。每个注册流程各写各的文件，不会像共享状态文件那样在
    "读改写"窗口互相覆盖丢基线。

    基线条目缺失说明 CLI 的快照没跑（它吞掉异常只打日志）。这时地址不可信：
    没有基线的 ``wait-code`` 会把收件箱里已有的营销邮件当新邮件。按传输层
    失败处理，换一个地址重试。
    """
    attempts = emailnator_retry_count()
    last_error: Optional[Exception] = None
    for attempt in range(1, attempts + 1):
        scratch = _emailnator_scratch_state_file()
        try:
            data = _emailnator_call_once(
                _emailnator_cmd("new-email", state=scratch),
                "new-email",
                timeout=120,
            )
            address = str(data.get("address", "") or "").strip()
            if not address:
                raise Exception(f"emailnator 未返回地址: {data}")
            baseline = _emailnator_scratch_baseline(scratch, address)
            if baseline is None:
                raise _EmailnatorTransportError(
                    "基线快照未记录（邮件列表拉取失败），换地址重试"
                )
            _write_emailnator_state(
                emailnator_state_file(address),
                {address.lower(): {"codes": [], "baseline": baseline}},
            )
            return address, f"emailnator:{address}"
        except _EmailnatorTransportError as exc:
            last_error = exc
            if attempt >= attempts:
                break
            time.sleep(min(20.0, 3.0 * attempt))
        finally:
            for leftover in (scratch, scratch[: -len(".json")] + ".tmp"):
                try:
                    os.unlink(leftover)
                except OSError:
                    pass
    raise Exception(f"emailnator new-email 失败: {last_error}")


def emailnator_get_messages(address: str) -> list:
    data = _emailnator_call(
        "messages",
        address,
        timeout=90,
        attempts=emailnator_retry_count(),
        state=emailnator_state_file(address),
    )
    messages = data.get("messages")
    return messages if isinstance(messages, list) else []


def emailnator_mail_sender(address: str, message_id: str) -> Optional[str]:
    """按 message_id 查这封邮件的发件人；查不到返回 None。"""
    if not message_id:
        return None
    try:
        messages = emailnator_get_messages(address)
    except Exception:
        return None
    for message in messages:
        if str(message.get("messageID") or message.get("id") or "") != message_id:
            continue
        sender = str(message.get("from") or message.get("fromEmail") or "").strip()
        return sender or None
    return None


def emailnator_get_oai_code(
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
    """轮询 emailnator 收件箱取验证码。

    每个 ``wait-code`` 只等一小段（便于重发和取消），循环到总超时。
    CLI 的已用码状态按地址隔离（``--state``），同一地址不会重复返回同一个码。

    只接受 Mozilla 确认邮件里的码：
    * ``--pattern`` 让 CLI 只从 "Use <6 digits> to confirm your account" /
      "confirmation code: <6 digits>" 上下文取码，营销邮件不参与提取；
    * 取到码后再核对发件人，非 Mozilla/Firefox 的邮件直接丢弃并继续等。
    """
    _ = (dev_token, code_shape)
    rejected_codes = set(ignore_codes or ())
    state_path = emailnator_state_file(email)
    if not emailnator_baseline_recorded(email):
        # 外部提供的邮箱（--emails / --signin）没有 new-email 快照：登录流程
        # 在提交表单前拍的 ignore_ids 就是等价基线，必须补进去。
        try:
            emailnator_seed_baseline(
                email, [str(mid) for mid in (ignore_ids or ()) if str(mid)]
            )
        except OSError as exc:
            if log_callback:
                log_callback(f"[Debug] emailnator 基线写入失败: {exc}")
    pattern = emailnator_code_pattern()
    deadline = time.time() + float(timeout)
    next_resend_at = time.time() + 35
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        if resend_callback and time.time() >= next_resend_at:
            try:
                if resend_callback() and log_callback:
                    log_callback("[*] 已触发重新发送验证码")
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] 触发重发验证码失败: {exc}")
            next_resend_at = time.time() + 35
        remaining = deadline - time.time()
        chunk = int(max(5, min(remaining, 60)))
        wait_args = [
            email,
            "--timeout",
            str(chunk),
            "--interval",
            str(max(1, int(poll_interval))),
        ]
        if pattern:
            wait_args.extend(["--pattern", pattern])
        try:
            # wait-code 不在内部重试：每次尝试最多占用 chunk+45s，内层重试会
            # 越过 mail_timeout。外层循环本身就是有界重试（受 deadline 约束）。
            data = _emailnator_call(
                "wait-code",
                *wait_args,
                timeout=chunk + 45,
                log_callback=log_callback,
                state=state_path,
            )
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] emailnator wait-code 失败: {exc}")
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        code = str(data.get("code", "") or "").strip()
        if not code:
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        if code in rejected_codes:
            if log_callback:
                log_callback(f"[Debug] 跳过已尝试过的验证码: {code}")
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        subject = str(data.get("subject", "") or "")
        sender = emailnator_mail_sender(email, str(data.get("message_id", "") or ""))
        if sender is not None and not re.search(r"mozilla|firefox", sender, re.IGNORECASE):
            # 非 Mozilla 邮件里的数字（营销/推广）不能当验证码提交。
            rejected_codes.add(code)
            if log_callback:
                log_callback(
                    f"[!] 忽略非 Mozilla 邮件的验证码: {code} "
                    f"from={sender} subject={subject}"
                )
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        if log_callback:
            log_callback(f"[*] emailnator 从邮件中提取到验证码: {code}")
        return code
    raise Exception(f"emailnator 在 {timeout}s 内未收到验证码邮件")


# ---------------------------------------------------------------- dispatch

def get_email_provider() -> str:
    return str(config.get("email_provider", "cloudmail") or "cloudmail").strip().lower()


def get_email_and_token(api_key=None):
    """按配置的 provider 返回 (email, credential)。"""
    provider = get_email_provider()
    if provider == "cloudmail":
        return cloudmail_get_email_and_token()
    if provider == "emailnator":
        return emailnator_get_email_and_token()
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
    if provider == "emailnator":
        return emailnator_get_oai_code(
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
