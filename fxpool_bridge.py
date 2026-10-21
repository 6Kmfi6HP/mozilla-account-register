"""把浏览器采集到的 FxA 会话发布给 fxpool-proxy。

两种产物：

1. 凭据包（bundle）——供 ``fxpool-proxy import-credentials <bundle>`` 使用，
   键必须恰好是 ``schema/email/uid/session_token``。Go 侧用
   ``json.Decoder.DisallowUnknownFields()`` 解析，多一个 ``password`` 键整包作废。
2. ``<fxpool_root>/tokens/renewal_credentials.json`` —— fxpool-proxy 直接读取的
   内部凭据文件，``schema`` 是数字 1，权限 0600（Go 侧要求 ``perm & 0o077 == 0``）。

本模块只用标准库，不导入 cloakbrowser/playwright，因此在没有浏览器依赖的
环境里也能安全导入（CI 保持绿色）。

安全约定：
- 永远不写密码，不碰 ``mail_credentials.txt`` / ``accounts_*.txt``；
- 错误信息里绝不回显 session_token（uid、email 可以出现）。
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
from typing import Optional

try:  # pragma: no cover - 非 POSIX 平台没有 fcntl
    import fcntl
except Exception:  # pragma: no cover - 依赖可选
    fcntl = None

BUNDLE_SCHEMA = "firefox-ip-protection-renewal-credentials-v1"
CREDENTIALS_SCHEMA = 1

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+$")
_UID_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_TOKEN_RE = re.compile(r"^[0-9a-fA-F]{64}$")

_LOCK = threading.Lock()
_LOCK_NAME = ".bridge.lock"
_CREDENTIALS_NAME = "renewal_credentials.json"


class BridgeError(RuntimeError):
    """凭据发布失败（校验、权限或冲突）。"""


def _normalize_path(path: str) -> str:
    """展开 ``~`` / ``$VAR`` 并转为绝对路径。

    config.json 与环境变量里的路径不会经过 shell 展开，直接 abspath 会得到
    字面量 ``./~`` 目录；这里统一规范化，保证 fxpool-proxy 能读到凭据。
    """
    return os.path.abspath(os.path.expanduser(os.path.expandvars(str(path))))


def _validate(email: str, uid: str, session_token: str) -> tuple:
    """校验并规范化三元组；失败抛 BridgeError（绝不回显 token）。"""
    email = str(email or "").strip()
    if not email or len(email) > 320 or not _EMAIL_RE.match(email):
        raise BridgeError("invalid email: expected user@domain")

    uid = str(uid or "").strip()
    if not _UID_RE.match(uid):
        raise BridgeError(f"invalid uid: expected 32 hex characters (got {uid!r})")

    token = str(session_token or "").strip()
    if not _TOKEN_RE.match(token):
        raise BridgeError("invalid session_token: expected 64 hex characters")

    return email, uid.lower(), token.lower()


def build_bundle(email: str, uid: str, session_token: str) -> dict:
    """构造凭据包；键恰好四个，顺序固定，不含密码。"""
    email, uid, token = _validate(email, uid, session_token)
    return {
        "schema": BUNDLE_SCHEMA,
        "email": email,
        "uid": uid,
        "session_token": token,
    }


def _fsync_dir(directory: str) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _atomic_write(path: str, payload: bytes, mode: int = 0o600) -> None:
    """同目录临时文件 + fsync + os.replace，最终权限固定为 mode。"""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd = -1
    temp_path = None
    handle = None
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(prefix=".fxpool-", suffix=".tmp", dir=directory)
        try:
            os.fchmod(fd, mode)
        except (AttributeError, OSError):
            pass
        handle = os.fdopen(fd, "wb")
        fd = -1
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        handle = None
        os.replace(temp_path, path)
        temp_path = None
        os.chmod(path, mode)
        _fsync_dir(directory)
    except OSError as exc:
        raise BridgeError(f"cannot write {path}: {exc}") from exc
    finally:
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if temp_path is not None:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def write_bundle(path: str, email: str, uid: str, session_token: str) -> str:
    """写凭据包（0600，目录 0700）；已存在则原子替换。返回绝对路径。"""
    bundle = build_bundle(email, uid, session_token)
    target = _normalize_path(path)
    payload = (json.dumps(bundle, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    _atomic_write(target, payload, 0o600)
    return target


def _acquire_lock(tokens_dir: str) -> Optional[int]:
    """尽力而为的进程间互斥；fcntl 不可用时退化为仅线程锁。"""
    if fcntl is None:
        return None
    lock_path = os.path.join(tokens_dir, _LOCK_NAME)
    try:
        fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
    except OSError:
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        return None
    return fd


def _release_lock(fd: Optional[int]) -> None:
    if fd is None:
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        os.close(fd)
    except OSError:
        pass


def _rename_invalid(path: str) -> str:
    """把损坏的凭据文件改名为 .bak-invalid-<timestamp>（不覆盖已有备份）。"""
    stamp = time.strftime("%Y%m%d%H%M%S")
    base = f"{path}.bak-invalid-{stamp}"
    candidate = base
    counter = 1
    while os.path.lexists(candidate):
        candidate = f"{base}-{counter}"
        counter += 1
    try:
        os.replace(path, candidate)
    except OSError as exc:
        raise BridgeError(f"cannot move invalid {path} aside: {exc}") from exc
    return candidate


def _prepare_target(target: str, uid: str) -> None:
    """检查已有凭据文件：同 uid 允许替换，不同有效 uid 拒绝，损坏文件改名让路。"""
    if not os.path.lexists(target):
        return
    if os.path.islink(target) or not os.path.isfile(target):
        _rename_invalid(target)
        return
    try:
        with open(target, "r", encoding="utf-8") as handle:
            existing = json.load(handle)
    except (OSError, ValueError):
        _rename_invalid(target)
        return
    if not isinstance(existing, dict):
        _rename_invalid(target)
        return

    existing_uid = existing.get("uid")
    if isinstance(existing_uid, str) and _UID_RE.match(existing_uid.strip()):
        if existing_uid.strip().lower() == uid:
            return
        raise BridgeError(
            "tokens/renewal_credentials.json already holds uid "
            f"{existing_uid.strip()}; refusing to overwrite; "
            "use the bundle and fxpool-proxy import-credentials"
        )
    _rename_invalid(target)


def publish_renewal_credentials(
    fxpool_root: str, email: str, uid: str, session_token: str
) -> str:
    """写 ``<fxpool_root>/tokens/renewal_credentials.json``（紧凑 JSON，0600）。

    - 目录缺失时以 0700 创建；已存在的目录不改权限。
    - 同一 uid 原子替换（幂等）；不同有效 uid 拒绝并保持原文件不动。
    - 已有文件损坏（非 JSON / 无有效 uid / 非普通文件）时改名为
      ``.bak-invalid-<timestamp>`` 后写入新文件。
    """
    email, uid, token = _validate(email, uid, session_token)
    root = _normalize_path(fxpool_root)
    tokens_dir = os.path.join(root, "tokens")
    target = os.path.join(tokens_dir, _CREDENTIALS_NAME)

    try:
        os.makedirs(root, mode=0o700, exist_ok=True)
        os.makedirs(tokens_dir, mode=0o700, exist_ok=True)
    except OSError as exc:
        raise BridgeError(f"cannot create {tokens_dir}: {exc}") from exc

    payload = {
        "schema": CREDENTIALS_SCHEMA,
        "email": email,
        "uid": uid,
        "session_token": token,
    }
    data = (
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")

    with _LOCK:
        lock_fd = _acquire_lock(tokens_dir)
        try:
            _prepare_target(target, uid)
            _atomic_write(target, data, 0o600)
        finally:
            _release_lock(lock_fd)
    return target


def publish_credentials(
    email: str,
    uid: str,
    session_token: str,
    *,
    fxpool_root: Optional[str] = None,
    bundle_dir: Optional[str] = None,
) -> dict:
    """按配置发布凭据包和/或内部凭据文件。

    返回 ``{"bundle_path": str|None, "credentials_path": str|None}``；
    两个目标都未配置时抛 ``BridgeError("no bridge target configured")``。
    """
    if not fxpool_root and not bundle_dir:
        raise BridgeError("no bridge target configured")

    email, uid, token = _validate(email, uid, session_token)

    bundle_path = None
    credentials_path = None
    if bundle_dir:
        bundle_path = write_bundle(
            os.path.join(bundle_dir, uid + ".json"), email, uid, token
        )
    if fxpool_root:
        credentials_path = publish_renewal_credentials(
            fxpool_root, email, uid, token
        )
    return {"bundle_path": bundle_path, "credentials_path": credentials_path}
