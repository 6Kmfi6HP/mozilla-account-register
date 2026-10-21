"""应用配置：默认值、加载保存、规范化与运行前校验。"""
from __future__ import annotations

import json
import os
import tempfile

from app_paths import default_config_path, ensure_user_data_layout

CONFIG_FILE = default_config_path()

DEFAULT_CONFIG = {
    # 邮箱服务（cloudmail）
    "email_provider": "cloudmail",
    "cloudmail_api_base": "",
    "cloudmail_public_token": "",
    "cloudmail_domains": "",
    "cloudmail_path_messages": "/api/public/emailList",
    # 邮箱服务（emailnator 临时 Gmail）
    "emailnator_script": "~/.claude/skills/emailnator/emailnator.py",
    "emailnator_proxy": "",
    # 每个邮箱一个状态文件（基线 + 已用验证码）；共享文件会在并发下丢基线
    "emailnator_state_dir": "~/.emailnator/states",
    # wait-code 的严格提取正则（含捕获组）；空串退回 CLI 通用规则
    "emailnator_code_pattern": r"(?:confirmation\s+code:\s*|use\s+)(\d{6})\b",
    # 网络
    "proxy": "",
    # 浏览器后端专用代理（FxA 对注册按出口 IP 限速，批量注册必须走代理）
    "browser_proxy": "",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    # 注册参数
    "service": "sync",
    "register_count": 1,
    "register_threads": 1,
    "thread_start_interval": 3,
    "register_max_attempts": 10,
    # 超时
    "mail_timeout": 180,
    "mail_poll_interval": 3,
    "mail_retry_count": 3,
    "request_timeout": 30,
    "account_hard_timeout": 900,
    # 邮箱列表批量模式
    "emails_file": "",
    "password_prefix": "Moz!",
    # 浏览器后端 / fxpool 凭据桥接
    "register_backend": "api",
    "fxpool_enroll": False,
    "fxpool_root": "",
    "bundle_dir": "",
}

config = DEFAULT_CONFIG.copy()


class ConfigError(RuntimeError):
    pass


def _require_bool(cfg, key):
    value = cfg.get(key)
    if type(value) is not bool:
        raise ConfigError(f"配置项 {key} 必须是布尔值 true/false")
    return value


def _require_int(cfg, key, minimum, maximum):
    value = cfg.get(key)
    if type(value) is not int:
        raise ConfigError(f"配置项 {key} 必须是整数")
    if not minimum <= value <= maximum:
        raise ConfigError(f"配置项 {key} 必须在 {minimum} 到 {maximum} 之间")
    return value


def _normalize_keys(cfg):
    for key in list(cfg.keys()):
        normalized = key.strip()
        if normalized != key:
            cfg[normalized] = cfg.pop(key)


def load_config(path=None, validate=True):
    global config
    ensure_user_data_layout()
    file_path = path or CONFIG_FILE
    if not os.path.isfile(file_path):
        config = DEFAULT_CONFIG.copy()
        return config
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            loaded = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"配置文件不是合法 JSON: {file_path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ConfigError(f"配置根节点必须是 JSON object: {file_path}")
    _normalize_keys(loaded)
    merged = DEFAULT_CONFIG.copy()
    merged.update(loaded)
    config = merged
    if validate:
        validate_config(config)
    return config


def save_config(cfg=None, path=None):
    data = cfg if cfg is not None else config
    file_path = path or CONFIG_FILE
    directory = os.path.dirname(file_path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".config-", suffix=".json.tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, file_path)
        temp_path = None
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
    return file_path


def validate_config(cfg=None):
    data = cfg if cfg is not None else config
    _require_int(data, "register_count", 1, 100000)
    _require_int(data, "register_threads", 1, 100)
    _require_int(data, "mail_timeout", 5, 3600)
    _require_int(data, "mail_poll_interval", 1, 60)
    _require_int(data, "register_max_attempts", 1, 1000)
    provider = str(data.get("email_provider", "cloudmail") or "cloudmail").strip().lower()
    if provider not in ("cloudmail", "emailnator", "duckmail", "yyds", "cloudflare", "manual"):
        raise ConfigError(f"不支持的 email_provider: {provider}")
    # 新增键只在出现时做类型校验，兼容直接传 dict 的调用方
    if "register_backend" in data:
        backend = str(data["register_backend"]).strip().lower()
        if backend not in ("api", "browser"):
            raise ConfigError("配置项 register_backend 必须是 api 或 browser")
    if "fxpool_enroll" in data and type(data["fxpool_enroll"]) is not bool:
        raise ConfigError("配置项 fxpool_enroll 必须是布尔值 true/false")
    for key in ("fxpool_root", "bundle_dir", "emailnator_state_dir", "emailnator_code_pattern"):
        if key in data and not isinstance(data[key], str):
            raise ConfigError(f"配置项 {key} 必须是字符串")
    return data


def get_config():
    return config
