#!/usr/bin/env python3
"""Mozilla 账号注册机入口（CLI）。

支持：
  - 自动生成临时邮箱（cloudmail）+ 随机密码 注册 N 个账号
  - 从 CSV/文本文件读取邮箱列表批量注册（每行一个邮箱）
  - 并发控制（register_threads）

用法：
  python register.py                       # 按 config.json 注册 register_count 个（API 后端）
  python register.py --count 5             # 注册 5 个
  python register.py --emails emails.txt   # 批量注册文件中的邮箱
  python register.py --backend browser     # 用浏览器后端（绕过生产 WAF，需 cloakbrowser）
  python register.py --dry-run             # 只跑派生+参数校验，不发请求
"""
from __future__ import annotations

import argparse
import os
import secrets
import string
import sys
import threading
import time
from datetime import datetime
from typing import Callable, List, Optional

from app_config import load_config, validate_config
from app_paths import default_accounts_path
import mail_service
import mozilla_api
import register_browser
from register_mozilla import register_one
_LOCK = threading.Lock()
_OUTPUT_LINE_PREFIXES = ("[+]", "[*]", "[!]", "[Debug]", "---")


class _ThreadLog:
    def __init__(self):
        self._lock = threading.Lock()

    def __call__(self, message: str) -> None:
        with self._lock:
            print(message, flush=True)


def _line_prefix_filter(log: Callable[[str], None], email: str) -> Callable[[str], None]:
    def wrapped(message: str) -> None:
        if message.startswith(("[+]", "[*]", "[!]")):
            log(f"[{email}] {message}")
        else:
            log(message)
    return wrapped


def _thread_log_for(log: Callable[[str], None], email: str) -> Callable[[str], None]:
    return _line_prefix_filter(log, email)


def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#_-"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _run_one(
    email: Optional[str],
    config: dict,
    log: Callable[[str], None],
    account_path: str,
    mail_credential_dir: str,
    auth_client: Optional[mozilla_api.MozillaAuthClient],
    backend: str = "api",
):
    try:
        if backend == "browser":
            if email is None:
                # 浏览器后端需要显式邮箱；从 cloudmail 生成临时邮箱
                email, credential = mail_service.get_email_and_token()
                log(f"[*] 已生成临时邮箱: {email}")
                if mail_credential_dir:
                    from account_outputs import save_mail_credential

                    save_mail_credential(mail_credential_dir, email, credential)
            result = register_browser.register_one_browser(
                email=email,
                password=generate_password(),
                config=config,
                log_callback=log,
            )
            if result and account_path:
                from account_outputs import append_account_line

                append_account_line(
                    account_path,
                    result["email"],
                    result["password"],
                    "browser-verified",
                )
        else:
            result = register_one(
                email=email,
                password=None,
                config=config,
                auth_client=auth_client,
                log_callback=log,
                account_path=account_path,
                mail_credential_dir=mail_credential_dir,
            )
        return result
    except Exception as exc:
        log(f"[!] 注册失败 {email or '?'}: {exc}")
        return None


def _read_emails_file(path: str) -> List[str]:
    emails = []
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            email = raw.strip()
            if email and "@" in email and not email.startswith("#"):
                emails.append(email)
    return emails


def register_batch(
    emails: Optional[List[str]],
    config: dict,
    log: Callable[[str], None],
    account_path: str,
    mail_credential_dir: str,
    threads: int = 1,
    thread_start_interval: float = 3.0,
    cancel_callback: Optional[Callable[[], None]] = None,
    backend: str = "api",
) -> int:
    """批量注册。返回成功数。

    emails 为 None 时按 config.register_count 生成临时邮箱。
    每线程一个 auth client（各自独立 Session/Cookie）；
    backend=browser 时走 cloakbrowser 注册页（每线程独立浏览器实例）。
    """
    if emails is not None and emails:
        work: List[Optional[str]] = list(emails)
        total = len(work)
    else:
        count = int(config.get("register_count", 1) or 1)
        work = [None] * count
        total = count

    if not work:
        log("[!] 没有待注册的邮箱")
        return 0

    results: List[dict] = []
    results_lock = threading.Lock()
    index = 0
    index_lock = threading.Lock()

    def worker():
        nonlocal index
        client = None
        if backend == "api":
            client = mozilla_api.MozillaAuthClient(
                base=config.get("auth_base", mozilla_api.AUTH_BASE),
                user_agent=config.get("user_agent", ""),
                proxy=config.get("proxy", ""),
                timeout=int(config.get("request_timeout", 30) or 30),
            )
        try:
            while True:
                with index_lock:
                    if index >= total:
                        break
                    i = index
                    index += 1
                email = work[i]
                tlog = _thread_log_for(log, email or "auto")
                # 并发启动间隔
                if i > 0 and threads > 1:
                    time.sleep(thread_start_interval * (i % threads))
                result = _run_one(
                    email,
                    config,
                    tlog,
                    account_path,
                    mail_credential_dir,
                    auth_client=client,
                    backend=backend,
                )
                if result:
                    with results_lock:
                        results.append(result)
        finally:
            if client is not None:
                client.close()

    thread_list = []
    for _ in range(max(1, threads)):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        thread_list.append(t)
    for t in thread_list:
        t.join()

    return len(results)


def _dry_run(config: dict, log: Callable[[str], None]) -> int:
    """只做参数校验与派生测试，不发任何网络请求。"""
    from mozilla_crypto import get_auth_pw

    # 邮箱只用于派生测试；未配置 cloudmail 时用占位邮箱，避免联网
    email = "dryrun@example.com"
    if (
        mail_service.get_email_provider() == "cloudmail"
        and mail_service.get_cloudmail_api_base()
        and mail_service.get_cloudmail_public_token()
    ):
        try:
            email, _ = mail_service.cloudmail_get_email_and_token()
        except Exception:
            pass
    pw = generate_password()
    auth_pw = get_auth_pw(email, pw)
    log(f"[*] 派生测试通过: email={email}")
    log(f"[*] authPW={auth_pw[:16]}...")
    log(f"[*] 配置合法，可开始注册（dry-run 未发请求）")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="register",
        description="Mozilla 账号注册机",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n  python register.py --count 3\n  python register.py --emails emails.txt --threads 2\n  python register.py --dry-run",
    )
    parser.add_argument("--config", default=None, help="配置文件路径（默认 config.json）")
    parser.add_argument("--count", type=int, default=None, help="注册数量（覆盖配置）")
    parser.add_argument("--emails", default=None, help="邮箱列表文件，每行一个邮箱")
    parser.add_argument("--threads", type=int, default=None, help="并发线程数（覆盖配置）")
    parser.add_argument("--out", default=None, help="账号输出文件（默认 accounts_<时间戳>.txt）")
    parser.add_argument("--dry-run", action="store_true", help="只校验配置与派生，不发请求")
    parser.add_argument(
        "--backend",
        choices=("api", "browser"),
        default=None,
        help="注册后端：api=纯 HTTP onepw 协议（默认，可能被 WAF 拦）；browser=cloakbrowser 注册页（需安装依赖）",
    )
    args = parser.parse_args(argv)

    config = load_config(path=args.config)
    try:
        validate_config(config)
    except Exception as exc:
        print(f"[!] 配置校验失败: {exc}", file=sys.stderr)
        return 2

    log = _ThreadLog()

    if args.count is not None:
        config["register_count"] = args.count
    if args.threads is not None:
        config["register_threads"] = args.threads

    email_list = None
    if args.emails:
        if not os.path.isfile(args.emails):
            print(f"[!] 邮箱列表文件不存在: {args.emails}", file=sys.stderr)
            return 2
        email_list = _read_emails_file(args.emails)
        if not email_list:
            print(f"[!] 邮箱列表为空: {args.emails}", file=sys.stderr)
            return 2

    if args.dry_run:
        return _dry_run(config, log)

    backend = args.backend or str(config.get("register_backend", "api") or "api")
    if backend == "browser":
        try:
            register_browser._ensure_cloakbrowser()
        except Exception as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 2

    if email_list is None and config.get("emails_file"):
        path = config.get("emails_file")
        if os.path.isfile(path):
            email_list = _read_emails_file(path)

    # 绑定运行时（mail_service 读 config）
    mail_service.bind_runtime({"config": config})

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    account_path = args.out or default_accounts_path(timestamp)
    mail_credential_dir = "."

    log(f"[*] 输出文件: {account_path}")
    log(f"[*] 注册后端: {backend}")
    threads = int(config.get("register_threads", 1) or 1)
    interval = float(config.get("thread_start_interval", 3) or 3)

    ok = register_batch(
        email_list,
        config,
        log,
        account_path,
        mail_credential_dir,
        threads=threads,
        thread_start_interval=interval,
        backend=backend,
    )
    log(f"--- 完成: 成功 {ok} / 共 {(len(email_list) if email_list else int(config.get('register_count', 1) or 1))}")
    return 0 if ok > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
