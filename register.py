#!/usr/bin/env python3
"""Mozilla 账号注册机入口（CLI）。

支持：
  - 自动生成临时邮箱（cloudmail）+ 随机密码 注册 N 个账号
  - 从 CSV/文本文件读取邮箱列表批量注册（每行一个邮箱）
  - 浏览器后端注册后把 FxA 会话桥接给 fxpool-proxy（凭据包 / renewal_credentials.json）
  - 用已有账号登录（--signin）只生成会话，不创建账号
  - 并发控制（register_threads）

用法：
  python register.py                       # 按 config.json 注册 register_count 个（API 后端）
  python register.py --count 5             # 注册 5 个
  python register.py --emails emails.txt   # 批量注册文件中的邮箱
  python register.py --backend browser     # 用浏览器后端（绕过生产 WAF，需 cloakbrowser）
  python register.py --backend browser --enroll --fxpool-root ~/.fxpool
  python register.py --backend browser --signin --emails accounts.txt
  python register.py --dry-run             # 只跑派生+参数校验，不发请求
"""
from __future__ import annotations

import argparse
import os
import re
import secrets
import string
import sys
import threading
import time
from datetime import datetime
from typing import Callable, List, Optional, Tuple

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


def _log_browser_outputs(result: Optional[dict], log: Callable[[str], None]) -> None:
    """输出浏览器后端的凭据桥接/开通结果（绝不打印 session token）。

    bridge 失败由 register_browser._finish_session 通过同一 log 回调打印
    ``[!] bridge: ...``，这里只补充成功路径的确认信息，避免重复。
    """
    if not isinstance(result, dict):
        return
    bundle_path = result.get("bundle_path")
    if bundle_path:
        log(f"[+] 续期凭据包: {os.path.abspath(bundle_path)}")
    credentials_path = result.get("credentials_path")
    if credentials_path:
        log(f"[+] 已写入 fxpool 凭据: {os.path.abspath(credentials_path)}")
    entitlement = result.get("entitlement")
    if result.get("enrolled") and isinstance(entitlement, dict):
        limited = "true" if entitlement.get("limited_bandwidth") is True else "false"
        log(
            f"[+] 开通成功: entitlement uid={entitlement.get('uid')} "
            f"limited_bandwidth={limited}"
        )


def _run_one(
    email: Optional[str],
    config: dict,
    log: Callable[[str], None],
    account_path: str,
    mail_credential_dir: str,
    auth_client: Optional[mozilla_api.MozillaAuthClient],
    backend: str = "api",
    browser_options: Optional[dict] = None,
    signin: bool = False,
    password: Optional[str] = None,
):
    try:
        if backend == "browser":
            options = dict(browser_options or {})
            if signin:
                if not email or password is None:
                    raise ValueError("--signin 需要 email----password 账号行")
                result = register_browser.ensure_session_browser(
                    email=email,
                    password=password,
                    config=config,
                    log_callback=log,
                    **options,
                )
                _log_browser_outputs(result, log)
                return result

            if email is None:
                # 浏览器后端需要显式邮箱；从 cloudmail 生成临时邮箱
                email, credential = mail_service.get_email_and_token()
                log(f"[*] 已生成临时邮箱: {email}")
                if mail_credential_dir:
                    from account_outputs import save_mail_credential

                    save_mail_credential(mail_credential_dir, email, credential)
            created = {"email": None, "password": None}

            def _on_account_created(created_email: str, created_password: str) -> None:
                """账号在服务端创建后立即落盘，避免验证码/收尾失败丢账号。"""
                created["email"] = created_email
                created["password"] = created_password
                if not account_path:
                    return
                try:
                    from account_outputs import append_account_line

                    append_account_line(
                        account_path,
                        created_email,
                        created_password,
                        "created-unverified",
                    )
                    log("[*] 账号已创建，已立即保存 email----password（待验证）")
                except Exception as exc:
                    log(f"[!] 立即保存账号失败: {exc}")

            result = register_browser.register_one_browser(
                email=email,
                password=generate_password(),
                config=config,
                log_callback=log,
                on_account_created=_on_account_created,
                **options,
            )
            if result and account_path:
                from account_outputs import append_account_line, update_account_line_extra

                saved_email, saved_password = result["email"], result["password"]
                updated = (
                    created["email"] == saved_email
                    and created["password"] == saved_password
                    and update_account_line_extra(
                        account_path,
                        saved_email,
                        saved_password,
                        "created-unverified",
                        "browser-verified",
                    )
                )
                if not updated:
                    append_account_line(
                        account_path,
                        saved_email,
                        saved_password,
                        "browser-verified",
                    )
            _log_browser_outputs(result, log)
            return result

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
        action = "登录" if signin else "注册"
        log(f"[!] {action}失败 {email or '?'}: {exc}")
        return None


def _read_emails_file(path: str) -> List[str]:
    emails = []
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            email = raw.strip()
            if email and "@" in email and not email.startswith("#"):
                emails.append(email)
    return emails


def _is_account_marker(value: str) -> bool:
    """账号行末尾的附加字段（浏览器标记或 API 后端的 32 位 uid）。"""
    return value in ("browser-verified", "created-unverified") or bool(
        re.fullmatch(r"[0-9a-fA-F]{32}", value)
    )


def _read_accounts_file(path: str) -> List[Tuple[str, str]]:
    """读取登录账号文件：每行 email----password[----extra]。

    空行与 # 注释行跳过；password 是第一个 ---- 之后的内容（可再含 ----）。
    本工具自己写出的 ``accounts_*.txt`` 末尾还有第三个字段
    （``browser-verified`` / ``created-unverified`` / 32 位 uid），会被识别并
    丢弃，因此可以直接把生成的文件喂给 ``--signin --emails``。
    缺少分隔符或 email/password 为空时抛 ValueError，并带上行号。
    """
    accounts: List[Tuple[str, str]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for lineno, raw in enumerate(handle, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("----")
            if len(parts) < 2:
                raise ValueError(f"{path} 第 {lineno} 行缺少 ---- 分隔符: {line}")
            email = parts[0].strip()
            tail = parts[1:]
            if len(tail) >= 2 and _is_account_marker(tail[-1].strip()):
                tail = tail[:-1]
            password = "----".join(tail)
            if not email or not password:
                raise ValueError(f"{path} 第 {lineno} 行不是 email----password 格式")
            accounts.append((email, password))
    return accounts


def _resolve_browser_options(args, config: dict) -> dict:
    """解析 --enroll/--fxpool-root/--bundle-dir/--no-bridge 的有效值。"""
    enroll = args.enroll
    if enroll is None:
        enroll = bool(config.get("fxpool_enroll", False))
    fxpool_root = args.fxpool_root
    if fxpool_root is None:
        fxpool_root = str(config.get("fxpool_root", "") or "")
    if not fxpool_root:
        fxpool_root = os.environ.get("FXPOOL_ROOT", "") or ""
    bundle_dir = args.bundle_dir
    if bundle_dir is None:
        bundle_dir = str(config.get("bundle_dir", "") or "")
    return {
        "enroll": bool(enroll),
        "fxpool_root": fxpool_root or None,
        "bundle_dir": bundle_dir or None,
        "bridge": not args.no_bridge,
    }


def register_batch(
    emails: Optional[List],
    config: dict,
    log: Callable[[str], None],
    account_path: str,
    mail_credential_dir: str,
    threads: int = 1,
    thread_start_interval: float = 3.0,
    cancel_callback: Optional[Callable[[], None]] = None,
    backend: str = "api",
    browser_options: Optional[dict] = None,
    signin: bool = False,
) -> int:
    """批量注册（signin=True 时批量登录）。返回成功数。

    emails 为 None 时按 config.register_count 生成临时邮箱；
    signin=True 时 emails 是 (email, password) 元组列表。
    每线程一个 auth client（各自独立 Session/Cookie）；
    backend=browser 时走 cloakbrowser 注册页（每线程独立浏览器实例）。
    """
    if signin:
        work: List = list(emails or [])
        total = len(work)
    elif emails is not None and emails:
        work = list(emails)
        total = len(work)
    else:
        count = int(config.get("register_count", 1) or 1)
        work = [None] * count
        total = count

    if not work:
        log("[!] 没有待登录的账号" if signin else "[!] 没有待注册的邮箱")
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
                item = work[i]
                password = None
                if signin:
                    email, password = item
                else:
                    email = item
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
                    browser_options=browser_options,
                    signin=signin,
                    password=password,
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
    """只做参数校验与派生测试，不发任何网络请求、不写文件。"""
    from mozilla_crypto import get_auth_pw

    email = "dryrun@example.com"
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
        epilog=(
            "示例:\n"
            "  python register.py --count 3\n"
            "  python register.py --emails emails.txt --threads 2\n"
            "  python register.py --backend browser --enroll --fxpool-root ~/.fxpool\n"
            "  python register.py --backend browser --signin --emails accounts.txt\n"
            "  python register.py --dry-run"
        ),
    )
    parser.add_argument("--config", default=None, help="配置文件路径（默认 config.json）")
    parser.add_argument("--count", type=int, default=None, help="注册数量（覆盖配置）")
    parser.add_argument(
        "--emails",
        default=None,
        help="邮箱列表文件，每行一个邮箱（--signin 时每行为 email----password）",
    )
    parser.add_argument("--threads", type=int, default=None, help="并发线程数（覆盖配置）")
    parser.add_argument("--out", default=None, help="账号输出文件（默认 accounts_<时间戳>.txt）")
    parser.add_argument("--dry-run", action="store_true", help="只校验配置与派生，不发请求")
    parser.add_argument(
        "--backend",
        choices=("api", "browser"),
        default=None,
        help="注册后端：api=纯 HTTP onepw 协议（默认，可能被 WAF 拦）；browser=cloakbrowser 注册页（需安装依赖）",
    )
    parser.add_argument(
        "--enroll",
        action="store_true",
        default=None,
        help="注册/登录后执行一次开通（GET vpn.mozilla.org/api/v1/fpn/auth，每账号仅一次）",
    )
    parser.add_argument(
        "--fxpool-root",
        default=None,
        metavar="PATH",
        help="写入 <PATH>/tokens/renewal_credentials.json（默认 config.fxpool_root，其次环境变量 FXPOOL_ROOT）",
    )
    parser.add_argument(
        "--bundle-dir",
        default=None,
        metavar="DIR",
        help="为每个账号写入 <DIR>/<uid>.json 凭据包（默认 config.bundle_dir，空=关闭）",
    )
    parser.add_argument(
        "--no-bridge",
        action="store_true",
        help="不写凭据包与 renewal_credentials.json",
    )
    parser.add_argument(
        "--signin",
        action="store_true",
        help="只登录已有账号生成会话，不创建账号（需 --backend browser）",
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

    backend = args.backend or str(config.get("register_backend", "api") or "api")
    browser_options = _resolve_browser_options(args, config)

    # 新增选项只对浏览器后端有意义。这里只看显式传入的 CLI 参数：
    # config.json 里的 fxpool_root/bundle_dir 在 api 后端下应当是无害的，
    # 不能因为配置里存在就让所有默认运行都退出 2。
    explicit_browser_only = []
    if args.enroll:
        explicit_browser_only.append("--enroll")
    if args.fxpool_root is not None and args.fxpool_root != "":
        explicit_browser_only.append("--fxpool-root")
    if args.bundle_dir is not None and args.bundle_dir != "":
        explicit_browser_only.append("--bundle-dir")
    if args.no_bridge:
        explicit_browser_only.append("--no-bridge")
    if args.signin:
        explicit_browser_only.append("--signin")
    if backend == "api" and explicit_browser_only:
        print(
            "[!] 这些选项需要 --backend browser: " + ", ".join(explicit_browser_only),
            file=sys.stderr,
        )
        return 2
    if backend == "api" and bool(config.get("fxpool_enroll", False)):
        print(
            "[!] 配置项 fxpool_enroll=true 需要 register_backend=browser "
            "或 --backend browser",
            file=sys.stderr,
        )
        return 2
    if backend == "api" and (config.get("fxpool_root") or config.get("bundle_dir")):
        log("[!] 忽略配置项 fxpool_root/bundle_dir：仅浏览器后端使用")

    email_list: Optional[List] = None
    if args.emails:
        if not os.path.isfile(args.emails):
            print(f"[!] 邮箱列表文件不存在: {args.emails}", file=sys.stderr)
            return 2
        if args.signin:
            try:
                email_list = _read_accounts_file(args.emails)
            except ValueError as exc:
                print(f"[!] {exc}", file=sys.stderr)
                return 2
            if not email_list:
                print(f"[!] 账号列表为空: {args.emails}", file=sys.stderr)
                return 2
        else:
            email_list = _read_emails_file(args.emails)
            if not email_list:
                print(f"[!] 邮箱列表为空: {args.emails}", file=sys.stderr)
                return 2
    elif args.signin:
        path = str(config.get("emails_file", "") or "")
        if not path:
            print(
                "[!] --signin 需要账号来源：--emails 或配置 emails_file（每行 email----password）",
                file=sys.stderr,
            )
            return 2
        if not os.path.isfile(path):
            print(f"[!] 邮箱列表文件不存在: {path}", file=sys.stderr)
            return 2
        try:
            email_list = _read_accounts_file(path)
        except ValueError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 2
        if not email_list:
            print(f"[!] 账号列表为空: {path}", file=sys.stderr)
            return 2
    elif config.get("emails_file"):
        path = config.get("emails_file")
        if os.path.isfile(path):
            email_list = _read_emails_file(path)

    if args.dry_run:
        return _dry_run(config, log)

    if backend == "browser":
        try:
            register_browser._ensure_cloakbrowser()
        except Exception as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 2

    # 绑定运行时（mail_service 读 config）
    mail_service.bind_runtime({"config": config})

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    account_path = args.out or default_accounts_path(timestamp)
    mail_credential_dir = "."

    if args.signin:
        log("[*] 模式: signin（登录已有账号生成会话，不写账号文件）")
    else:
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
        browser_options=browser_options,
        signin=args.signin,
    )
    if args.signin:
        total = len(email_list or [])
    else:
        total = len(email_list) if email_list else int(config.get("register_count", 1) or 1)
    log(f"--- 完成: 成功 {ok} / 共 {total}")
    return 0 if ok > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
