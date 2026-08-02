"""浏览器注册后端（cloakbrowser 自动化）。

生产环境对 auth API 的 POST 走 Fastly WAF 拦截（纯 HTTP /account/create 会
406），因此提供浏览器后端：用反检测浏览器走真实注册页完成注册。

依赖（可选，未安装时调用会给出明确错误）：
    cloakbrowser>=0.4   （反检测 Chromium，内部依赖 playwright）

主流程与官方网页一致：
    1. 填邮箱 -> 提交，绕过 Client Challenge 到达注册页
    2. cloudmail 轮询 6 位注册验证码 -> 填入 -> Confirm（账号创建+登录）
    3. settings/create_password 触发二次验证（confirmationCode）-> 填入
    4. 设置新密码 + 确认密码 -> Save

与 register_mozilla（API 后端）接口对齐，方便 register_batch 按后端分派。
"""
from __future__ import annotations

import time
from typing import Callable, Optional

import mail_service

# 可选依赖：cloakbrowser 未安装时给出明确提示
try:
    import cloakbrowser
except Exception as exc:  # pragma: no cover - 依赖可选
    cloakbrowser = None
    _CLOAK_IMPORT_ERROR = exc
else:
    _CLOAK_IMPORT_ERROR = None

# 选择器（来自真实注册页 DOM，随官方前端可能变动）
_SEL_EMAIL = "input[name=email]"
_SEL_REG_CODE = "input[name=code]"
_SEL_CONFIRM_CODE = "input[name=confirmationCode]"
_SEL_PASSWORD = "input[name=password], input[type=password]"
_SEL_SUBMIT_ENABLED = "button[type=submit]:not([disabled])"
_SEL_SAVE_ENABLED = 'button:has-text("Save"):not([disabled])'
_SEL_SAVE = 'button:has-text("Save")'


class BrowserRegisterError(RuntimeError):
    pass


class RegisterCancelled(Exception):
    pass


def _ensure_cloakbrowser() -> None:
    if cloakbrowser is None:
        raise BrowserRegisterError(
            "浏览器后端需要 cloakbrowser，请安装: "
            "pip install cloakbrowser  (或复用已装 cloakbrowser 的虚拟环境)；"
            f"导入错误: {_CLOAK_IMPORT_ERROR}"
        )


def _wait_code(page, email, timeout, poll_interval, first_code, log, cancel) -> str:
    """轮询 cloudmail 提取验证码，返回 6 位数字。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cancel:
            cancel()
        try:
            msgs = mail_service.cloudmail_get_messages(email)
        except Exception as exc:
            if log:
                log(f"[Debug] Cloud Mail 拉取失败: {exc}")
            time.sleep(poll_interval)
            continue
        for msg in msgs:
            subject = str(msg.get("subject", "") or "")
            body = mail_service.normalize_mail_body(msg)
            code = mail_service.extract_verification_code(body, subject)
            # first_code 传入时用于区分"二次验证码"与"注册验证码"
            if code and (first_code is None or code != first_code):
                return code
        time.sleep(poll_interval)
    raise BrowserRegisterError(f"{email} 在 {timeout}s 内未收到验证码邮件")


def _click_submit_or(page, fallback_text: str, log) -> None:
    """优先点 type=submit 的启用按钮，失败则按文本兜底（force）。"""
    try:
        page.wait_for_selector(_SEL_SUBMIT_ENABLED, timeout=8000)
        page.click("button[type=submit]", timeout=5000)
    except Exception:
        page.click(f'button:has-text("{fallback_text}")', timeout=5000, force=True)


def register_one_browser(
    email: str,
    password: str,
    config: Optional[dict] = None,
    log_callback: Optional[Callable[[str], None]] = None,
    cancel_callback: Optional[Callable[[], None]] = None,
    account_path: Optional[str] = None,
    mail_credential_dir: Optional[str] = None,
) -> dict:
    """用浏览器注册一个 Mozilla 账号，返回结果 dict。

    与 register_mozilla.register_one 的签名对齐；email/password 必须由调用方
    显式传入（浏览器后端不自动生成临时邮箱）。
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
        log("[*] 启动反检测浏览器 (cloakbrowser)")
        browser = cloakbrowser.launch(headless=True, humanize=True)
        page = browser.new_page()

        cancel()
        log("[*] 打开 Mozilla 账号注册页")
        page.goto(
            "https://accounts.firefox.com/signup",
            timeout=90000,
            wait_until="domcontentloaded",
        )
        # 绕过 Client Challenge 后到达真实注册页
        page.wait_for_selector(_SEL_EMAIL, timeout=60000)
        log("[*] 已通过 Client Challenge，到达注册页")

        cancel()
        page.fill(_SEL_EMAIL, email)
        page.click("button[type=submit]", timeout=10000)
        log("[*] 已提交邮箱，等待注册验证码输入页")
        page.wait_for_selector(_SEL_REG_CODE, timeout=60000)

        # 注册验证码（第一封邮件）
        reg_code = _wait_code(
            page, email, timeout, poll_interval, None, log, cancel
        )
        log(f"[*] 注册验证码: {reg_code}")
        cancel()
        page.fill(_SEL_REG_CODE, reg_code)
        _click_submit_or(page, "Confirm", log)
        log("[*] 已提交注册验证码")

        # 账号创建后落地 /settings（无密码注册流），再去设置密码
        page.wait_for_url("**/settings**", timeout=60000)
        time.sleep(6)  # 等 SPA 导航渲染
        log("[*] 账号已创建并登录，进入设置密码页")
        page.goto(
            "https://accounts.firefox.com/settings/create_password",
            timeout=30000,
            wait_until="domcontentloaded",
        )

        # 改设置需二次验证：若页面直接给密码框则跳过，否则先收二次验证码
        has_pw = False
        try:
            page.wait_for_selector(_SEL_PASSWORD, state="attached", timeout=3000)
            has_pw = True
        except Exception:
            has_pw = False
        if not has_pw:
            page.wait_for_selector(_SEL_CONFIRM_CODE, timeout=20000)
            log("[*] create_password 页要求二次验证，等待二次验证码")
            confirm_code = _wait_code(
                page, email, timeout, poll_interval, reg_code, log, cancel
            )
            log(f"[*] 二次验证码: {confirm_code}")
            cancel()
            page.fill(_SEL_CONFIRM_CODE, confirm_code)
            _click_submit_or(page, "Confirm", log)
            page.wait_for_selector(_SEL_PASSWORD, timeout=20000)

        # 设置新密码 + 确认密码（密码框可能被可见性图标 SPAN 覆盖，需 force）
        cancel()
        pw_fields = page.query_selector_all(_SEL_PASSWORD)
        for idx, field in enumerate(pw_fields):
            fname = field.get_attribute("name") or (
                "newPassword" if idx == 0 else "confirmPassword"
            )
            page.fill(f"input[name={fname}]", password, force=True)
        time.sleep(0.5)
        # Save 按钮初始 disabled，填完密码后启用
        try:
            page.wait_for_selector(_SEL_SAVE_ENABLED, timeout=10000)
            page.click(_SEL_SAVE, timeout=5000, force=True)
        except Exception:
            page.click(_SEL_SAVE, timeout=5000, force=True)
        log("[*] 已提交密码设置")

        # 回落到 /settings#password，确认密码已设
        time.sleep(4)
        page.wait_for_url("**/settings**", timeout=30000)
        body = page.inner_text("body")
        password_set = "Password set" in body or page.url.endswith("#password")

        result = {
            "email": email,
            "password": password,
            "verified": True,
            "password_set": password_set,
        }
        if password_set:
            log("[+] 密码设置成功，账号完全可用")
        else:
            log("[!] 账号已创建但未能确认密码设置（可能页面结构变化）")
        return result
    finally:
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
