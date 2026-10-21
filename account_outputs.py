"""账号结果与邮箱凭证的安全持久化。

输出格式：
    账号行: {email}----{password}----{extra}\n  （Mozilla 无 token 时 extra 可存 uid）
    邮箱凭证: {email}\t{credential}\n
均先 fsync 再返回，保证批量中断不丢。

浏览器后端在点击 "Create account" 后立即写入
``email----password----created-unverified``，流程成功后再把该行的 extra
原子更新为 ``browser-verified``；这样验证码邮件迟到/失败也不会丢失已创建
账号的密码。
"""
from __future__ import annotations

import os
import tempfile
import threading

_ACCOUNT_LOCK = threading.RLock()


def append_account_line(path, email, password, extra=""):
    """追加一行账号记录：email----password[----extra]。"""
    with _ACCOUNT_LOCK:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(f"{email}----{password}----{extra}\n")
            handle.flush()
            os.fsync(handle.fileno())
    return True


def update_account_line_extra(path, email, password, old_extra, new_extra):
    """把已存在的一行账号记录的 extra 原地改成 new_extra。

    原子重写（同目录临时文件 + os.replace），保留原文件权限；返回 True
    表示找到并更新，False 表示目标行不存在（调用方可退回追加）。
    多线程追加与更新由模块级锁串行化，避免重写时丢掉其他线程刚写的行。
    """
    needle = f"{email}----{password}----{old_extra}\n"
    replacement = f"{email}----{password}----{new_extra}\n"
    with _ACCOUNT_LOCK:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                lines = handle.readlines()
        except FileNotFoundError:
            return False
        try:
            index = lines.index(needle)
        except ValueError:
            return False
        lines[index] = replacement

        directory = os.path.dirname(os.path.abspath(path)) or "."
        try:
            mode = os.stat(path).st_mode & 0o777
        except OSError:
            mode = 0o600
        fd, temp_path = tempfile.mkstemp(prefix=".accounts-", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.writelines(lines)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_path, mode)
            os.replace(temp_path, path)
            temp_path = None
        finally:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)
    return True


def save_mail_credential(base_dir, email, credential):
    """把邮箱与凭证追加到 mail_credentials.txt。"""
    path = os.path.join(base_dir, "mail_credentials.txt")
    with _ACCOUNT_LOCK:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(f"{email}\t{credential}\n")
            handle.flush()
            os.fsync(handle.fileno())
    return True
