"""账号结果与邮箱凭证的安全持久化。

输出格式：
    账号行: {email}----{password}----{extra}\n  （Mozilla 无 token 时 extra 可存 uid）
    邮箱凭证: {email}\t{credential}\n
均先 fsync 再返回，保证批量中断不丢。
"""
from __future__ import annotations

import os


def append_account_line(path, email, password, extra=""):
    """追加一行账号记录：email----password[----extra]。"""
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"{email}----{password}----{extra}\n")
        handle.flush()
        os.fsync(handle.fileno())
    return True


def save_mail_credential(base_dir, email, credential):
    """把邮箱与凭证追加到 mail_credentials.txt。"""
    path = os.path.join(base_dir, "mail_credentials.txt")
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"{email}\t{credential}\n")
        handle.flush()
        os.fsync(handle.fileno())
    return True
