"""可移植的应用程序根目录解析（开发与 PyInstaller 冻结运行）。

用户可写数据始终解析到可执行文件旁边（冻结时），绝不放在只读的
``sys._MEIPASS`` bundle 树内。
"""
from __future__ import annotations

import os
import shutil
import sys

__version__ = "0.1.0"


def is_frozen() -> bool:
    """判断是否在 PyInstaller（或类似）bundle 内运行。"""
    return bool(getattr(sys, "frozen", False)) or hasattr(sys, "_MEIPASS")


def get_resource_root() -> str:
    """只读根：开发时为源码树，冻结时为 _MEIPASS。"""
    meipass = getattr(sys, "_MEIPASS", None)
    if is_frozen() and meipass:
        return os.path.abspath(str(meipass))
    return os.path.dirname(os.path.abspath(__file__))


def get_app_root() -> str:
    """用户可写根：开发时为源码目录，冻结时为可执行文件所在目录。"""
    if is_frozen():
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def user_path(*parts: str) -> str:
    """把路径段拼到可写的应用根目录下。"""
    return os.path.join(get_app_root(), *parts)


def resource_path(*parts: str) -> str:
    """把路径段拼到只读的资源根目录下。"""
    return os.path.join(get_resource_root(), *parts)


def ensure_user_data_layout(copy_example: bool = True) -> str:
    """确保可写应用根存在，并在缺失时播种 config.example.json。

    不会创建或覆盖真实的 config.json（可能含密钥）。
    """
    root = get_app_root()
    try:
        os.makedirs(root, exist_ok=True)
    except OSError:
        pass

    if copy_example:
        dest = os.path.join(root, "config.example.json")
        if not os.path.isfile(dest):
            candidates = [
                resource_path("config.example.json"),
                os.path.join(root, "config.example.json"),
            ]
            for src in candidates:
                if os.path.isfile(src) and os.path.normcase(os.path.abspath(src)) != os.path.normcase(
                    os.path.abspath(dest)
                ):
                    try:
                        shutil.copy2(src, dest)
                    except OSError:
                        pass
                    break
    return root


def default_config_path() -> str:
    return user_path("config.json")


def default_accounts_path(timestamp: str) -> str:
    return user_path(f"accounts_{timestamp}.txt")


def default_mail_credentials_path() -> str:
    return user_path("mail_credentials.txt")
