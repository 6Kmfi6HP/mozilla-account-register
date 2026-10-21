#!/usr/bin/env python3
"""批量把 fxpool_bridge 凭据包导入 fxpool-proxy 账号池。

register.py 配置 bundle_dir 后，每个注册成功的账号会在 bundle_dir
留下 <uid>.json 凭据包。本脚本扫该目录，对每个调 ``fxpool-proxy
import-credentials``，把账号写进 fxpool 的 SQLite 账号池；成功后删除凭据包
（--delete-source），失败则保留以便重试。

用法：
    python register.py --backend browser --bundle-dir ./bundles
    python import_bundles.py --bundle-dir ./bundles \\
        --fxpool-root /path/to/fxpool-root --fxpool-bin /path/to/fxpool-proxy
    fxpool-proxy accounts --root /path/to/fxpool-root

默认 --no-verify（离线导入，首次取 token 时 fxpool-proxy 自行刷新）。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

_SCHEMA = "firefox-ip-protection-renewal-credentials-v1"
_UID_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def _find_bin(hint: str | None, root: str | None) -> str:
    if hint:
        p = os.path.expanduser(hint)
        if os.path.isfile(p):
            return p
        cand = os.path.join(p, "fxpool-proxy")
        return cand if os.path.isfile(cand) else p
    if root:
        cand = os.path.join(os.path.expanduser(root), "fxpool-proxy")
        if os.path.isfile(cand):
            return cand
    found = shutil.which("fxpool-proxy")
    if found:
        return found
    raise FileNotFoundError("找不到 fxpool-proxy：用 --fxpool-bin 指定，或放进 PATH")


def _is_bundle(path: Path) -> bool:
    if not path.is_file() or path.suffix != ".json" or not _UID_RE.match(path.stem):
        return False
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and data.get("schema") == _SCHEMA


def _import_one(bin_: str, bundle: Path, root: str, verify: bool, delete: bool) -> tuple[bool, str]:
    args = [bin_, "import-credentials", str(bundle), "--root", root]
    if not verify:
        args.append("--no-verify")
    if delete:
        args.append("--delete-source")
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return False, "超时（120s）"
    except OSError as exc:
        return False, f"执行失败: {exc}"
    if proc.returncode != 0:
        out = (proc.stderr or proc.stdout or "").strip().splitlines()
        tail = out[-1] if out else ""
        return False, f"exit={proc.returncode} {tail}"
    return True, "ok"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="批量导入 fxpool_bridge 凭据包到 fxpool-proxy 账号池",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--bundle-dir", required=True, help="register_browser 写凭据包的目录")
    p.add_argument("--fxpool-root", required=True, help="fxpool-proxy 工作目录（含 data/、store db）")
    p.add_argument("--fxpool-bin", default=None, help="fxpool-proxy 可执行文件路径")
    p.add_argument("--verify", action="store_true", help="导入时联网验证 token（默认离线）")
    p.add_argument("--keep", action="store_true", help="导入成功后保留凭据包（默认删除）")
    p.add_argument("--dry-run", action="store_true", help="只列出凭据包不执行")
    args = p.parse_args(argv)

    bdir = Path(os.path.expanduser(args.bundle_dir))
    if not bdir.is_dir():
        print(f"[!] bundle-dir 不存在: {bdir}", file=sys.stderr)
        return 2
    root = os.path.expanduser(args.fxpool_root)
    if not os.path.isdir(root):
        print(f"[!] fxpool-root 不存在: {root}", file=sys.stderr)
        return 2

    bundles = sorted(x for x in bdir.iterdir() if _is_bundle(x))
    if not bundles:
        print(f"[i] {bdir} 无凭据包（<32hex>.json，schema={_SCHEMA}）")
        return 0

    if args.dry_run:
        print(f"[i] 将导入 {len(bundles)} 个凭据包到 {root}:")
        for b in bundles:
            print(f"    {b.name}")
        return 0

    try:
        bin_ = _find_bin(args.fxpool_bin, root)
    except FileNotFoundError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2

    delete = not args.keep
    ok = fail = 0
    for b in bundles:
        success, msg = _import_one(bin_, b, root, args.verify, delete)
        if success:
            ok += 1
            print(f"[+] {b.name} ok")
        else:
            fail += 1
            print(f"[-] {b.name} {msg}", file=sys.stderr)
    print(f"[done] 成功 {ok} 失败 {fail} 共 {len(bundles)}")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
