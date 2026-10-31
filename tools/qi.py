#!/usr/bin/env python3
"""Query the 24A446 decompiler cache (query-index.json) offline.

Read-only. Used to close OPEN claims that only need "what does this function do"
without re-running Ghidra.

Examples:
  python3 -B firmware/tools/qi.py sym timeoutCallback
  python3 -B firmware/tools/qi.py fn 0x100074678
  python3 -B firmware/tools/qi.py callers 0x100074678
  python3 -B firmware/tools/qi.py callees 0x100074678
  python3 -B firmware/tools/qi.py grep "0x141"
  python3 -B firmware/tools/qi.py find "UseCarPlayHEVC"
"""
from __future__ import annotations

import argparse
import io
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# c_path in the index is relative to firmware/, not the repo root.
ASSET_ROOT = ROOT / "firmware"
CACHE = ASSET_ROOT / "analysis" / "decompiler-cache" / "24A446"
INDEX = CACHE / "query-index.json"

_cache: dict | None = None


def index() -> dict:
    global _cache
    if _cache is None:
        with io.open(INDEX, encoding="utf-8") as fh:
            _cache = json.load(fh)
    return _cache


def norm(addr: str) -> str:
    a = addr.strip().lower()
    if not a.startswith("0x"):
        a = "0x" + a
    return hex(int(a, 16))


def matches(query: str) -> list[tuple[str, dict]]:
    q = query.lower()
    out = []
    for addr, row in index()["functions"].items():
        names = [row.get("ghidra_name") or ""] + (row.get("symbols") or [])
        if any(q in (n or "").lower() for n in names):
            out.append((addr, row))
    out.sort(key=lambda kv: int(kv[0], 16))
    return out


def cpath(row: dict) -> Path | None:
    p = row.get("c_path")
    return ASSET_ROOT / p if p else None


def read_c(row: dict) -> str:
    p = cpath(row)
    if not p or not p.exists():
        return f"<no C output: status={row.get('status')} diagnostic={row.get('diagnostic')}>"
    return p.read_text(encoding="utf-8", errors="replace")


def cmd_sym(args) -> int:
    rows = matches(args.query)
    if not rows:
        print(f"no symbol matching {args.query!r}")
        return 1
    for addr, row in rows:
        print(f"{addr}  {row['component']:<18} {row.get('ghidra_name')}  {row.get('signature')}")
        if args.show:
            print(read_c(row))
        print()
    return 0


def cmd_fn(args) -> int:
    addr = norm(args.address)
    row = index()["functions"].get(addr)
    if not row:
        print(f"address {addr} not in cache")
        return 1
    print(f"{addr}  {row['component']}  {row.get('ghidra_name')}")
    print(f"signature: {row.get('signature')}")
    print(f"status: {row.get('status')}  diagnostic: {row.get('diagnostic')}")
    print("-" * 70)
    print(read_c(row))
    return 0


def cmd_callers(args) -> int:
    addr = norm(args.address)
    callers = index().get("callers", {}).get(addr, [])
    print(f"callers of {addr}: {len(callers)}")
    for c in callers:
        row = index()["functions"].get(c if isinstance(c, str) else c.get("address"), {})
        print(f"  {c}  {row.get('component','')}  {row.get('ghidra_name','')}")
    return 0


def cmd_callees(args) -> int:
    addr = norm(args.address)
    callees = index().get("callees", {}).get(addr, [])
    print(f"callees of {addr}: {len(callees)}")
    for c in callees:
        key = c if isinstance(c, str) else c.get("address")
        row = index()["functions"].get(key, {})
        print(f"  {c}  {row.get('component','')}  {row.get('ghidra_name','')}")
    return 0


def cmd_find(args) -> int:
    """Substring search across all decompiled C bodies."""
    pat = args.text
    rx = re.compile(pat, re.I) if args.regex else None
    hits = 0
    for addr, row in index()["functions"].items():
        p = cpath(row)
        if not p or not p.exists():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = []
        for i, line in enumerate(text.splitlines(), 1):
            ok = rx.search(line) if rx else (pat.lower() in line.lower())
            if ok:
                lines.append((i, line.rstrip()))
        if lines:
            hits += 1
            print(f"== {addr}  {row['component']}  {row.get('ghidra_name')}")
            for i, line in lines[: args.max_lines]:
                print(f"   {i}: {line}")
            print()
    print(f"{hits} functions matched")
    return 0 if hits else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("sym")
    p.add_argument("query")
    p.add_argument("--show", action="store_true")
    p.set_defaults(func=cmd_sym)

    p = sub.add_parser("fn")
    p.add_argument("address")
    p.set_defaults(func=cmd_fn)

    p = sub.add_parser("callers")
    p.add_argument("address")
    p.set_defaults(func=cmd_callers)

    p = sub.add_parser("callees")
    p.add_argument("address")
    p.set_defaults(func=cmd_callees)

    p = sub.add_parser("find")
    p.add_argument("text")
    p.add_argument("--regex", action="store_true")
    p.add_argument("--max-lines", type=int, default=6)
    p.set_defaults(func=cmd_find)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
