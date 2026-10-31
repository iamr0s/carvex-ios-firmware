#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Print symbols whose name matches a regular expression.

Usage:
  python3 grep-symbols.py <symbols.json> <regex> [--defined-only]

symbols.json is a list of {"name": ..., "addr": ..., "type"/"external": ...}
as produced by macho-meta.py.  Output: "<addr> <name>" sorted by address.
"""
import json
import re
import sys


def main() -> int:
    path = sys.argv[1]
    pat = re.compile(sys.argv[2])
    defined_only = "--defined-only" in sys.argv[3:]
    syms = json.load(open(path, encoding="utf-8"))
    rows = []
    for s in syms:
        name = s.get("name", "")
        if not pat.search(name):
            continue
        if defined_only and not s.get("defined", True):
            continue
        rows.append((s["addr"], name))
    rows.sort()
    for addr, name in rows:
        print("0x%x %s" % (addr, name))
    print("# total", len(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
