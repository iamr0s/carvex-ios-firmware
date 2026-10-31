#!/usr/bin/env python3
"""按名字子串查符号，并给出估算大小（到下一个函数起始的距离）。

用法： python3 symfind.py <metadata-dir> <regex> [--limit N]
"""
import bisect
import json
import os
import re
import sys

metadir = sys.argv[1]
pat = re.compile(sys.argv[2], re.I)
limit = 200
if "--limit" in sys.argv:
    limit = int(sys.argv[sys.argv.index("--limit") + 1])

syms = json.load(open(os.path.join(metadir, "symbols.json"), encoding="utf-8"))
starts = sorted(set(json.load(open(os.path.join(metadir, "function-starts.json")))))
seen = set()
n = 0
for s in syms:
    a = s["addr"]
    if not a or a in seen or not pat.search(s["name"]):
        continue
    seen.add(a)
    i = bisect.bisect_right(starts, a)
    end = starts[i] if i < len(starts) else 0
    print(f"{a:#012x} {end - a:6d} {s['name']}")
    n += 1
    if n >= limit:
        break
