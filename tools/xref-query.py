#!/usr/bin/env python3
"""查询调用图（由 xref-scan.py 生成）：谁调用 X / X 调用了谁。

用法：
  python3 xref-query.py <xrefs.json> <metadata-dir> <stub-index.txt> <callers|callees> <name|0xaddr> [...]
"""
import bisect
import json
import os
import sys


def main():
    xrefs_path, metadir, stubfile, mode = sys.argv[1:5]
    queries = sys.argv[5:]

    names = {}
    for x in json.load(open(os.path.join(metadir, "symbols.json"), encoding="utf-8")):
        if x["addr"]:
            names.setdefault(x["addr"], x["name"])
    for line in open(stubfile, encoding="utf-8"):
        a, _, n = line.partition(": ")
        names.setdefault(int(a.strip(), 16), n.strip())
    starts = sorted(set(json.load(open(os.path.join(metadir, "function-starts.json")))))

    def fname(a):
        if a in names:
            return names[a]
        i = bisect.bisect_right(starts, a) - 1
        if i >= 0 and a - starts[i] < 0x20000:
            return f"{names.get(starts[i], 'sub')}+0x{a - starts[i]:x}"
        return f"0x{a:x}"

    by_addr = {}
    for q in queries:
        if q.startswith("0x"):
            by_addr[int(q, 16)] = q
        else:
            hits = [a for a, n in names.items() if n == q]
            if not hits:
                hits = [a for a, n in names.items() if n.endswith(q)]
            for a in hits[:4]:
                by_addr[a] = q

    calls = json.load(open(xrefs_path, encoding="utf-8"))["calls"]
    for a, q in sorted(by_addr.items()):
        print(f"== {q} ({a:#x}) {fname(a)} [{mode}]")
        if mode == "callers":
            rows = {(c["in_func"], c["from"], c["kind"]) for c in calls if c["to"] == a}
            for fn, src, kind in sorted(rows):
                print(f"   {fn:#012x} {fname(fn)}  (call@{src:#x} {kind})")
        else:
            rows = {(c["to"], c["kind"]) for c in calls if c["in_func"] == a}
            for dst, kind in sorted(rows):
                print(f"   -> {dst:#012x} {fname(dst)}  ({kind})")
        print()


if __name__ == "__main__":
    main()
