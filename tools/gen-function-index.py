#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build function-index.json for the iAP2 link-establishment docset.

Rows come from source/asm/accessoryd/index.json (address, end, size, symbol,
hashes).  For every row we scan analysis/ and spec/ for the literal address and
record which documents cite it, plus a coarse status:

    CONFIRMED_BY_ANALYSIS  cited in analysis/
    CITED_IN_SPEC_ONLY     cited only in spec/
    SAMPLED_NOT_CITED      not cited anywhere

This is a *bookkeeping* index; it does not infer behaviour.
"""
import json
import os
import re
import sys


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    idx = json.load(open(root + "/source/asm/accessoryd/index.json", encoding="utf-8"))
    summary = json.load(open(root + "/source/metadata/summary.json", encoding="utf-8"))

    docs = []
    for sub in ("analysis", "spec"):
        d = root + "/" + sub
        for name in sorted(os.listdir(d)):
            if name.endswith(".md"):
                docs.append((sub + "/" + name, open(d + "/" + name, encoding="utf-8").read()))

    rows = []
    for f in idx["functions"]:
        addr = f["address"]
        cited = [name for name, text in docs if addr in text]
        if any(c.startswith("analysis/") for c in cited):
            status = "CONFIRMED_BY_ANALYSIS"
        elif cited:
            status = "CITED_IN_SPEC_ONLY"
        else:
            status = "SAMPLED_NOT_CITED"
        rows.append({
            "symbol": f["symbol"],
            "address": addr,
            "end": f["end"],
            "size": f["size"],
            "raw_sha256": f["raw_sha256"],
            "asm": "source/asm/accessoryd/f_%s.s" % addr[2:],
            "bin": "source/asm/accessoryd/f_%s.bin" % addr[2:],
            "ghidra_c": "readable/ghidra/accessoryd/f_%s.ghidra.c" % addr[2:],
            "cited_by": cited,
            "status": status,
        })

    out = {
        "docset": os.path.basename(os.path.abspath(root)),
        "build": "24A446",
        "binary": "accessoryd",
        "source_sha256": summary["sha256"],
        "image_window": ["0x100000000", "0x102180000"],
        "total_function_starts": summary["function_starts"],
        "exported": len(rows),
        "sampling": "%d / %d" % (len(rows), summary["function_starts"]),
        "generator": "firmware/tools/gen-function-index.py",
        "functions": rows,
    }
    path = root + "/function-index.json"
    json.dump(out, open(path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print("wrote", path, len(rows), "rows", counts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
