#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build a direct-call graph for one AArch64 Mach-O image (linear sweep).

Usage:
  python3 build-callgraph.py <binary> <metadata-dir> <out.json>

Only direct `bl` (call) and `b` (tail transfer) immediates are recorded; indirect
calls, `adrp`/`ldr` literal references and data words are NOT resolved here.
The output is a *navigation aid*: every edge must still be read in the exported
assembly before it is used as evidence.

Output:
  {"image":.., "source_sha256":.., "edge_count":N,
   "calls": {"<caller>": ["<callee>", ...]},        # bl
   "tails": {"<caller>": ["<callee>", ...]},        # b
   "callers": {"<callee>": ["<caller>", ...]}}      # union of the two, inverted
"""
import hashlib
import json
import os
import sys

import capstone


def main() -> int:
    binary, metadir, outpath = sys.argv[1:4]
    blob = open(binary, "rb").read()
    sha = hashlib.sha256(blob).hexdigest()
    secs = json.load(open(os.path.join(metadir, "sections.json"), encoding="utf-8"))
    text = None
    for s in secs:
        if s.get("section") == "__text" and s.get("segment") == "__TEXT":
            text = s
            break
    if text is None:
        raise SystemExit("no __text section")
    base = text["addr"]
    body = blob[text["fileoff"]:text["fileoff"] + text["size"]]

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.skipdata = True
    calls = {}
    tails = {}
    for ins in md.disasm(body, base):
        m = ins.mnemonic
        if m not in ("bl", "b"):
            continue
        ops = ins.op_str.strip()
        if not ops.startswith("#0x"):
            continue
        try:
            tgt = int(ops[1:], 16)
        except ValueError:
            continue
        tgt_s = "0x%x" % tgt
        src = "0x%x" % ins.address
        bucket = calls if m == "bl" else tails
        bucket.setdefault(src, [])
        if tgt_s not in bucket[src]:
            bucket[src].append(tgt_s)

    callers = {}
    for table in (calls, tails):
        for src, tgts in table.items():
            for t in tgts:
                callers.setdefault(t, [])
                if src not in callers[t]:
                    callers[t].append(src)

    out = {
        "image": "accessoryd",
        "source_sha256": sha,
        "text": {"addr": "0x%x" % base, "size": text["size"]},
        "tool": "Capstone 5.0.7 linear sweep, direct bl/b immediates only",
        "edge_count": sum(len(v) for v in calls.values()) + sum(len(v) for v in tails.values()),
        "calls": calls,
        "tails": tails,
        "callers": callers,
    }
    json.dump(out, open(outpath, "w", encoding="utf-8"), indent=0, sort_keys=True)
    print("wrote", outpath, "edges", out["edge_count"], "callers-of", len(callers))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
