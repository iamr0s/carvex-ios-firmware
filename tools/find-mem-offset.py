#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Find instructions that reference a given structure offset anywhere in __text.

Usage:
  python3 find-mem-offset.py <binary> <metadata-dir> <offset> [<offset> ...]

<offset> is a decimal or 0x-hex byte offset.  For every instruction whose operand
text contains "[xN, #<offset>]" or an `add xD, xN, #<offset>` the tool prints:

  0xINSN  func=0xFUNC  sym=NAME  text

func is the nearest LC_FUNCTION_STARTS entry at or below the instruction, and sym
is the nearest symbol name at or below that (may be empty when stripped).

This is a *lead generator*: a hit is only a candidate.  Confirm by reading the
function's exported assembly (source/asm) — a linear sweep can mis-decode literal
pools.
"""
import json
import os
import re
import sys

import capstone


def main() -> int:
    binary, metadir = sys.argv[1], sys.argv[2]
    offsets = [int(x, 0) for x in sys.argv[3:]]
    blob = open(binary, "rb").read()
    secs = json.load(open(os.path.join(metadir, "sections.json"), encoding="utf-8"))
    text = next(s for s in secs if s.get("section") == "__text" and s.get("segment") == "__TEXT")
    starts = sorted(set(json.load(open(os.path.join(metadir, "function-starts.json"),
                                       encoding="utf-8"))))
    syms = json.load(open(os.path.join(metadir, "symbols.json"), encoding="utf-8"))
    named = sorted({(s["addr"], s["name"]) for s in syms if s["name"]})

    base = text["addr"]
    body = blob[text["fileoff"]:text["fileoff"] + text["size"]]
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.skipdata = True

    pat = re.compile(r"\[x\d+, #(0x[0-9a-f]+)\]|, #(0x[0-9a-f]+)$")
    want = {}
    for ins in md.disasm(body, base):
        hits = []
        for m in pat.finditer(ins.op_str):
            raw = m.group(1) or m.group(2)
            if raw is None:
                continue
            v = int(raw, 16)
            if v in offsets:
                hits.append(v)
        if not hits:
            continue
        want.setdefault(ins.address, (hits, "%s %s" % (ins.mnemonic, ins.op_str)))

    import bisect
    saddrs = [a for a, _ in named]
    for addr in sorted(want):
        hits, text_s = want[addr]
        i = bisect.bisect_right(starts, addr) - 1
        func = starts[i] if i >= 0 else 0
        j = bisect.bisect_right(saddrs, func) - 1
        name = named[j][1] if j >= 0 else ""
        print("0x%x func=0x%x sym=%s off=%s %s"
              % (addr, func, name, ",".join("0x%x" % h for h in hits), text_s))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
