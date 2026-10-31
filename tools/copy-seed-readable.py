#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Copy already-exported readable/ files from the link docset into this docset.

Only files whose address is present in this stage's source/asm index are copied,
and only when the destination does not exist.  The firmware image, the extracted
code range and the SHA256 chain are identical between the two docsets, so the raw
decompiler output is the same byte-for-byte artifact; nothing is re-interpreted.
"""
import json
import os
import shutil


def main() -> int:
    src = "research/protocol/iap2_link_establish/readable/ghidra/accessoryd"
    dstdir = "research/protocol/iap2_control_session/readable/ghidra/accessoryd"
    idx = json.load(open("research/protocol/iap2_control_session/source/asm/accessoryd/index.json",
                         encoding="utf-8"))
    copied = 0
    for f in idx["functions"]:
        base = "f_%s" % f["address"][2:]
        for ext in (".ghidra.c", ".json"):
            s = os.path.join(src, base + ext)
            d = os.path.join(dstdir, base + ext)
            if os.path.exists(s) and not os.path.exists(d):
                shutil.copy2(s, d)
                copied += 1
    print("copied", copied, "files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
