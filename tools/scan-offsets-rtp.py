#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""扫描 __text，找出所有"带指定立即数偏移"的 ldr/str/ldp/stp 指令，并归属到函数。

用法：
  python3 scan-offsets-rtp.py <binary> <metadata-dir> <off> [<off> ...]

  <off> 用十六进制（如 0x5c0）或十进制。

输出：按函数分组，每行  insn_addr  mnemonic  op_str
目的：给定"对象 + 某偏移"的线索（如包缓冲的 +0x5c0），反查所有读写它的函数。
"""
import bisect
import json
import os
import re
import sys

import capstone


def main() -> int:
    binary, metadir = sys.argv[1], sys.argv[2]
    offs = []
    for a in sys.argv[3:]:
        offs.append(int(a, 16) if a.lower().startswith("0x") else int(a))
    want = {f"#0x{o:x}" for o in offs} | {f"#{o}" for o in offs if o > 9}

    segs = json.load(open(os.path.join(metadir, "segments.json"), encoding="utf-8"))
    text = [s for s in segs if s["segname"] == "__TEXT"][0]
    starts = sorted(set(json.load(open(os.path.join(metadir, "function-starts.json"),
                                       encoding="utf-8"))))
    syms = json.load(open(os.path.join(metadir, "symbols.json"), encoding="utf-8"))
    byaddr = {}
    for s in syms:
        byaddr.setdefault(s["addr"], s["name"])

    blob = open(binary, "rb").read()
    code = blob[text["fileoff"]:text["fileoff"] + text["filesize"]]
    base = text["vmaddr"]

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.skipdata = True

    hits = {}
    for insn in md.disasm(code, base):
        m = insn.mnemonic
        if not (m.startswith("ldr") or m.startswith("str") or m in ("ldp", "stp", "ldur", "stur")):
            continue
        # 只看形如  [xN, #0x...] 的立即数偏移
        for tok in re.findall(r"#(?:0x[0-9a-f]+|\d+)", insn.op_str):
            if tok in want:
                i = bisect.bisect_right(starts, insn.address) - 1
                fstart = starts[i] if i >= 0 else 0
                name = byaddr.get(fstart, "?")
                hits.setdefault((fstart, name), []).append(
                    (insn.address, m, insn.op_str, tok))
                break

    print(f"# 扫描偏移: {sorted(want)}  命中函数 {len(hits)} 个")
    for (fstart, name), rows in sorted(hits.items()):
        print(f"\n## {name} @ {fstart:#x}   ({len(rows)} 命中)")
        for addr, m, ops, tok in rows:
            print(f"  {addr:#x}  {m:6s} {ops}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
