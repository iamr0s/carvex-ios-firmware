#!/usr/bin/env python3
"""打印某镜像任意地址窗口的反汇编（Capstone，字节来自固件本体）。

用法：
  python3 slice.py <binary> <metadata-dir> <start> <length>
"""
import json
import os
import sys

import capstone

binary, metadir = sys.argv[1], sys.argv[2]
start = int(sys.argv[3], 16)
length = int(sys.argv[4], 16)
blob = open(binary, "rb").read()
segs = json.load(open(os.path.join(metadir, "segments.json"), encoding="utf-8"))


def off_of(va):
    for s in segs:
        end = s["vmaddr"] + s["filesize"]
        if s["fileoff"] and s["vmaddr"] <= va < end:
            return s["fileoff"] + (va - s["vmaddr"])
        if not s["fileoff"] and s["vmaddr"] <= va < end:
            return va - s["vmaddr"]
    return None


o = off_of(start)
if o is None or o >= len(blob):
    print(f"地址 {start:#x} 不在任何有文件内容的段内（或超出文件）；段表：", file=sys.stderr)
    for s in segs:
        print(f"  {s['segname']} {s['vmaddr']:#x}..{s['vmaddr'] + s['filesize']:#x}", file=sys.stderr)
    raise SystemExit(2)
code = blob[o:o + length]
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = False
for ins in md.disasm(code, start):
    print(f"{ins.address:#012x}: {ins.mnemonic:8s} {ins.op_str}")
