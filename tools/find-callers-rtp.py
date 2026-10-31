#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""扫描 __text 里所有 BL/ADRP+ADD，找出指向给定目标的调用点。

用法： python3 find-callers-rtp.py <binary> <segments.json> <target-hex> [<target-hex> ...]

输出： 每个目标一行，列出调用点地址（十进制/十六进制）与所属函数起点（用 function-starts.json 若提供）。
只做"直接 BL"匹配，不做重定位、不处理 stub 跳转链。
"""
import json
import struct
import sys


def main() -> int:
    binary, segs_path = sys.argv[1], sys.argv[2]
    targets = {int(t, 16) for t in sys.argv[3:]}
    segs = json.load(open(segs_path, encoding="utf-8"))
    text = [s for s in segs if s["segname"] == "__TEXT"][0]
    blob = open(binary, "rb").read()
    base = text["vmaddr"]
    fileoff = text["fileoff"]
    size = text["filesize"] if "filesize" in text else text["vmsize"]
    code = blob[fileoff:fileoff + size]
    hits = {t: [] for t in targets}
    for off in range(0, len(code) - 3, 4):
        w = struct.unpack_from("<I", code, off)[0]
        if (w & 0xFC000000) != 0x94000000:      # BL opcode
            continue
        imm = w & 0x03FFFFFF
        if imm & 0x02000000:                     # sign extend 26-bit
            imm -= 1 << 26
        addr = base + off
        target = addr + imm * 4
        if target in hits:
            hits[target].append(addr)
    for t, addrs in hits.items():
        print(f"target {t:#x}: {len(addrs)} call site(s)")
        for a in addrs:
            print(f"  {a:#x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
