#!/usr/bin/env python3
"""扫描整个 __text，把所有「adrp+add 指向可打印字符串」的引用连同所在函数列出来。

用法：
  python3 macho-strxrefs.py <binary> <metadata-dir> [regex] [--limit N]

输出：<字符串>  <函数符号>  <指令地址>
同一 (字符串,函数) 只输出一次，便于回答「哪些函数用了这个键名」。
"""
import json
import os
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def load(blob):
    ncmds = u32(blob, 16)
    off = 32
    segs = []
    for _ in range(ncmds):
        cmd, size = u32(blob, off), u32(blob, off + 4)
        if cmd == 0x19:
            name = blob[off + 8:off + 24].split(b"\0")[0].decode()
            vmaddr = struct.unpack_from("<Q", blob, off + 24)[0]
            vmsize = struct.unpack_from("<Q", blob, off + 32)[0]
            fileoff = struct.unpack_from("<Q", blob, off + 40)[0]
            segs.append((name, vmaddr, vmsize, fileoff))
        off += size
    return segs


def main():
    path, metadir = sys.argv[1:3]
    rx = None
    args = sys.argv[3:]
    if args and not args[0].startswith("--"):
        import re
        rx = re.compile(args[0])
    limit = 100000
    if "--limit" in args:
        limit = int(args[args.index("--limit") + 1])
    blob = open(path, "rb").read()
    segs = load(blob)
    syms = json.load(open(os.path.join(metadir, "symbols.json"), encoding="utf-8"))
    table = []
    for s in syms:
        addrs = s["addr"] if isinstance(s["addr"], list) else [s["addr"]]
        for a in addrs:
            table.append((int(a, 16) if isinstance(a, str) else int(a), s["name"]))
    table.sort()

    def enclosing(pc):
        lo, hi = 0, len(table)
        while lo < hi:
            mid = (lo + hi) // 2
            if table[mid][0] <= pc:
                lo = mid + 1
            else:
                hi = mid
        return table[lo - 1][1] if lo else "(无符号)"

    text = next(s for s in segs if s[0] == "__TEXT")
    base, size, fileoff = text[1], text[2], text[3]
    code = blob[fileoff:fileoff + size]

    def cstr(addr):
        for name, vmaddr, vmsize, fo in segs:
            if name == "__LINKEDIT":
                continue
            if vmaddr <= addr < vmaddr + vmsize:
                o = fo + (addr - vmaddr)
                raw = blob[o:o + 200]
                nul = raw.find(b"\0")
                if nul <= 0:
                    return None
                try:
                    t = raw[:nul].decode("utf-8")
                except UnicodeDecodeError:
                    return None
                if any(ord(c) < 0x20 or ord(c) == 0x7F for c in t):
                    return None
                return t
        return None

    seen = set()
    out = 0
    for i in range(0, len(code) - 8, 4):
        w = struct.unpack_from("<I", code, i)[0]
        if (w & 0x9F000000) != 0x90000000:
            continue
        rd = w & 0x1F
        immlo = (w >> 29) & 0x3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        pc = base + i
        page = ((pc >> 12) << 12) + (imm << 12)
        nxt = struct.unpack_from("<I", code, i + 4)[0]
        if (nxt & 0xFF000000) != 0x91000000:
            continue
        imm12 = (nxt >> 10) & 0xFFF
        if ((nxt >> 22) & 0x3) == 1:
            imm12 <<= 12
        if ((nxt >> 5) & 0x1F) != rd:
            continue
        t = cstr(page + imm12)
        if not t:
            continue
        if rx and not rx.search(t):
            continue
        fn = enclosing(pc)
        key = (t, fn)
        if key in seen:
            continue
        seen.add(key)
        print(f"{t}\t{fn}\t0x{pc:x}")
        out += 1
        if out >= limit:
            return


if __name__ == "__main__":
    main()
