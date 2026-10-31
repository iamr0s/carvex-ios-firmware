#!/usr/bin/env python3
"""找出指向给定地址的 ARM64 ADRP(+ADD/LDR) 引用，并报出所在函数（符号名）。

用法：
  python3 macho-xrefs.py <binary> <target-addr> [--symbols symbols.json] [--all]

target 可用 16 进制（0x...）或十进制。
两种匹配（都只做相邻两条的保守匹配，不追踪寄存器传递）：
  adrp+add   adrp xN, page ; add xM, xN, #imm   （M 可与 N 不同）
  adrp-页    adrp 目标页等于 target 所在页，且没有匹配的 add（可能是页基址取用）
输出：<指令地址>  <所在函数符号或 (无符号)>  <匹配类型>
"""
import json
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def segments(blob):
    if u32(blob, 0) != MH_MAGIC_64:
        raise SystemExit("不是 64 位 Mach-O")
    ncmds = u32(blob, 16)
    off = 32
    out = []
    for _ in range(ncmds):
        cmd, size = u32(blob, off), u32(blob, off + 4)
        if cmd == 0x19:
            name = blob[off + 8:off + 24].split(b"\0")[0].decode()
            vmaddr = struct.unpack_from("<Q", blob, off + 24)[0]
            vmsize = struct.unpack_from("<Q", blob, off + 32)[0]
            fileoff = struct.unpack_from("<Q", blob, off + 40)[0]
            out.append((name, vmaddr, vmsize, fileoff))
        off += size
    return out


def text_segment(blob):
    for name, vmaddr, vmsize, fileoff in segments(blob):
        if name == "__TEXT":
            return vmaddr, vmsize, fileoff
    raise SystemExit("没有 __TEXT")


def main():
    path = sys.argv[1]
    target = int(sys.argv[2], 0)
    symfile = None
    if "--symbols" in sys.argv:
        symfile = sys.argv[sys.argv.index("--symbols") + 1]
    blob = open(path, "rb").read()
    base, size, fileoff = text_segment(blob)
    code = blob[fileoff:fileoff + size]

    syms = []
    if symfile:
        for s in json.load(open(symfile, encoding="utf-8")):
            try:
                addrs = s["addr"] if isinstance(s["addr"], list) else [s["addr"]]
                for a in addrs:
                    syms.append((int(a, 16) if isinstance(a, str) else int(a), s["name"]))
            except Exception:
                pass
    syms.sort()

    def enclosing(pc):
        lo, hi = 0, len(syms)
        while lo < hi:
            mid = (lo + hi) // 2
            if syms[mid][0] <= pc:
                lo = mid + 1
            else:
                hi = mid
        if lo == 0:
            return "(无符号)"
        return syms[lo - 1][1]

    hits = 0
    for i in range(0, len(code) - 8, 4):
        w = struct.unpack_from("<I", code, i)[0]
        if (w & 0x9F000000) != 0x90000000:  # ADRP
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
        # ADD (immediate), 64-bit: 0x91 / 0x914 (shift=1)
        if (nxt & 0xFF000000) == 0x91000000:
            imm12 = (nxt >> 10) & 0xFFF
            shift = (nxt >> 22) & 0x3
            rn = (nxt >> 5) & 0x1F
            if shift == 1:
                imm12 <<= 12
            if rn == rd and page + imm12 == target:
                print(f"0x{pc:x}\t{enclosing(pc)}\tadrp+add")
                hits += 1
                continue
        if page == (target & ~0xFFF):
            print(f"0x{pc:x}\t{enclosing(pc)}\tadrp(页基址)")
            hits += 1
    print(f"# hits={hits} target=0x{target:x}", file=sys.stderr)


if __name__ == "__main__":
    main()
