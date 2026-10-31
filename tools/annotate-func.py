#!/usr/bin/env python3
"""按符号/地址反汇编一个函数，并把 adrp+add 的字符串目标、bl 的符号名就地标注。

用法：
  python3 annotate-func.py <binary> <metadata-dir> <symbol|0xaddr> [--end 0xaddr] [--max N]

metadata-dir 由 macho-meta.py 产出（需要 segments.json、symbols.json）。
输出列为：地址  Mnemonic  操作数  ; 注解
注解：
  ;str "..."       adrp+add 指向可打印字符串
  ;sym <name>      bl 目标符号
"""
import json
import os
import struct
import sys

import capstone


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def load_segments(path):
    blob = open(path, "rb").read()
    if u32(blob, 0) != 0xFEEDFACF:
        raise SystemExit("不是 64 位 Mach-O")
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
    return blob, segs


def addr_to_off(segs, addr):
    for name, vmaddr, vmsize, fileoff in segs:
        if name in ("__LINKEDIT",):
            continue
        if vmaddr <= addr < vmaddr + vmsize:
            return fileoff + (addr - vmaddr)
    return None


def main():
    binary, metadir, what = sys.argv[1:4]
    blob, segs = load_segments(binary)
    syms = json.load(open(os.path.join(metadir, "symbols.json"), encoding="utf-8"))
    table = []
    for s in syms:
        addrs = s["addr"] if isinstance(s["addr"], list) else [s["addr"]]
        for a in addrs:
            table.append((int(a, 16) if isinstance(a, str) else int(a), s["name"]))
    table.sort()

    if what.startswith("0x"):
        start = int(what, 16)
        name = "(addr)"
    else:
        start = None
        for addr, nm in table:
            if nm in (what, "_" + what, "__" + what):
                start, name = addr, nm
                break
        if start is None:
            raise SystemExit(f"找不到符号 {what}")

    end = None
    if "--end" in sys.argv:
        end = int(sys.argv[sys.argv.index("--end") + 1], 16)
    if end is None:
        for addr, nm in table:
            if addr > start:
                end = min(addr, start + 0x20000)
                break
        if end is None:
            end = start + 0x1000
    maxinsn = int(sys.argv[sys.argv.index("--max") + 1]) if "--max" in sys.argv else 100000

    def cstr(addr):
        off = addr_to_off(segs, addr)
        if off is None or off >= len(blob):
            return None
        raw = blob[off:off + 160]
        nul = raw.find(b"\0")
        if nul <= 0:
            return None
        try:
            text = raw[:nul].decode("utf-8")
        except UnicodeDecodeError:
            return None
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in text):
            return None
        return text

    def symname(addr):
        lo, hi = 0, len(table)
        while lo < hi:
            mid = (lo + hi) // 2
            if table[mid][0] <= addr:
                lo = mid + 1
            else:
                hi = mid
        if lo and table[lo - 1][0] == addr:
            return table[lo - 1][1]
        return None

    off = addr_to_off(segs, start)
    raw = blob[off:off + (end - start)]
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.skipdata = True
    insns = list(md.disasm(raw, start))[:maxinsn]
    print(f"; function {name} 0x{start:x}-0x{end:x}  bytes={len(raw)}  insns={len(insns)}")
    for idx, ins in enumerate(insns):
        note = ""
        w = struct.unpack_from("<I", raw, ins.address - start)[0] if ins.address - start + 4 <= len(raw) else 0
        if (w & 0x9F000000) == 0x90000000 and idx + 1 < len(insns):
            nxt = insns[idx + 1]
            nw = struct.unpack_from("<I", raw, nxt.address - start)[0]
            rd = w & 0x1F
            immlo = (w >> 29) & 0x3
            immhi = (w >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & (1 << 20):
                imm -= 1 << 21
            page = ((ins.address >> 12) << 12) + (imm << 12)
            if (nw & 0xFF000000) == 0x91000000:
                imm12 = (nw >> 10) & 0xFFF
                shift = (nw >> 22) & 0x3
                rn = (nw >> 5) & 0x1F
                if shift == 1:
                    imm12 <<= 12
                if rn == rd:
                    text = cstr(page + imm12)
                    if text:
                        note = f';str "{text}" @0x{page + imm12:x}'
        if ins.mnemonic in ("bl", "b") and ins.op_str.startswith("#0x"):
            tgt = int(ins.op_str[3:], 16)
            nm = symname(tgt)
            if nm:
                note = f";sym {nm}"
        line = f"0x{ins.address:x}\t{ins.mnemonic}\t{ins.op_str}"
        print(line + (f"\t{note}" if note else ""))


if __name__ == "__main__":
    main()
