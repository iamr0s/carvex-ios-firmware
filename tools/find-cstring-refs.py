#!/usr/bin/env python3
"""在 Mach-O 里找到引用指定 C 字符串的 adrp/add 指令位置。

用途：定位 MediaToolbox 里构造 timestampInfo 数组的代码（五个 name 字符串的引用点），
避免对 18 MB 的库做全量 Ghidra 分析。
"""
import json
import struct
import subprocess
import sys

BIN = "/tmp/mtb/MediaToolbox"


def sections():
    out = subprocess.run(["ipsw", "macho", "info", "-l", "-j", BIN], capture_output=True, text=True, check=True)
    data = json.loads(out.stdout)
    result = {}
    for load in data["loads"]:
        for sec in load.get("sections", []) or []:
            result[sec["name"]] = sec
    return result


def adrp_add_pairs(text: bytes, base_addr: int):
    """逐条解码 adrp 与后续 add 立即数，产出 (指令地址, 目标地址)。"""
    for i in range(0, len(text) - 8, 4):
        word = struct.unpack_from("<I", text, i)[0]
        if (word & 0x9F000000) != 0x90000000:      # adrp
            continue
        rd = word & 0x1F
        immlo = (word >> 29) & 0x3
        immhi = (word >> 5) & 0x7FFFF
        imm = ((immhi << 2) | immlo)
        if imm & (1 << 20):
            imm -= 1 << 21
        pc = base_addr + i
        page = ((pc >> 12) << 12) + (imm << 12)
        follow = struct.unpack_from("<I", text, i + 4)[0]
        if (follow & 0xFFC003FF) == 0x91000000 and (follow & 0x1F) == rd:   # add xD, xD, #imm12
            imm12 = (follow >> 10) & 0xFFF
            shift = (follow >> 22) & 0x3
            if shift == 1:
                imm12 <<= 12
            yield (pc, page + imm12)


def main() -> None:
    wanted = sys.argv[1:] or ["SubSU", "BePxT", "AfPxT", "BefEn", "EmEnc"]
    secs = sections()
    text_sec = secs["__text"]
    cstr_sec = secs["__cstring"]
    with open(BIN, "rb") as handle:
        blob = handle.read()
    targets = {}
    for name in wanted:
        needle = name.encode()
        start = cstr_sec["offset"]
        pos = blob.find(needle, start, start + cstr_sec["size"])
        if pos < 0:
            print(f"{name}: not found in __cstring")
            continue
        vaddr = cstr_sec["addr"] + (pos - start)
        targets[name] = vaddr
        print(f"{name}: file 0x{pos:x} vaddr 0x{vaddr:x}")
    text = blob[text_sec["offset"]:text_sec["offset"] + text_sec["size"]]
    base = text_sec["addr"]
    hits = []
    for pc, target in adrp_add_pairs(text, base):
        if target in targets.values():
            name = next(n for n, v in targets.items() if v == target)
            hits.append((pc, name))
    print(f"\n引用点 {len(hits)} 个")
    for pc, name in hits[:40]:
        print(f"  0x{pc:x}  -> {name}")


if __name__ == "__main__":
    main()
