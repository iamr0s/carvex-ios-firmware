#!/usr/bin/env python3
"""列出引用某个函数/数据地址的 adrp(+add|ldr) 指令位置。

用法：
  python3 tools/find-code-xrefs.py /tmp/apx/AirPlaySender 0x251a31acc
"""
import json
import struct
import subprocess
import sys

BIN = sys.argv[1]
TARGET = int(sys.argv[2], 16)


def sections():
    out = subprocess.run(["ipsw", "macho", "info", "-l", "-j", BIN], capture_output=True, text=True, check=True)
    data = json.loads(out.stdout)
    result = {}
    for load in data["loads"]:
        for sec in load.get("sections", []) or []:
            result[sec["name"]] = sec
    return result


def pairs(text, base):
    for i in range(0, len(text) - 8, 4):
        word = struct.unpack_from("<I", text, i)[0]
        if (word & 0x9F000000) != 0x90000000:
            continue
        rd = word & 0x1F
        imm = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 0x3)
        if imm & (1 << 20):
            imm -= 1 << 21
        pc = base + i
        page = ((pc >> 12) << 12) + (imm << 12)
        follow = struct.unpack_from("<I", text, i + 4)[0]
        if (follow & 0xFFC003FF) == 0x91000000 and (follow & 0x1F) == rd:
            imm12 = (follow >> 10) & 0xFFF
            if ((follow >> 22) & 0x3) == 1:
                imm12 <<= 12
            yield (pc, page + imm12)
        elif (follow & 0xFFC00000) == 0xF9400000 and (follow & 0x1F) == rd:
            yield (pc, page + ((follow >> 10) & 0xFFF) * 8)


def main() -> None:
    secs = sections()
    blob = open(BIN, "rb").read()
    text = secs["__text"]
    body = blob[text["offset"]:text["offset"] + text["size"]]
    hits = [(pc, v) for pc, v in pairs(body, text["addr"]) if v == TARGET]
    print(f"target 0x{TARGET:x}: {len(hits)} reference(s)")
    for pc, _ in hits[:40]:
        print(f"  0x{pc:x}")


if __name__ == "__main__":
    main()
