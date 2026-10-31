#!/usr/bin/env python3
"""两跳定位：cstring → CFString 对象（__DATA 里指向它的指针）→ 代码里引用该对象的 adrp(+add|ldr)。

用法： python3 tools/find-cfstring-users.py <macho> 0x<cstring_vaddr>
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
    secs = {}
    for load in data["loads"]:
        for sec in load.get("sections", []) or []:
            secs[sec["name"]] = sec
    return secs


def main() -> None:
    secs = sections()
    blob = open(BIN, "rb").read()
    packed = struct.pack("<Q", TARGET)
    holders = []
    pos = 0
    while True:
        pos = blob.find(packed, pos)
        if pos < 0:
            break
        holders.append(pos)
        pos += 1
    print(f"pointers to cstring: {len(holders)}")
    for holder in holders[:10]:
        print(f"  holder file offset 0x{holder:x}")
    # 打印这些指针所在的段，便于判断是否是 CFString 结构
    for holder in holders[:5]:
        for name, sec in secs.items():
            if sec["offset"] <= holder < sec["offset"] + sec["size"]:
                vaddr = sec["addr"] + (holder - sec["offset"])
                print(f"    in {name} vaddr 0x{vaddr:x}")
                break


if __name__ == "__main__":
    main()
