#!/usr/bin/env python3
"""按虚拟地址读取字符串 / 原始字节（只读，用来核对固件里的字面量）。

用法：
  python3 read-cstr.py <binary> <metadata-dir> <addr> [<addr> ...]
  python3 read-cstr.py <binary> <metadata-dir> --hex <addr> [<n>]
"""
import json
import os
import sys


def main():
    binary, metadir = sys.argv[1], sys.argv[2]
    segs = json.load(open(os.path.join(metadir, "segments.json"), encoding="utf-8"))
    blob = open(binary, "rb").read()

    def off_of(va):
        for s in segs:
            if s["vmaddr"] <= va < s["vmaddr"] + s["filesize"]:
                return s["fileoff"] + (va - s["vmaddr"])
        return None

    args = sys.argv[3:]
    if args and args[0] == "--hex":
        va = int(args[1], 16)
        n = int(args[2], 16) if len(args) > 2 else 32
        o = off_of(va)
        raw = blob[o:o + n]
        print(f"0x{va:x}: " + " ".join(f"{b:02x}" for b in raw))
        return
    for a in args:
        va = int(a, 16)
        o = off_of(va)
        if o is None:
            print(f"0x{va:x}: <不在有文件内容的段内>")
            continue
        e = blob.index(b"\0", o)
        raw = blob[o:e]
        try:
            txt = raw.decode("utf-8")
        except UnicodeDecodeError:
            txt = raw.decode("latin-1")
        print(f"0x{va:x}: {txt!r}  (bytes={len(raw)})")


if __name__ == "__main__":
    main()
