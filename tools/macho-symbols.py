#!/usr/bin/env python3
"""读 Mach-O 符号表，按名字子串过滤，输出 地址 与 名字。

用法： python3 tools/macho-symbols.py <binary> <substring>
"""
import struct
import sys

path, needle = sys.argv[1], sys.argv[2]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def main() -> None:
    blob = open(path, "rb").read()
    magic = u32(blob, 0)
    if magic != 0xFEEDFACF:
        raise SystemExit(f"不支持的 Mach-O magic {magic:#x}")
    ncmds = u32(blob, 16)
    off = 32
    symoff = nsyms = stroff = None
    for _ in range(ncmds):
        cmd, size = u32(blob, off), u32(blob, off + 4)
        if cmd == 0x2:  # LC_SYMTAB
            symoff, nsyms, stroff = u32(blob, off + 8), u32(blob, off + 12), u32(blob, off + 16)
        off += size
    if symoff is None:
        raise SystemExit("没有 LC_SYMTAB")
    hits = 0
    for i in range(nsyms):
        entry = symoff + i * 16
        strx, ntype, sect, desc, value = struct.unpack_from("<IBBHQ", blob, entry)
        if value == 0:
            continue
        end = blob.index(b"\0", stroff + strx)
        name = blob[stroff + strx:end].decode(errors="replace")
        if needle.lower() in name.lower():
            print(f"0x{value:x}\t{name}")
            hits += 1
    print(f"# {hits} 个匹配", file=sys.stderr)


if __name__ == "__main__":
    main()
