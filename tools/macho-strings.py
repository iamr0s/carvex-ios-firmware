#!/usr/bin/env python3
"""列出 Mach-O 里的可打印字符串及其虚拟地址（含所在节）。

用法：
  python3 macho-strings.py <binary> [regex] [--min-len N] [--limit N]

输出每行：<vmaddr>  <section>  <string>
地址由段表换算：vmaddr + (fileoff - seg.fileoff)，与符号表地址同一坐标。
"""
import re
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def load(blob):
    if u32(blob, 0) != MH_MAGIC_64:
        raise SystemExit("不是 64 位 Mach-O")
    ncmds = u32(blob, 16)
    off = 32
    segs = []
    for _ in range(ncmds):
        cmd, size = u32(blob, off), u32(blob, off + 4)
        if cmd == 0x19:  # LC_SEGMENT_64
            name = blob[off + 8:off + 24].split(b"\0")[0].decode()
            vmaddr = struct.unpack_from("<Q", blob, off + 24)[0]
            vmsize = struct.unpack_from("<Q", blob, off + 32)[0]
            fileoff = struct.unpack_from("<Q", blob, off + 40)[0]
            nsects = u32(blob, off + 64)
            secs = []
            so = off + 72
            for _ in range(nsects):
                sname = blob[so:so + 16].split(b"\0")[0].decode()
                saddr = struct.unpack_from("<Q", blob, so + 32)[0]
                ssize = struct.unpack_from("<Q", blob, so + 40)[0]
                soff = u32(blob, so + 48)
                secs.append((sname, saddr, ssize, soff))
                so += 80
            segs.append((name, vmaddr, vmsize, fileoff, secs))
        off += size
    return segs


def fileoff_to_addr(segs, off):
    for name, vmaddr, vmsize, fileoff, secs in segs:
        if name == "__LINKEDIT":
            continue
        if fileoff <= off < fileoff + vmsize:
            return vmaddr + (off - fileoff), "?"
    return None, None


def main():
    path = sys.argv[1]
    pattern = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else None
    min_len = 4
    limit = 100000
    args = sys.argv[2:]
    for i, a in enumerate(args):
        if a == "--min-len":
            min_len = int(args[i + 1])
        if a == "--limit":
            limit = int(args[i + 1])
    rx = re.compile(pattern) if pattern else None
    blob = open(path, "rb").read()
    seen = 0
    for name, vmaddr, vmsize, fileoff, secs in load(blob):
        if name == "__LINKEDIT":
            continue
        for sname, saddr, ssize, soff in secs:
            if ssize == 0:
                continue
            data = blob[soff:soff + ssize]
            for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
                text = m.group().decode("ascii")
                if rx and not rx.search(text):
                    continue
                print(f"0x{saddr + m.start():x}\t{sname}\t{text}")
                seen += 1
                if seen >= limit:
                    print(f"# truncated at limit {limit}", file=sys.stderr)
                    return


if __name__ == "__main__":
    main()
