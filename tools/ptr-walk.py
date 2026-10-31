#!/usr/bin/env python3
"""解码 dyld shared cache 提取出的 Mach-O 指针表（chained fixup 未重定位形态）。

背景：`binaries/<Component>/<Component>` 是从 dyld shared cache 抽出的镜像，
__DATA 里的指针仍保留 cache 内相对形态：

    DYLD_CHAINED_PTR_ARM64E: target:32 | diversity:16 | addrDiv:1 | key:2 | next:11 | isBind:1 | isAuth:1
    DYLD_CHAINED_PTR_64:     target:36 | high8:8  | reserved:7 | next:12 | isBind:1

本工具把 target 还原成 cache 内绝对地址（默认 base 0x180000000），
再按符号表 / function-starts 解析成人可读名字。只做读取，不改固件。

用法：
  python3 ptr-walk.py <binary> <metadata-dir> <vaddr> [count] [--base 0x180000000]

输出：每行 `[i] raw -> resolved  name`，并把 `resolved` 是否落在
function-starts 内一并标出，便于区分"代码指针/数据指针/零"。
"""
import bisect
import json
import os
import struct
import sys

CACHE_BASE = 0x180000000


def load(binary, metadir):
    blob = open(binary, "rb").read()
    segs = json.load(open(os.path.join(metadir, "segments.json"), encoding="utf-8"))
    syms = json.load(open(os.path.join(metadir, "symbols.json"), encoding="utf-8"))
    starts = json.load(open(os.path.join(metadir, "function-starts.json"), encoding="utf-8"))
    return blob, segs, syms, starts


def off_of(segs, va):
    for s in segs:
        a, n = s["vmaddr"], s["filesize"]
        if a <= va < a + n:
            return s["fileoff"] + (va - a)
    return None


def decode(raw, base):
    """返回 (resolved_vaddr, kind)。kind: 'null' / 'arm64e' / 'ptr64'。"""
    if raw == 0:
        return 0, "null"
    is_auth = (raw >> 63) & 1
    is_bind = (raw >> 62) & 1
    if is_auth or is_bind:
        # DYLD_CHAINED_PTR_ARM64E
        target = raw & 0xFFFFFFFF
        return base + target, "arm64e"
    # DYLD_CHAINED_PTR_64
    target = raw & 0xFFFFFFFFF
    high8 = (raw >> 36) & 0xFF
    return (high8 << 56) | target, "ptr64"


def main():
    argv = sys.argv[1:]
    base = CACHE_BASE
    if "--base" in argv:
        i = argv.index("--base")
        base = int(argv[i + 1], 16)
        del argv[i:i + 2]
    binary, metadir, va = argv[0], argv[1], int(argv[2], 16)
    count = int(argv[3]) if len(argv) > 3 else 8
    blob, segs, syms, starts = load(binary, metadir)
    o = off_of(segs, va)
    if o is None:
        raise SystemExit(f"0x{va:x} 不在任何有文件内容的段内")
    starts_sorted = sorted(set(starts))
    byaddr = {}
    for s in syms:
        byaddr.setdefault(s["addr"], s["name"])
    addrs = sorted(byaddr)

    def name_of(va):
        if va in byaddr:
            return byaddr[va]
        i = bisect.bisect_right(addrs, va) - 1
        if i >= 0 and va - addrs[i] < 0x800:
            return f"{byaddr[addrs[i]]}+0x{va - addrs[i]:x}"
        return "?"

    def in_func(va):
        i = bisect.bisect_right(starts_sorted, va) - 1
        return i >= 0 and va - starts_sorted[i] < 0x400

    print(f"# base=0x{base:x} vaddr=0x{va:x} fileoff=0x{o:x} count={count}")
    for k in range(count):
        raw = struct.unpack_from("<Q", blob, o + 8 * k)[0]
        val, kind = decode(raw, base)
        tag = "CODE" if val and in_func(val) else ("DATA" if val else "NULL")
        nm = name_of(val) if val else "-"
        print(f"[{k:2}] raw=0x{raw:016x} {kind:7} -> 0x{val:012x} {tag} {nm}")


if __name__ == "__main__":
    main()
