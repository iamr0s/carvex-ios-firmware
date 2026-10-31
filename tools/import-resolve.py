#!/usr/bin/env python3
"""把 dyld shared cache 提取出的 Mach-O 里的"外部调用桩"解析成 `dylib:symbol`。

为什么需要：`binaries/<Component>` 是从 cache 抽出的镜像，被调用函数名不在
`symbols.json` 里（那些只有本镜像的定义符号），而 `__stubs` 只有
`adrp x16, page / ldr x16,[x16,#off] / br x16`，真正的名字在
LC_DYLD_CHAINED_FIXUPS 的 imports 表里：GOT 槽是一个"bind"链式指针，
其 `target` 字段就是 import 序号。

用法：
  python3 import-resolve.py <binary> <metadata-dir> <addr> [<addr> ...]
    addr 可以是 __stubs 里的桩地址，也可以是 GOT 槽地址（自动判别）。
  python3 import-resolve.py <binary> <metadata-dir> --all-stubs [起始 结束]
    批量导出某段范围内所有桩的解析结果（用于给整份汇编加注释）。

输出：`0x... -> dylib:symbol`，解析失败时给出原因（不做猜测）。
"""
import json
import os
import struct
import sys

LC_DYLD_CHAINED_FIXUPS = 0x80000034
IMPORT_FORMAT_1 = 1  # DYLD_CHAINED_IMPORT (32-bit)


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def cstr(b, o):
    e = b.index(b"\0", o)
    return b[o:e].decode("utf-8", "replace")


def parse(binary, metadir):
    b = open(binary, "rb").read()
    segs = json.load(open(os.path.join(metadir, "segments.json"), encoding="utf-8"))
    ncmds = u32(b, 16)
    off = 32
    chained = None
    dylibs = []
    for _ in range(ncmds):
        cmd, size = u32(b, off), u32(b, off + 4)
        if cmd == LC_DYLD_CHAINED_FIXUPS:
            chained = struct.unpack_from("<II", b, off + 8)  # dataoff, datasize
        elif cmd in (0xC, 0x8000001F, 0xD, 0x18, 0x1F):  # LC_LOAD_DYLIB 家族
            name_off = u32(b, off + 8)
            dylibs.append(cstr(b, off + name_off))
        off += size
    if chained is None:
        raise SystemExit("没有 LC_DYLD_CHAINED_FIXUPS：本工具不适用")
    dataoff, datasize = chained
    base = dataoff
    fixups_version, starts_offset, imports_offset, symbols_offset, imports_count, imports_format, symbols_format = (
        struct.unpack_from("<7I", b, base)
    )
    imports = []
    for i in range(imports_count):
        if imports_format != IMPORT_FORMAT_1:
            raise SystemExit(f"未支持的 imports_format {imports_format}")
        v = u32(b, base + imports_offset + 4 * i)
        lib_ordinal = v & 0xFF
        weak = (v >> 8) & 1
        name_offset = v >> 9
        name = cstr(b, base + symbols_offset + name_offset)
        if lib_ordinal == 0xFF:
            lib = "main-executable"
        elif lib_ordinal == 0xFE:
            lib = "flat-lookup"
        elif lib_ordinal > 0xE0:
            lib = f"special(0x{lib_ordinal:02x})"
        else:
            idx = lib_ordinal - 1
            lib = dylibs[idx].split("/")[-1] if 0 <= idx < len(dylibs) else f"dylib#{idx}"
        imports.append({"name": name, "lib": lib, "weak": weak})
    return b, segs, imports


def off_of(segs, va):
    for s in segs:
        a, n = s["vmaddr"], s["filesize"]
        if a <= va < a + n:
            return s["fileoff"] + (va - a)
    return None


def decode_bind(raw):
    """链式指针 -> (是否 bind, ordinal)。arm64e 与 64 位两种格式都试。"""
    if raw == 0:
        return None
    is_auth = (raw >> 63) & 1
    is_bind = (raw >> 62) & 1
    if is_bind:
        return (raw & 0xFFFFFFFF) if is_auth or True else None
    return None


def stub_slot(b, segs, va):
    """从 adrp/ldr 桩算出 GOT 槽地址；不是桩则返回 None。"""
    o = off_of(segs, va)
    if o is None:
        return None
    ins = struct.unpack_from("<II", b, o)
    adrp = ins[0]
    if (adrp & 0x9F00001F) != 0x90000010:  # adrp x16, ...
        return None
    immlo = (adrp >> 29) & 3
    immhi = (adrp >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    page = (va & ~0xFFF) + (imm << 12)
    ldr = ins[1]
    if (ldr & 0xFFC00000) != 0xF9400000:  # ldr x16, [x16, #imm]
        return None
    imm12 = (ldr >> 10) & 0xFFF
    return page + imm12 * 8


def main():
    binary, metadir = sys.argv[1], sys.argv[2]
    args = sys.argv[3:]
    b, segs, imports = parse(binary, metadir)
    if args and args[0] == "--all-stubs":
        lo = int(args[1], 16) if len(args) > 1 else 0
        hi = int(args[2], 16) if len(args) > 2 else 1 << 64
        starts = sorted(set(json.load(open(os.path.join(metadir, "function-starts.json")))))
        print(f"# imports={len(imports)} stubs-in-range")
        for va in starts:
            if not (lo <= va < hi):
                continue
            slot = stub_slot(b, segs, va)
            if slot is None:
                continue
            o = off_of(segs, slot)
            if o is None:
                continue
            raw = struct.unpack_from("<Q", b, o)[0]
            ordi = decode_bind(raw)
            nm = imports[ordi]["name"] if ordi is not None and ordi < len(imports) else "?"
            lib = imports[ordi]["lib"] if ordi is not None and ordi < len(imports) else "?"
            print(f"0x{va:x} -> {lib}:{nm}")
        return
    for a in args:
        va = int(a, 16)
        slot = stub_slot(b, segs, va)
        target = va
        kind = "got-slot"
        if slot is not None:
            target = slot
            kind = "stub"
        o = off_of(segs, target)
        if o is None:
            print(f"0x{va:x} -> 地址不在有文件内容的段内")
            continue
        raw = struct.unpack_from("<Q", b, o)[0]
        ordi = decode_bind(raw)
        if ordi is None:
            print(f"0x{va:x} ({kind} @0x{target:x}) raw=0x{raw:016x} -> 不是 bind 指针")
            continue
        if ordi >= len(imports):
            print(f"0x{va:x} ({kind} @0x{target:x}) ordinal={ordi} -> 超出 imports 表")
            continue
        print(f"0x{va:x} ({kind} @0x{target:x}) -> {imports[ordi]['lib']}:{imports[ordi]['name']}")


if __name__ == "__main__":
    main()
