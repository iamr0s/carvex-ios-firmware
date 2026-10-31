"""读 CFString 或其引用（__cfstring 结构 / 全局槽里的 CFString 指针）。

CFString 常量结构（__cfstring 段）：{ isa, flags, cstring_ptr }
flags 低位 0x7 = 长度，若 (flags & 0x10) 则 cstring_ptr 指向 inline 缓冲。

用法：
  python3 cfstr.py <binary> <metadata-dir> <addr> [--slot]
  --slot 表示 addr 是一个 8 字节槽，里面存着 CFString 的地址
"""
import json
import os
import struct
import sys


def main():
    binary, metadir, addr = sys.argv[1], sys.argv[2], int(sys.argv[3], 16)
    slot = "--slot" in sys.argv
    segs = json.load(open(os.path.join(metadir, "segments.json"), encoding="utf-8"))
    blob = open(binary, "rb").read()

    def off_of(va):
        for s in segs:
            if s["vmaddr"] <= va < s["vmaddr"] + s["filesize"]:
                return s["fileoff"] + (va - s["vmaddr"])
        return None

    if slot:
        o = off_of(addr)
        va = struct.unpack_from("<Q", blob, o)[0]
        print(f"slot 0x{addr:x} -> 0x{va:x}")
        addr = va
    o = off_of(addr)
    if o is None:
        print("地址不在有文件内容的段内")
        return
    isa, flags, ptr = struct.unpack_from("<QQQ", blob, o)
    print(f"0x{addr:x}: isa=0x{isa:x} flags=0x{flags:x} ptrfield=0x{ptr:x}")
    if flags & 0x10:
        # inline buffer：字符串内容在结构体自身 + 0x10 处（此处 ptrfield 即 inline 起点）
        raw = blob[o + 0x10: o + 0x10 + (flags & 0xF)]
        target = addr + 0x10
    else:
        target = ptr
        raw = blob[off_of(ptr): blob.index(b"\0", off_of(ptr))]
    print(f"  -> target 0x{target:x}: {raw.decode('utf-8', 'replace')!r}")


if __name__ == "__main__":
    main()
