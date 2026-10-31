#!/usr/bin/env python3
"""离线把 dyld 共享缓存地址映射到所属镜像（不需要 ipsw，一次读取即可）。

用法：
  python3 tools/dsc-image-map.py 0x196f5bca4 0x196f5bca4 ...
  python3 tools/dsc-image-map.py --from-tsv /tmp/crit.tsv

原理：读 dyld_cache_header 的 imagesTextOffset/imagesTextCount，每条
  { uuid[16], loadAddress:u64, textSize:u32, pathOffset:u32 }（32 字节），
按 [loadAddress, loadAddress+textSize) 匹配，再从 pathOffset 读镜像路径。
"""
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DSC = ROOT / "firmware/extracted/24A446/dyld/dyld_shared_cache_arm64e"


def load_images(path: str):
    with open(path, "rb") as handle:
        head = handle.read(0x100)
        magic = struct.unpack_from("<I", head, 0)[0]
        if magic != 0x646C7964:
            raise SystemExit(f"not a dyld cache: magic=0x{magic:08x}")
        text_offset = struct.unpack_from("<Q", head, 0x88)[0]
        text_count = struct.unpack_from("<Q", head, 0x90)[0]
        handle.seek(text_offset)
        table = handle.read(32 * text_count)
        images = []
        for i in range(text_count):
            uuid, addr, size, path_off = struct.unpack_from("<16sQII", table, i * 32)
            images.append((addr, size, path_off))
        images.sort()
        paths = {}
        for _, _, path_off in images:
            if path_off in paths:
                continue
            handle.seek(path_off)
            buf = bytearray()
            while True:
                ch = handle.read(1)
                if not ch or ch == b"\x00":
                    break
                buf += ch
            paths[path_off] = buf.decode("utf-8", "replace")
        return [(addr, size, paths[path_off]) for addr, size, path_off in images]


def main() -> None:
    images = load_images(DSC)
    addrs = []
    args = sys.argv[1:]
    if args and args[0] == "--from-tsv":
        for line in open(args[1], encoding="utf-8"):
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 4:
                addrs.append(parts[3])
    else:
        addrs = args
    for text in addrs:
        value = int(text, 16)
        hit = None
        for addr, size, path in images:
            if addr <= value < addr + size:
                hit = (path, addr, size)
                break
        print(f"{text}\t{hit[0] if hit else 'UNMAPPED'}\t{hex(hit[1]) if hit else '-'}")


if __name__ == "__main__":
    main()
