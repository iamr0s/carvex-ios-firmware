#!/usr/bin/env python3
"""把文档里引用的固件地址映射到所属镜像，列出"文档引用但还没反编译缓存"的库。

用法： python3 tools/doc-address-images.py
"""
import collections
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "research"
DSC = ROOT / "firmware/extracted/24A446/dyld/dyld_shared_cache_arm64e"
CACHE = ROOT / "firmware/analysis/decompiler-cache/24A446"
ADDR = re.compile(r"0x([0-9a-f]{6,12})")


def load_images():
    with open(DSC, "rb") as handle:
        head = handle.read(0x100)
        off = struct.unpack_from("<Q", head, 0x88)[0]
        count = struct.unpack_from("<Q", head, 0x90)[0]
        handle.seek(off)
        table = handle.read(32 * count)
        rows = [struct.unpack_from("<16sQII", table, i * 32) for i in range(count)]
        paths = {}
        for _, _, _, path_off in rows:
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
    return sorted((addr, size, paths[p]) for _, addr, size, p in rows)


def cached_names():
    return {d.name.lower() for d in CACHE.iterdir() if d.is_dir()}


def short(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    return name.split(".")[0]


def main() -> None:
    images = load_images()
    cached = cached_names()
    counts = collections.Counter()
    per_doc = collections.defaultdict(collections.Counter)
    for md in sorted(DOCS.glob("*.md")):
        text = md.read_text(encoding="utf-8", errors="replace")
        for hex_text in ADDR.findall(text):
            value = int(hex_text, 16)
            for addr, size, path in images:
                if addr <= value < addr + size:
                    counts[path] += 1
                    per_doc[md.name][path] += 1
                    break
    print("=== 文档引用的固件地址按镜像统计 ===")
    for path, count in counts.most_common(60):
        name = short(path)
        mark = "cached" if name.lower() in cached else "MISSING"
        print(f"{count:5d}  [{mark:7s}] {path}")
    print("\n=== 未缓存且引用较多的库 ===")
    for path, count in counts.most_common(60):
        name = short(path)
        if name.lower() not in cached and count >= 3:
            docs = ", ".join(d for d, c in per_doc.items() if c.get(path))
            print(f"{count:5d}  {path}\n        章节: {docs}")


if __name__ == "__main__":
    main()
