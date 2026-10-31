#!/usr/bin/env python3
"""统计已缓存反编译结果里的"未知调用"分别落在哪些镜像。

输出两组：
  1) 协议关键函数（媒体 SETUP / TEARDOWN / 控制 SETUP / 包构造 / 音频流 / feedback）
  2) AirPlaySender + APTransport 全部已缓存函数
并按镜像聚合，用来判断还缺哪些库没补进反编译缓存。
"""
import collections
import glob
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "firmware/tools"))
from importlib import import_module

dsc_map = import_module("dsc-image-map".replace("-", "_")) if False else None

CALL = re.compile(r"func_0x([0-9a-f]{9,11})")
BASE = ROOT / "firmware/analysis/decompiler-cache/24A446"
CRITICAL = {
    "2519bbf24": "media SETUP",
    "2519ce5c4": "TEARDOWN",
    "251bd65d8": "screen stream",
    "251a59338": "control setup caller",
    "251a59708": "control setup kind5",
    "24fda58ec": "APTransport package",
    "24fda3f70": "feedback",
    "251b61f50": "record",
}


def load_images():
    import struct

    DSC = ROOT / "firmware/extracted/24A446/dyld/dyld_shared_cache_arm64e"
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
    images = sorted((addr, size, paths[p]) for _, addr, size, p in rows)
    return images


def image_of(images, value):
    for addr, size, path in images:
        if addr <= value < addr + size:
            return path
    return "UNMAPPED"


def files_for(module):
    return glob.glob(f"{BASE}/{module}/*/functions/*.ghidra.c")


def main() -> None:
    images = load_images()
    critical_addrs = set()
    for addr in CRITICAL:
        for module in ("AirPlaySender", "APTransport"):
            for path in glob.glob(f"{BASE}/{module}/*/functions/f_{addr}.ghidra.c"):
                critical_addrs.update(CALL.findall(open(path, encoding="utf-8", errors="replace").read()))

    all_addrs = set()
    for module in ("AirPlaySender", "APTransport", "AirPlaySupport"):
        for path in files_for(module):
            all_addrs.update(CALL.findall(open(path, encoding="utf-8", errors="replace").read()))

    for label, addrs in (("协议关键函数", critical_addrs), ("全部已缓存函数", all_addrs)):
        counts = collections.Counter(image_of(images, int(a, 16)) for a in addrs)
        print(f"\n=== {label}：{len(addrs)} 个未知调用，落在 {len(counts)} 个镜像 ===")
        for image, count in counts.most_common(25):
            print(f"{count:5d}  {image}")


if __name__ == "__main__":
    main()
