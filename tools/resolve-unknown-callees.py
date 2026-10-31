#!/usr/bin/env python3
"""把已缓存函数里的未知调用（func_0x…）逐个解析到所属镜像，统计"还有哪些库没补进缓存"。

用法： python3 tools/resolve-unknown-callees.py [--limit N]
输出： 每个镜像的未知调用数量 + 这些调用的符号名（前若干）
"""
import collections
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DSC = ROOT / "firmware/extracted/24A446/dyld/dyld_shared_cache_arm64e"
CACHE = ROOT / "firmware/analysis/decompiler-cache/24A446"
MODULES = ["AirPlaySender", "APTransport", "AirPlaySupport", "CarKit", "AirPlayReceiver"]
CALL = re.compile(r"func_0x([0-9a-f]{9,11})")


def collect() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for module in MODULES:
        addrs: set[str] = set()
        for path in (CACHE / module).glob("*/functions/*.ghidra.c"):
            addrs.update(CALL.findall(path.read_text(encoding="utf-8", errors="replace")))
        out[module] = addrs
    return out


def resolve(addr: str) -> tuple[str, str]:
    try:
        proc = subprocess.run(
            ["ipsw", "dyld", "a2s", DSC, "0x" + addr, "-i", "--cache", "/tmp/a2s.json"],
            capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return ("TIMEOUT", addr)
    image, symbol = "UNKNOWN", addr
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("> "):
            image = line[2:].split(" (")[0]
        elif line.startswith("0x") and ":" in line:
            symbol = line.split(":", 1)[1].strip()
    return (image, symbol)


def main() -> None:
    limit = 0
    if "--limit" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--limit") + 1])
    per_module = collect()
    by_image: collections.Counter = collections.Counter()
    samples: dict[str, list[str]] = collections.defaultdict(list)
    total = 0
    for module, addrs in per_module.items():
        for addr in sorted(addrs):
            if limit and total >= limit:
                break
            total += 1
            image, symbol = resolve(addr)
            by_image[image] += 1
            if len(samples[image]) < 8 and symbol != addr:
                samples[image].append(symbol)
            if total % 50 == 0:
                print(f"... {total}", flush=True)
    print("\n=== 未知调用按镜像统计 ===")
    for image, count in by_image.most_common(40):
        print(f"{count:5d}  {image}")
        for name in samples[image][:4]:
            print(f"        {name}")


if __name__ == "__main__":
    main()
