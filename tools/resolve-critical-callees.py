#!/usr/bin/env python3
"""A 方案：把"协议关键函数"里的未知调用（func_0x…）逐个解析到所属镜像。

每解析出一条就追加到 /tmp/crit.tsv，所以中途查看也能看到已完成的部分。
"""
import collections
import glob
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DSC = ROOT / "firmware/extracted/24A446/dyld/dyld_shared_cache_arm64e"
BASE = ROOT / "firmware/analysis/decompiler-cache/24A446"
CACHE = ROOT / "firmware/analysis/24A446/dyld.a2s"
OUT = "/tmp/crit.tsv"

CRITICAL = {
    "2519bbf24": "media SETUP builder",
    "2519ce5c4": "TEARDOWN",
    "251bd65d8": "screen stream descriptor",
    "251a59338": "control setup (caller)",
    "251a59708": "control setup (kind5)",
    "24fda58ec": "APTransport package builder",
    "24fda3f70": "feedback keep-alive",
    "251b61f50": "record / stream control",
}

CALL = re.compile(r"func_0x([0-9a-f]{9,11})")


def source_for(addr: str) -> str | None:
    for module in ("AirPlaySender", "APTransport"):
        hits = glob.glob(f"{BASE}/{module}/*/functions/f_{addr}.ghidra.c")
        if hits:
            return hits[0]
    return None


def resolve(addr: str) -> tuple[str, str]:
    try:
        proc = subprocess.run(
            ["ipsw", "dyld", "a2s", DSC, "0x" + addr, "-i", "--cache", CACHE],
            capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        return ("TIMEOUT", addr)
    image, symbol = "UNRESOLVED", addr
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("> "):
            image = line[2:].split(" (")[0]
        elif line.startswith("0x") and ":" in line:
            symbol = line.split(":", 1)[1].strip()
    return (image, symbol)


def main() -> None:
    todo: list[tuple[str, str]] = []          # (address, 说明)
    seen: set[str] = set()
    for addr, label in CRITICAL.items():
        path = source_for(addr)
        if not path:
            continue
        for target in sorted(set(CALL.findall(open(path, encoding="utf-8", errors="replace").read()))):
            if target in seen:
                continue
            seen.add(target)
            todo.append((target, label))
    print(f"total unique callees: {len(todo)}", flush=True)
    with open(OUT, "a", encoding="utf-8") as sink:
        for i, (target, label) in enumerate(todo, 1):
            image, symbol = resolve(target)
            sink.write(f"{image}\t{symbol}\t{label}\t0x{target}\n")
            sink.flush()
            if i % 10 == 0:
                print(f"{i}/{len(todo)}", flush=True)


if __name__ == "__main__":
    main()
