#!/usr/bin/env python3
"""临时探针：按关键字过滤 Mach-O 符号/字符串，为 airplay_rtp 阶段定位证据。"""
import json
import re
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BIN = REPO / "firmware/extracted/24A446/binaries/AirPlaySender/AirPlaySender"
SYM = REPO / "research/protocol/airplay_rtp_timing/source/metadata/AirPlaySender/symbols.json"

KEY = re.compile(r"rtp|rtcp|timestamp|jitter|ssrc|nack|retransmi|pacing|stall|latency|deadline|clock|pts|dts", re.I)


def main() -> None:
    syms = json.loads(SYM.read_text(encoding="utf-8"))
    if isinstance(syms, dict):
        syms = syms.get("symbols", [])
    hits = []
    for s in syms:
        name = s.get("name") or ""
        if KEY.search(name):
            hits.append((s.get("addr") or s.get("address") or 0, name))
    hits.sort()
    print(f"total symbols={len(syms)} hits={len(hits)}")
    for a, n in hits:
        print(f"{a:#x} {n}")


if __name__ == "__main__":
    main()
