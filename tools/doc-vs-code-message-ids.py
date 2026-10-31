#!/usr/bin/env python3
"""文档 ↔ 实现：按 iAP2 消息号做覆盖核查。

从 carplay-docs 各章提取消息号（`0xNNNN` 或 `NNNN` 四位十六进制），
再到 carplay-xiaomi-carlife 的 Kotlin 源码里找同号常量（0x 形式或十进制），
输出每章"文档提到但实现里找不到"的清单。
"""
import re
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DOCS = REPO / "research"
CODE = REPO / "android"
ID = re.compile(r"\b(?:0x)?([0-9a-fA-F]{4})\b")


def message_ids(text: str) -> set[int]:
    out = set()
    for m in ID.finditer(text):
        raw = m.group(1)
        try:
            value = int(raw, 16)
        except ValueError:
            continue
        # 只看 iAP2 消息号区间：1d00-1d0f, 4e00-4e0f, 5x00, aa00-aa0f, ae00, 4300-4301 ...
        high = value >> 8
        if high in (0x1d, 0x4e, 0x50, 0x52, 0x57, 0xaa, 0xae, 0x43, 0x41, 0x4c, 0xda, 0xea):
            out.add(value)
    return out


def code_text() -> str:
    parts = []
    for path in CODE.rglob("*.kt"):
        if "/build/" in str(path):
            continue
        parts.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def main() -> None:
    blob = code_text()
    per_chapter: dict[str, set[int]] = defaultdict(set)
    for md in sorted(DOCS.rglob("*.md")):
        chapter = md.relative_to(DOCS).as_posix()
        per_chapter[chapter] = message_ids(md.read_text(encoding="utf-8", errors="replace"))

    total = missing_total = 0
    for chapter, ids in per_chapter.items():
        if not ids:
            continue
        missing = []
        for value in sorted(ids):
            total += 1
            hex_form = f"0x{value:04x}"
            dec_form = str(value)
            if hex_form in blob.lower() or re.search(rf"\b{dec_form}\b", blob):
                continue
            missing.append(hex_form)
        missing_total += len(missing)
        if missing:
            print(f"{chapter}: {len(missing)}/{len(ids)} 未在代码中出现 -> {' '.join(missing[:12])}")
    print(f"\n合计消息号 {total}，代码中未出现 {missing_total}")


if __name__ == "__main__":
    main()
