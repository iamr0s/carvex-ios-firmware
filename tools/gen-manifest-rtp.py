#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""为 airplay_rtp_timing 生成 manifest.json。

用法： python3 gen-manifest-rtp.py <docset-root> [image-name]

内容：全量文件哈希、源二进制身份、计数、12 项覆盖状态、OPEN 索引。
verify.py 会重算并与本文件比对。
"""
import hashlib
import json
import os
import re
import sys

SKIP = {"manifest.json"}


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    image = sys.argv[2] if len(sys.argv) > 2 else "AirPlaySender"

    files = []
    for base, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if not d.startswith(".git") and d != "__pycache__"]
        for n in sorted(names):
            p = os.path.join(base, n)
            rel = os.path.relpath(p, root).replace("\\", "/")
            if rel in SKIP:
                continue
            files.append({"path": rel, "size": os.path.getsize(p), "sha256": sha256(p)})
    files.sort(key=lambda x: x["path"])

    summary = json.load(open(os.path.join(root, "source/metadata", image, "summary.json"),
                            encoding="utf-8"))
    fi = json.load(open(os.path.join(root, "function-index.json"), encoding="utf-8"))
    cov = json.load(open(os.path.join(root, "source/metadata/coverage.json"),
                         encoding="utf-8"))

    open_items = {}
    for item in files:
        if not item["path"].endswith(".md"):
            continue
        text = open(os.path.join(root, item["path"]), encoding="utf-8").read()
        for m in re.finditer(r"`(OPEN-[A-Z]+-[0-9]+)`", text):
            open_items.setdefault(m.group(1), item["path"])

    manifest = {
        "docset": os.path.basename(os.path.abspath(root)),
        "build": "24A446",
        "device": "iPhone18,1",
        "source": {
            "binary": image,
            "path": f"source/firmware/{image}",
            "size": summary["size"],
            "sha256": summary["sha256"],
            "uuid": summary["uuid"],
            "function_starts": summary["function_starts"],
            "text_window": [hex(summary["text_section"]["addr"]),
                            hex(summary["text_section"]["addr"] + summary["text_section"]["size"])],
        },
        "counts": {
            "files": len(files),
            "analysis_docs": sum(1 for f in files if f["path"].startswith("analysis/")),
            "spec_docs": sum(1 for f in files if f["path"].startswith("spec/")),
            "asm_files": sum(1 for f in files
                             if f["path"].startswith("source/asm/") and f["path"].endswith(".s")),
            "readable_c_files": sum(1 for f in files if f["path"].endswith(".ghidra.c")),
            "exported_functions": fi["exported"],
            "sampling": fi["sampling"],
        },
        "coverage": cov["items"],
        "coverage_summary": cov["summary"],
        "open_items": open_items,
        "open_item_count": len(open_items),
        "files": files,
    }
    registry = open(os.path.join(root, "spec/08-open-items.md"), encoding="utf-8").read()
    closed = set(re.findall(r"^\|\s*`(OPEN-[A-Z]+-\d+)`\s*\|\s*CLOSED\s*\|", registry, re.M))
    manifest["closed_items"] = {key: open_items.pop(key) for key in sorted(closed)}
    manifest["closed_item_count"] = len(closed)
    manifest["open_item_count"] = len(open_items)
    audit = []
    for entry in files:
        if entry["path"].startswith("source/asm-audit/") and entry["path"].endswith("/index.json"):
            audit.append(json.load(open(os.path.join(root, entry["path"]), encoding="utf-8")))
    manifest["audit_sources"] = [{"image": a["image"], "sha256": a["source_sha256"],
                                  "functions": len(a["functions"])} for a in audit]
    manifest["counts"]["audit_asm_functions"] = sum(len(a["functions"]) for a in audit)
    path = os.path.join(root, "manifest.json")
    json.dump(manifest, open(path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print("wrote", path, "files=", len(files), "open_items=", len(open_items))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
