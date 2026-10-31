#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build manifest.json for research/protocol/iap2_airplay_tunnel.

    python3 firmware/tools/gen-manifest-airplay-tunnel.py research/protocol/iap2_airplay_tunnel

与 `gen-manifest.py`（控制会话阶段）的区别：本阶段的 coverage 用英文状态
（answered/negative/changed/partial），因此单独生成，不共用状态映射。
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
    root = (sys.argv[1] if len(sys.argv) > 1
            else "research/protocol/iap2_airplay_tunnel")
    files = []
    for base, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
        for n in sorted(names):
            p = os.path.join(base, n)
            rel = os.path.relpath(p, root).replace("\\", "/")
            if rel in SKIP:
                continue
            files.append({"path": rel, "size": os.path.getsize(p), "sha256": sha256(p)})
    files.sort(key=lambda x: x["path"])

    summary = json.load(open(root + "/source/metadata/summary.json", encoding="utf-8"))
    cov = json.load(open(root + "/source/metadata/coverage.json", encoding="utf-8"))
    asm_index = json.load(open(root + "/source/asm/accessoryd/index.json", encoding="utf-8"))

    open_items = {}
    for item in files:
        if not item["path"].endswith(".md"):
            continue
        text = open(os.path.join(root, item["path"]), encoding="utf-8").read()
        for m in re.finditer(r"`(OPEN-TUN-[0-9]+)`", text):
            open_items.setdefault(m.group(1), item["path"])

    manifest = {
        "docset": os.path.basename(os.path.abspath(root)),
        "build": "24A446",
        "device": "iPhone18,1",
        "source": {
            "binary": "accessoryd",
            "path": "source/firmware/accessoryd",
            "size": summary["size"],
            "sha256": summary["sha256"],
            "uuid": summary["uuid"],
            "function_starts": summary["function_starts"],
        },
        "counts": {
            "files": len(files),
            "analysis_docs": sum(1 for f in files
                                 if f["path"].startswith("analysis/") and f["path"].endswith(".md")),
            "spec_docs": sum(1 for f in files
                             if f["path"].startswith("spec/") and f["path"].endswith(".md")),
            "asm_files": sum(1 for f in files
                             if f["path"].startswith("source/asm/") and f["path"].endswith(".s")),
            "readable_c_files": sum(1 for f in files if f["path"].endswith(".ghidra.c")),
            "exported_functions": asm_index["count"],
            "function_starts": summary["function_starts"],
            "sampling": round(asm_index["count"] / summary["function_starts"], 4),
            "test_vectors": len(json.load(open(root + "/reference-impl/test_vectors.json",
                                              encoding="utf-8"))["vectors"]),
        },
        "coverage": cov["requirements"],
        "coverage_summary": cov["counts"],
        "open_items": open_items,
        "open_item_count": len(open_items),
        "file_count": len(files),
        "files": files,
    }
    path = root + "/manifest.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    print("wrote", path, "files=", len(files), "open_items=", len(open_items))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
