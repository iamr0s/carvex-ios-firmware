#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build manifest.json for the iAP2 link-establishment docset.

Manifest content:
  * every regular file under the docset (relative path, size, sha256), except
    manifest.json itself;
  * source binary identity;
  * counts (analysis/spec docs, exported functions, readable files);
  * the aggregated OPEN item list, parsed from analysis/ + spec/ tables.

verify.py checks the manifest against the tree (hashes, missing/extra files).
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
    files = []
    for base, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if not d.startswith(".git")]
        for n in sorted(names):
            p = os.path.join(base, n)
            rel = os.path.relpath(p, root).replace("\\", "/")
            if rel in SKIP:
                continue
            files.append({"path": rel, "size": os.path.getsize(p), "sha256": sha256(p)})
    files.sort(key=lambda x: x["path"])

    summary = json.load(open(root + "/source/metadata/summary.json", encoding="utf-8"))
    fi = json.load(open(root + "/function-index.json", encoding="utf-8"))
    cov = json.load(open(root + "/source/metadata/coverage.json", encoding="utf-8"))

    # aggregate OPEN-* identifiers from prose (first occurrence wins)
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
            "binary": "accessoryd",
            "path": "source/firmware/accessoryd",
            "size": summary["size"],
            "sha256": summary["sha256"],
            "uuid": summary["uuid"],
            "function_starts": summary["function_starts"],
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
        "coverage_summary": {k: sum(1 for i in cov["items"] if i["status"] == k)
                             for k in ("已确认", "部分确认", "OPEN")},
        "open_items": open_items,
        "open_item_count": len(open_items),
        "files": files,
    }
    path = root + "/manifest.json"
    json.dump(manifest, open(path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print("wrote", path, "files=", len(files), "open_items=", len(open_items))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
