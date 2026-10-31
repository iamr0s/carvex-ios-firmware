#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 research/protocol/iap2_input_business_lifecycle/manifest.json。

用法：python3 firmware/tools/gen-lifecycle-manifest.py [research/protocol/iap2_input_business_lifecycle]
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys

DEFAULT = "research/protocol/iap2_input_business_lifecycle"


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    root = os.path.abspath(root)
    files: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in sorted(dirnames) if d not in {"__pycache__"}]
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            relp = os.path.relpath(full, root).replace(os.sep, "/")
            if relp in {"manifest.json"}:
                continue
            files[relp] = sha256(full)

    with open(os.path.join(root, "source", "firmware", "accessoryd"), "rb") as fh:
        pass
    source_sha = sha256(os.path.join(root, "source", "firmware", "accessoryd"))
    source_size = os.path.getsize(os.path.join(root, "source", "firmware", "accessoryd"))

    coverage = json.load(open(os.path.join(root, "coverage.json"), encoding="utf-8"))
    items = coverage["coverage_items"]

    open_items = sorted(
        set(re.findall(r"`(OPEN-[A-Z]+-[A-Z0-9]+)`", open(os.path.join(root, "spec", "10-open-items.md"), encoding="utf-8").read()))
    )
    # 10.0 节的状态汇总；保留项并不全是外部证据缺口。
    spec10 = open(os.path.join(root, "spec", "10-open-items.md"), encoding="utf-8").read()
    open_status = {}
    for label, key in (("已关闭（固件证据）", "closed"), ("已缩小（仍缺一环）", "narrowed"), ("保留（静态待追或运行验收）", "remaining")):
        row = re.search(r"^\| " + re.escape(label) + r" \| (.+?) \|\s*$", spec10, re.M)
        open_status[key] = sorted(set(re.findall(r"`(OPEN-[A-Z]+-[A-Z0-9]+)`", row.group(1)))) if row else []

    asm_index = json.load(open(os.path.join(root, "source", "asm", "accessoryd", "index.json"), encoding="utf-8"))
    funcs = asm_index["functions"] if isinstance(asm_index, dict) else asm_index

    # function-index.json：汇编索引 + 反编译元数据的合并视图
    gh_dir = os.path.join(root, "readable", "ghidra", "accessoryd")
    index_entries = []
    for f in funcs:
        addr = f.get("addr") or f["address"]
        meta_path = os.path.join(gh_dir, f"f_{addr[2:]}.json")
        meta = {}
        if os.path.exists(meta_path):
            try:
                meta = json.loads(open(meta_path, encoding="utf-8").read(), strict=False)
            except ValueError:
                meta = {}
        index_entries.append(
            {
                "address": addr,
                "end": f.get("end"),
                "size": f.get("size"),
                "symbol": f.get("symbol"),
                "group": f.get("group"),
                "asm": f.get("asm"),
                "bin": f.get("bin"),
                "raw_sha256": f.get("raw_sha256"),
                "ghidra_c": meta.get("c_file"),
                "ghidra_status": meta.get("status"),
                "ghidra_name": meta.get("ghidra_name"),
            }
        )
    with open(os.path.join(root, "function-index.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(
            {
                "docset": "iap2_input_business_lifecycle",
                "source_sha256": source_sha,
                "image_functions": 8706,
                "count": len(index_entries),
                "functions": index_entries,
            },
            fh,
            ensure_ascii=False,
            indent=2,
        )
        fh.write("\n")

    # Refresh the generated index hash AFTER writing it, including first generation.
    files["function-index.json"] = sha256(os.path.join(root, "function-index.json"))

    spec_rules = 0
    for name in os.listdir(os.path.join(root, "spec")):
        if name.endswith(".md"):
            spec_rules += len(
                re.findall(r"^`R-\d+\.\d+(?:\.\d+)?`", open(os.path.join(root, "spec", name), encoding="utf-8").read(), re.M)
            )

    manifest = {
        "docset": "iap2_input_business_lifecycle",
        "title": "iAP2 输入、业务数据与生命周期",
        "build": {
            "product": "24A446",
            "os": "iOS 27.0.1",
            "device": "iPhone18,1",
            "binary": "accessoryd",
            "lc_uuid": "b3f36577-c4a2-3960-85ab-9d801b3f2c73",
        },
        "source_sha256": source_sha,
        "source_size": source_size,
        "stats": {
            "image_functions": 8706,
            "sampled_functions": len(funcs),
            "sample_ratio": round(len(funcs) / 8706, 4),
            "spec_rules": spec_rules,
            "coverage_items": len(items),
            "open_items": len(open_items),
        },
        "coverage": [
            {
                "id": it["id"],
                "title": it["title"],
                "status": it["status"],
                "opens": it.get("opens", []),
            }
            for it in items
        ],
        "open_items": open_items,
        "open_status": open_status,
        "files": files,
        "verify": "python3 verify.py",
    }
    out = os.path.join(root, "manifest.json")
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print(f"wrote {out}: files={len(files)} rules={spec_rules} opens={len(open_items)} "
          f"closed={len(open_status.get('closed', []))} sampled={len(funcs)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
