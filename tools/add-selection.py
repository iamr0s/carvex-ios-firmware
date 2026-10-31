#!/usr/bin/env python3
"""向 selection JSON 追加函数条目（按地址去重），供 export-asm.py 使用。

用法：
  python3 add-selection.py <selection.json> <image> <addr>[:note] [...]
"""
import json
import sys

path = sys.argv[1]
image = sys.argv[2]
items = sys.argv[3:]

sel = json.load(open(path, encoding="utf-8")) if __import__("os").path.exists(path) else {"image": image, "functions": []}
have = {f.get("address") for f in sel["functions"]}
added = 0
for it in items:
    a, _, note = it.partition(":")
    a = a if a.startswith("0x") else f"0x{int(a, 16):x}"
    if a in have:
        continue
    sel["functions"].append({"address": a, "group": "X", "note": note})
    have.add(a)
    added += 1
json.dump(sel, open(path, "w", encoding="utf-8"), indent=1)
print(f"{path}: +{added}, total {len(sel['functions'])}")
