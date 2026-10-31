#!/usr/bin/env python3
"""由 asm/index.json 生成 ExportDecomp.java 的请求 JSON。

用法： python3 mkreq.py <index.json> <out.json>
"""
import json
import sys

idx = json.load(open(sys.argv[1], encoding="utf-8"))
req = {
    "source_sha256": idx["source_sha256"],
    "timeout_seconds": 180,
    "functions": [
        {"address": f["address"], "end": f["end"], "raw_sha256": f["raw_sha256"]}
        for f in idx["functions"]
    ],
}
json.dump(req, open(sys.argv[2], "w", encoding="utf-8"), indent=1)
print(f"{sys.argv[2]}: {len(req['functions'])} functions")
