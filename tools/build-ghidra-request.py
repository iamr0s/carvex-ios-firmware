#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build source/metadata/ghidra-request.json from source/asm/accessoryd/index.json.

The request is the input of ghidra-scripts/ExportDecomp.java and pins, for every
function, the exact byte range and hash that must be decompiled.
"""
import json
import os
import sys


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    idx = json.load(open(root + "/source/asm/accessoryd/index.json", encoding="utf-8"))
    summary = json.load(open(root + "/source/metadata/summary.json", encoding="utf-8"))
    req = {
        "source_sha256": summary["sha256"],
        "timeout_seconds": 120,
        "functions": [
            {"address": f["address"], "end": f["end"], "raw_sha256": f["raw_sha256"]}
            for f in idx["functions"]
        ],
    }
    path = root + "/source/metadata/ghidra-request.json"
    json.dump(req, open(path, "w", encoding="utf-8"), indent=1)
    print("wrote", path, len(req["functions"]), "functions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
