#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""为 airplay_rtp_timing 生成 function-index.json。

用法： python3 gen-function-index-rtp.py <docset-root> [image-dir-name]

读取 <root>/source/asm/<image>/index.json，补充"每函数在文档中被引用的情况"，
并把采样率与源哈希写进索引。引用扫描范围：analysis/、spec/、TASK.md、STATUS.md。
"""
import json
import os
import re
import sys


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    image = sys.argv[2] if len(sys.argv) > 2 else "AirPlaySender"
    idx_path = os.path.join(root, "source", "asm", image, "index.json")
    idx = json.load(open(idx_path, encoding="utf-8"))
    summary = json.load(open(os.path.join(root, "source", "metadata", image, "summary.json"),
                            encoding="utf-8"))

    docs = []
    for base, _dirs, names in os.walk(root):
        for n in names:
            if not n.endswith(".md"):
                continue
            p = os.path.join(base, n)
            rel = os.path.relpath(p, root).replace("\\", "/")
            if rel.startswith("readable/") or rel.startswith("source/"):
                continue
            docs.append((rel, open(p, encoding="utf-8").read()))

    funcs = []
    for f in idx["functions"]:
        addr = f["address"].lower()
        needle = re.compile(re.escape(addr) + r"\b", re.I)
        refs = sorted(rel for rel, text in docs if needle.search(text))
        funcs.append({
            "symbol": f["symbol"],
            "address": f["address"],
            "end": f["end"],
            "size": f["size"],
            "group": f.get("group", ""),
            "raw_sha256": f["raw_sha256"],
            "asm": f["asm"],
            "bin": f["bin"],
            "cited_by": refs,
        })

    out = {
        "image": image,
        "source_sha256": summary["sha256"],
        "source_size": summary["size"],
        "function_starts": summary["function_starts"],
        "exported": len(funcs),
        "sampling": f"{len(funcs)} / {summary['function_starts']} "
                    f"≈ {100.0 * len(funcs) / summary['function_starts']:.2f}%",
        "note": "cited_by 只统计 analysis/spec/TASK/STATUS 中的十六进制地址引用；空列表表示该函数已导出但尚未被正文引用",
        "functions": funcs,
    }
    path = os.path.join(root, "function-index.json")
    json.dump(out, open(path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    uncited = [f["symbol"] for f in funcs if not f["cited_by"]]
    print("wrote", path, "exported=", len(funcs), "uncited=", len(uncited))
    if uncited:
        print("uncited:", ", ".join(uncited))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
