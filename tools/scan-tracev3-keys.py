#!/usr/bin/env python3
"""在 tracev3 日志里按关键字找命中（只回答"有没有"，不做完整解析）。

用法：scan-tracev3-keys.py <文件或目录> [更多路径...] --  key1 key2 ...
行为：
  - 对每个 .tracev3：先扫原始字节（未压缩段），再找 "bvx2" 标记逐个尝试 lzfse 解压，
    在解压结果里找关键字；
  - 输出每个关键字的命中次数，以及前若干条上下文（可打印片段）。
"""
import os
import re
import sys

import lzfse

MAGIC = b"bvx2"


def iter_tracev3(paths):
    for p in paths:
        if os.path.isdir(p):
            for dp, _, ns in os.walk(p):
                for n in sorted(ns):
                    if n.endswith(".tracev3"):
                        yield os.path.join(dp, n)
        else:
            yield p


def printable_runs(buf, minlen=6, limit=8):
    runs = re.findall(rb"[\x20-\x7e]{%d,}" % minlen, buf)
    return [r.decode("ascii", "replace") for r in runs[:limit]]


def scan_file(path, keys):
    """返回 {key: [上下文...]}"""
    hits = {k: [] for k in keys}
    data = open(path, "rb").read()

    def check(buf):
        for k in keys:
            kb = k.encode()
            for m in re.finditer(re.escape(kb), buf):
                if len(hits[k]) < 6:
                    lo = max(0, m.start() - 200)
                    hits[k].append(" | ".join(printable_runs(buf[lo:m.start() + 320], 6, 6)))

    check(data)  # 未压缩段
    pos = 0
    while True:
        i = data.find(MAGIC, pos)
        if i < 0:
            break
        pos = i + 4
        try:
            out = lzfse.decompress(data[i:])
        except Exception:
            continue
        if out:
            check(out)
    return {k: v for k, v in hits.items() if v}


def main():
    argv = sys.argv[1:]
    if "--" in argv:
        cut = argv.index("--")
        paths, keys = argv[:cut], argv[cut + 1:]
    else:
        paths, keys = argv, ["RFCOMM Channel connected"]
    files = list(iter_tracev3(paths))
    print(f"# files={len(files)} keys={len(keys)}")
    total = {k: 0 for k in keys}
    for f in files:
        got = scan_file(f, keys)
        if got:
            print(f"\n=== {f}")
            for k, ctx in got.items():
                total[k] += len(ctx)
                print(f"  [{k}] {len(ctx)} 条")
                for c in ctx[:3]:
                    print("     ", c[:300])
    print("\n# 汇总")
    for k in keys:
        print(f"  {k}: {total[k]}")


if __name__ == "__main__":
    main()
