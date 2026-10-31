#!/usr/bin/env python3
"""粗扫 tracev3：找 lzfse 流并解压，在解压结果里搜关键字。

不是完整的 tracev3 解析器，只用来回答"日志里有没有这条记录"。
"""
import sys

import lzfse

MAGIC = b"bvx2"
KEYS = [b"timestampInfo", b"streamConnectionID", b"APSenderSession", b"SETUP",
        b"latencyMs", b"uuid"]


def scan(path: str, limit: int = 400) -> None:
    data = open(path, "rb").read()
    hits = 0
    pos = 0
    while hits < limit:
        i = data.find(MAGIC, pos)
        if i < 0:
            break
        pos = i + 4
        try:
            out = lzfse.decompress(data[i:])
        except Exception:
            continue
        hits += 1
        for key in KEYS:
            if key in out:
                j = out.find(key)
                chunk = out[max(0, j - 200):j + 300]
                print(f"--- {path} @{i} key={key.decode()}")
                print(chunk.decode("utf-8", "replace").replace("\x00", "."))
                break


if __name__ == "__main__":
    for p in sys.argv[1:]:
        scan(p)
