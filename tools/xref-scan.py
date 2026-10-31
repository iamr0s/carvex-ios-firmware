#!/usr/bin/env python3
"""全量 __text 线性扫描，建「调用图 + 外部桩」索引。

用法：
  python3 xref-scan.py <image> <metadata-dir> <stub-index.txt> <out.json>

输出 JSON：
  {"image":..,"source_sha256":..,
   "calls":[{"from":..,"to":..,"kind":"bl|b","in_func":..}],
   "notes":"线性扫描，未做控制流恢复；from 落在已知函数区间内才算有效调用"}
"""
import json
import os
import sys

import capstone

image, metadir, stubfile, out = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
blob = open(image, "rb").read()
segs = json.load(open(os.path.join(metadir, "segments.json"), encoding="utf-8"))
sects = json.load(open(os.path.join(metadir, "sections.json"), encoding="utf-8"))
starts = sorted(set(json.load(open(os.path.join(metadir, "function-starts.json")))))

text = None
for s in sects:
    if s["section"] == "__text" and s["segment"] == "__TEXT":
        text = s
        break
if text is None:
    raise SystemExit("找不到 __TEXT.__text")

addr = text["addr"]
size = text["size"]
foff = text["fileoff"]
code = blob[foff:foff + size]

stubs = {}
for line in open(stubfile, encoding="utf-8"):
    a, _, name = line.partition(": ")
    stubs[int(a.strip(), 16)] = name.strip()

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = False

import bisect


def func_of(a):
    i = bisect.bisect_right(starts, a) - 1
    return starts[i] if i >= 0 else None


calls = []
for ins in md.disasm(code, addr):
    if ins.mnemonic not in ("bl", "b"):
        continue
    op = ins.op_str
    if not op.startswith("#"):
        continue
    try:
        tgt = int(op[1:], 16)
    except ValueError:
        continue
    fn = func_of(ins.address)
    if fn is None or ins.address - fn > 200000:
        continue
    calls.append({"from": ins.address, "to": tgt, "kind": ins.mnemonic, "in_func": fn})

json.dump({"image": os.path.basename(image), "text_addr": addr, "text_size": size,
           "note": "线性扫描；from 落在已知函数起始之后的调用才算有效；未做控制流恢复",
           "calls": calls}, open(out, "w", encoding="utf-8"))
print(f"{os.path.basename(image)}: {len(calls)} calls, text {size} bytes -> {out}")
