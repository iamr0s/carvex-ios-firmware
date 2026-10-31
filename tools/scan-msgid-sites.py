#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""定位「消息 ID 的发送点与比较点」。

两种形态：
  A. 发送点：`mov  w1, #X`（≤4 条指令内）→ `bl iAP2MsgSetMsgID`（0x1000676c4）；
  B. 比较点：`mov  w8, #X`（≤3 条指令内）→ `cmp w0, w8`（紧随其后）。

只保留 `0x4000 ≤ X ≤ 0x7FFF` 的候选（iAP2 业务消息段）。
输出 JSON：{"sites":[{"func","name","insn","imm","kind","call"}]}。
仍属定位，判定方向必须回到上下文。
"""
import json
import sys

import capstone

IMAGE_BASE = 0x100000000
SET_MSGID = 0x1000676C4


def main():
    docset = sys.argv[1]
    meta = docset + "/source/metadata/"
    blob = open(docset + "/source/firmware/accessoryd", "rb").read()
    syms = json.load(open(meta + "symbols.json", encoding="utf-8"))
    starts = sorted(set(json.load(open(meta + "function-starts.json", encoding="utf-8"))))
    byaddr = {}
    for s in syms:
        byaddr.setdefault(s["addr"], []).append(s["name"])
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.skipdata = True

    sites = []
    for i, a in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else a + 4
        ins = list(md.disasm(blob[a - IMAGE_BASE:end - IMAGE_BASE], a))
        for k in range(len(ins)):
            x = ins[k]
            if x.mnemonic.startswith("bl") and "#" in x.op_str:
                try:
                    t = int(x.op_str.split("#")[1], 16)
                except ValueError:
                    continue
                if t != SET_MSGID:
                    continue
                for j in range(max(0, k - 4), k):
                    y = ins[j]
                    if y.mnemonic == "mov" and y.op_str.startswith("w1, #"):
                        v = int(y.op_str.split("#")[1], 16)
                        if 0x4000 <= v <= 0x7FFF:
                            sites.append({"func": hex(a), "name": (byaddr.get(a) or [""])[0],
                                          "insn": hex(y.address), "imm": v,
                                          "kind": "send", "call": hex(x.address)})
            if x.mnemonic == "cmp" and x.op_str in ("w0, w8", "w0, w9", "w0, w10"):
                reg = x.op_str.split(",")[1].strip()
                for j in range(max(0, k - 3), k):
                    y = ins[j]
                    if y.mnemonic == "mov" and y.op_str.startswith(reg + ", #"):
                        v = int(y.op_str.split("#")[1], 16)
                        if 0x4000 <= v <= 0x7FFF:
                            sites.append({"func": hex(a), "name": (byaddr.get(a) or [""])[0],
                                          "insn": hex(y.address), "imm": v,
                                          "kind": "compare", "call": hex(x.address)})
    path = docset + "/source/metadata/msgid-sites.json"
    json.dump({"count": len(sites), "sites": sites}, open(path, "w", encoding="utf-8"), indent=1)
    print("wrote", path, len(sites), "sites")


if __name__ == "__main__":
    main()
