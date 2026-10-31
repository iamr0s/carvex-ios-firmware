#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""扫描整个镜像里「立即数形式的消息 ID」引用点。

iAP2 消息 ID 是 16 位；编译器把它变成 `movz wN,#lo` / `movk wN,#hi,lsl#16`
或单条 `mov wN,#imm`。本工具按函数遍历 LC_FUNCTION_STARTS，记录：
  * 单条 `mov wN, #imm`，imm 落在 [0x0000,0xFFFF]；
  * `movz`/`movk` 相邻对拼出的 32 位值，低 16 位非零且高 16 位为 0。

输出 JSON：{addr, symbol, imm, kind, insn_addr}。
只作定位用；是否真是消息 ID 必须回到汇编上下文确认。
"""
import bisect
import json
import sys

import capstone

IMAGE_BASE = 0x100000000


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

    out = []
    for i, a in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else a + 4
        raw = blob[a - IMAGE_BASE:end - IMAGE_BASE]
        prev = None
        for ins in md.disasm(raw, a):
            if ins.mnemonic == "mov" and ins.op_str.count("#") == 1 and ", #" in ins.op_str:
                try:
                    v = int(ins.op_str.split("#")[1].split(",")[0], 16)
                except ValueError:
                    continue
                if 0 <= v <= 0xFFFF:
                    out.append({"func": hex(a), "name": (byaddr.get(a) or [""])[0],
                                "insn": hex(ins.address), "imm": v, "kind": "mov"})
            elif ins.mnemonic.startswith("movz"):
                try:
                    v = int(ins.op_str.split("#")[1].split(",")[0], 16)
                except (ValueError, IndexError):
                    prev = None
                    continue
                prev = (v, ins.address)
            elif ins.mnemonic.startswith("movk") and prev:
                try:
                    k = int(ins.op_str.split("#")[1].split(",")[0], 16)
                except (ValueError, IndexError):
                    prev = None
                    continue
                v = prev[0] | (k << 16)
                if 0x4000 <= v <= 0x7FFF:
                    out.append({"func": hex(a), "name": (byaddr.get(a) or [""])[0],
                                "insn": hex(prev[1]), "imm": v, "kind": "movz+movk"})
                prev = None
            else:
                prev = None
    path = docset + "/source/metadata/msgid-refs.json"
    json.dump({"count": len(out), "refs": out}, open(path, "w", encoding="utf-8"), indent=1)
    print("wrote", path, len(out), "refs")


if __name__ == "__main__":
    main()
