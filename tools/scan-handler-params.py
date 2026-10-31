#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""扫描 iAP2 消息处理器里的「参数 ID → 取值函数」分派表。

用法:
  python3 scan-handler-params.py <docset> <addr> [<addr> ...]

对每个处理器地址:
  * 反汇编到下一个 LC_FUNCTION_STARTS 起点；
  * 找 `cmp w0, #N` 紧跟 `b.hi` 的形态，得到参数 ID 上界；
  * 找随后 `adrp/add` 取表地址、`adr` 取基址、`ldrsw` 索引的跳表，
    按 32 位有符号偏移解出每个参数 ID 的 case 地址（case = adr_pc + off）；
  * 每个 case 里第一条 `bl` 即取值函数（名称从符号表解析）。

输出 JSON 到 stdout；本工具只产出可复核的中间事实，不写文件。
"""
import bisect
import json
import sys

import capstone

IMAGE_BASE = 0x100000000


def load(docset):
    meta = docset + "/source/metadata/"
    blob = open(docset + "/source/firmware/accessoryd", "rb").read()
    syms = json.load(open(meta + "symbols.json", encoding="utf-8"))
    starts = sorted(set(json.load(open(meta + "function-starts.json", encoding="utf-8"))))
    byaddr = {}
    for s in syms:
        byaddr.setdefault(s["addr"], []).append(s["name"])
    return blob, byaddr, starts


def extent(starts, a):
    i = bisect.bisect_right(starts, a)
    return starts[i] if i < len(starts) else a + 4


def name_at(byaddr, a):
    v = byaddr.get(a) or []
    for n in v:
        if n:
            return n
    return None


def imm(op_str):
    """取操作数里第一个 #0x.. 的值。"""
    return int(op_str.split("#")[1].split(",")[0].strip(), 16)


def scan(blob, byaddr, starts, addr):
    end = extent(starts, addr)
    raw = blob[addr - IMAGE_BASE:end - IMAGE_BASE]
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.skipdata = True
    ins = list(md.disasm(raw, addr))
    base = {"addr": hex(addr), "name": name_at(byaddr, addr), "extent": hex(end)}

    # 1) 参数 ID 上界
    lim_idx, limit = None, None
    for i in range(len(ins) - 1):
        if ins[i].mnemonic == "cmp" and ins[i].op_str.startswith("w0, #") \
                and ins[i + 1].mnemonic.startswith("b.hi"):
            lim_idx, limit = i, imm(ins[i].op_str)
            break
    if limit is None:
        return dict(base, limit=None, note="未找到 cmp w0,#N + b.hi")
    base["limit"] = limit

    # 2) 跳表
    table = adr_pc = None
    for j in range(lim_idx, min(lim_idx + 20, len(ins))):
        if ins[j].mnemonic == "adrp" and table is None:
            reg = ins[j].op_str.split(",")[0]
            page = imm(ins[j].op_str)
            for k in range(j + 1, min(j + 4, len(ins))):
                if ins[k].mnemonic == "add" and ins[k].op_str.startswith(reg + ", " + reg + ", #"):
                    table = page + imm(ins[k].op_str)
        elif ins[j].mnemonic == "adr" and adr_pc is None:
            adr_pc = imm(ins[j].op_str)
    if table is None or adr_pc is None:
        return dict(base, table=None, note="跳表未识别")

    base["table"] = hex(table)
    base["adr_pc"] = hex(adr_pc)
    entries = []
    for pid in range(limit + 1):
        off = table - IMAGE_BASE + pid * 4
        val = int.from_bytes(blob[off:off + 4], "little", signed=True)
        case = adr_pc + val
        gi = next((k for k, x in enumerate(ins) if x.address == case), None)
        item = {"param_id": pid, "case": hex(case)}
        if gi is None:
            item["getter"] = None
            item["note"] = "case 不在本函数体内"
        else:
            calls = []
            for k in range(gi, min(gi + 10, len(ins))):
                if ins[k].mnemonic.startswith("bl"):
                    t = int(ins[k].op_str.split("#")[1], 16)
                    calls.append((t, name_at(byaddr, t)))
                if ins[k].mnemonic.startswith("b") and not ins[k].mnemonic.startswith("bl"):
                    break
            # 第一条非 OUTLINED_FUNCTION 的调用才是真正的取值函数
            real = [(t, n) for t, n in calls
                    if not (n or "").startswith("_OUTLINED_FUNCTION")]
            pick = real[0] if real else (calls[0] if calls else (None, None))
            item["getter"] = hex(pick[0]) if pick[0] else None
            item["getter_name"] = pick[1]
            item["calls"] = ["0x%x %s" % (t, n or "") for t, n in calls[:4]]
        entries.append(item)
    base["entries"] = entries
    return base


def main():
    docset = sys.argv[1]
    blob, byaddr, starts = load(docset)
    out = [scan(blob, byaddr, starts, int(a, 16)) for a in sys.argv[2:]]
    print(json.dumps(out, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
