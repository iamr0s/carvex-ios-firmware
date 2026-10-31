#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""为「输入 / 业务 / 生命周期」阶段的每个 iAP2 消息处理器生成事实表。

用法:
  python3 gen-input-handler-facts.py <docset> [--md <out.md>]

对每个目标处理器输出：
  * 参数 ID 上界与跳表地址（`cmp w0,#N` + `b.hi` + `ldrsw` 跳表）；
  * 每个参数 ID 的取值函数（按 `0x100067e1c`=U16、`0x100067e4c`=U8、
    `0x100067f30`=原始数据返回 `param+4`、`0x100067720`=取值长度 分类）；
  * 函数体内按顺序出现的 `bl` 目标（符号名缺失则留空——真实函数但名字被剥掉）；
  * 函数体内引用到的可打印 C 字符串（地址 + 内容）；
  * 调用的 ObjC selector（`objc_msgSend$…`）。
"""
import bisect
import json
import sys

import capstone

IMAGE_BASE = 0x100000000

TARGETS = [
    ("0x6800", "0x100130444", "HID"),
    ("0x6802", "0x100130cf0", "HID"),
    ("0x6805", "0x10013101c", "HID"),
    ("0x6803", "0x1001313dc", "HID"),
    ("0x5000", "0x1001499f0", "NowPlaying"),
    ("0x5002", "0x10014a93c", "NowPlaying"),
    ("0x5003", "0x10014aa20", "NowPlaying"),
    ("0x5200", "0x10017527c", "Navigation"),
    ("0x5203", "0x10017593c", "Navigation"),
    ("0x0D01", "0x100175c70", "Navigation"),
    ("0x5400", "0x10014bab4", "AssistiveTouch"),
    ("0x5401", "0x10014bbdc", "AssistiveTouch"),
    ("0x5402", "0x10014bcf4", "AssistiveTouch"),
    ("0x5404", "0x10014be18", "AssistiveTouch"),
]

GETTERS = {
    0x100067e1c: "U16（校验总长=6）",
    0x100067e4c: "U8（校验总长=5）",
    0x100067f30: "原始数据指针（返回 param+4）",
    0x100067720: "取值长度（总长-4）",
    0x100067734: "原始数据（iAP2MsgGetParamRawData）",
    0x100067ee4: "字符串",
    0x100067df0: "U32",
    0x100067e74: "Bool",
}
GATES = {
    0x100051054: "入站识别/认证门控",
    0x100005138: "出站识别/认证门控",
    0x100003360: "按特性号取特性对象（门控前置）",
    0x10013ec58: "从设备侧启动特性",
}


def imm(op):
    return int(op.split("#")[1].split(",")[0].strip(), 16)


def best_name(byaddr, a):
    for n in (byaddr.get(a) or []):
        if n:
            return n
    return ""


def load(docset):
    meta = docset + "/source/metadata/"
    blob = open(docset + "/source/firmware/accessoryd", "rb").read()
    syms = json.load(open(meta + "symbols.json", encoding="utf-8"))
    starts = sorted(set(json.load(open(meta + "function-starts.json", encoding="utf-8"))))
    byaddr = {}
    for s in syms:
        byaddr.setdefault(s["addr"], []).append(s["name"])
    return blob, byaddr, starts


def cstr(blob, a):
    off = a - IMAGE_BASE
    if off < 0 or off >= len(blob):
        return None
    end = blob.find(b"\x00", off, off + 300)
    if end < 0:
        return None
    raw = blob[off:end]
    if len(raw) < 3 or not all(32 <= c < 127 or c in (9, 10) for c in raw):
        return None
    return raw.decode("ascii", "replace")


def analyze(blob, byaddr, starts, addr):
    end = starts[bisect.bisect_right(starts, addr)] if bisect.bisect_right(starts, addr) < len(starts) else addr + 4
    raw = blob[addr - IMAGE_BASE:end - IMAGE_BASE]
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.skipdata = True
    ins = list(md.disasm(raw, addr))
    out = {"addr": hex(addr), "end": hex(end), "name": best_name(byaddr, addr)}

    # 参数分派
    params = []
    for i in range(len(ins) - 1):
        if ins[i].mnemonic == "cmp" and ins[i].op_str.startswith("w0, #") and ins[i + 1].mnemonic.startswith("b.hi"):
            limit = imm(ins[i].op_str)
            table = base = None
            for j in range(i, min(i + 20, len(ins))):
                if ins[j].mnemonic == "adrp" and table is None:
                    reg = ins[j].op_str.split(",")[0]
                    page = imm(ins[j].op_str)
                    for k in range(j + 1, min(j + 4, len(ins))):
                        if ins[k].mnemonic == "add" and ins[k].op_str.startswith(reg + ", " + reg + ", #"):
                            table = page + imm(ins[k].op_str)
                elif ins[j].mnemonic == "adr" and base is None and table:
                    base = imm(ins[j].op_str)
            if table and base:
                out["param_limit"] = limit
                out["jump_table"] = hex(table)
                for pid in range(limit + 1):
                    off = table - IMAGE_BASE + pid * 4
                    val = int.from_bytes(blob[off:off + 4], "little", signed=True)
                    case = base + val
                    gi = next((k for k, x in enumerate(ins) if x.address == case), None)
                    item = {"id": pid, "case": hex(case)}
                    if gi is not None:
                        cand = []
                        for k in range(gi, min(gi + 10, len(ins))):
                            if ins[k].mnemonic == "bl":
                                cand.append(int(ins[k].op_str.split("#")[1], 16))
                        real = [t for t in cand
                                if not (best_name(byaddr, t) or "").startswith("_OUTLINED_FUNCTION")]
                        t = real[0] if real else (cand[0] if cand else None)
                        if t:
                            item["getter"] = hex(t)
                            item["kind"] = GETTERS.get(t) or best_name(byaddr, t) or "（无符号，未分类）"
                    params.append(item)
                break
    out["params"] = params

    calls, strings, sels = [], [], []
    pending = {}
    for k, x in enumerate(ins):
        if x.mnemonic == "adrp":
            reg = x.op_str.split(",")[0]
            pending[reg] = imm(x.op_str)
        elif x.mnemonic == "add" and "," in x.op_str and "#" in x.op_str:
            parts = [p.strip() for p in x.op_str.split(",")]
            if len(parts) == 3 and parts[0] == parts[1] and parts[2].startswith("#") and parts[0] in pending:
                a = pending[parts[0]] + imm(parts[2])
                s = cstr(blob, a)
                if s and s not in [y[1] for y in strings]:
                    strings.append((a, s))
        if x.mnemonic.startswith("bl") and "#" in x.op_str:
            t = int(x.op_str.split("#")[1], 16)
            nm = best_name(byaddr, t)
            if not nm and t in GETTERS:
                nm = "取值原语：" + GETTERS[t].split("（")[0]
            calls.append((t, nm))
            if nm.startswith("_objc_msgSend$"):
                sels.append(nm.split("$", 1)[1])
    out["calls"] = [("0x%x" % t, n) for t, n in calls]
    out["strings"] = [("0x%x" % a, s) for a, s in strings]
    out["selectors"] = sels
    out["gates"] = [GATES[t] for t, _ in calls if t in GATES]
    return out


def md_table(facts):
    L = []
    w = L.append
    w("# analysis/02 — 输入/业务处理器事实表（机器生成）")
    w("")
    w("本文件由 `firmware/tools/gen-input-handler-facts.py` 从固件字节生成，**不接受手工编辑**。")
    w("它只记录可机械复核的事实：参数 ID 上界、跳表地址、每个参数 ID 的取值函数、")
    w("函数体内的调用序列、引用的 C 字符串、调用的 selector。**不含字段语义推断**。")
    w("")
    for msg, addr, dom in TARGETS:
        f = next(x for x in facts if x["addr"] == addr)
        w("## `%s` — `%s`（%s）" % (msg, addr, dom))
        w("")
        w("| 项 | 值 |")
        w("|---|---|")
        w("| 符号 | %s |" % (("`%s`" % f["name"]) if f["name"] else "（无符号：真实函数，名字被剥掉）"))
        w("| 区间 | `%s`–`%s` |" % (f["addr"], f["end"]))
        if "param_limit" in f:
            w("| 参数 ID 上界 | `#%d`（`cmp w0,#%d` + `b.hi`） |" % (f["param_limit"], f["param_limit"]))
            w("| 跳表 | `%s` |" % f["jump_table"])
        else:
            w("| 参数分派 | 未见 `cmp w0,#N` + 跳表形态 |")
        w("| 门控调用 | %s |" % ("、".join(f["gates"]) if f["gates"] else "无"))
        w("")
        if f["params"]:
            w("| 参数 ID | case | 取值函数 | 类型/说明 |")
            w("|---|---|---|---|")
            for p in f["params"]:
                w("| `%d` | `%s` | `%s` | %s |" % (p["id"], p["case"], p.get("getter", "—"), p.get("kind", "—")))
            w("")
        if f["selectors"]:
            w("调用的 selector（出现顺序，去重）：")
            w("")
            seen = []
            for s in f["selectors"]:
                if s not in seen:
                    seen.append(s)
            for s in seen[:24]:
                w("- `%s`" % s)
            w("")
        if f["strings"]:
            w("引用的可打印字符串：")
            w("")
            w("| 地址 | 内容 |")
            w("|---|---|")
            for a, s in f["strings"][:24]:
                esc = s.replace("|", "\\|")
                w("| `%s` | `%s` |" % (a, esc))
            w("")
        w("<details><summary>调用序列（按地址顺序，前 40 条）</summary>")
        w("")
        for a, n in f["calls"][:40]:
            w("- `%s` %s" % (a, ("`%s`" % n) if n else "（无符号）"))
        w("")
        w("</details>")
        w("")
    return "\n".join(L) + "\n"


def main():
    docset = sys.argv[1]
    blob, byaddr, starts = load(docset)
    facts = [analyze(blob, byaddr, starts, int(a, 16)) for _, a, _ in TARGETS]
    md = md_table(facts)
    path = docset + "/analysis/02-handler-facts.md"
    open(path, "w", encoding="utf-8", newline="\n").write(md)
    print("wrote", path, len(md.splitlines()), "lines")


if __name__ == "__main__":
    main()
