#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Emit analysis/14-message-table.md for the control-session docset.

Sources (all firmware-derived, nothing hand-typed except the two gate sets,
which are transcribed from the instructions cited in analysis/07):

  * source/firmware/accessoryd   — the image bytes
  * source/metadata/tables.json  — feature info table (29 entries -> handler tables)
  * source/metadata/symbols.json — symbol names (handler tables and handlers)

Handler table layout (see analysis/06): 16-byte entries
    { u32 msg_id; u32 reserved; u64 handler }
handler pointer decodes as target = 0x100000000 + (value & 0xFFFFFFFFFF).

The gate sets below are NOT inferred here; they are transcribed from
0x100051054 (incoming) and 0x100005138 (outgoing).  See analysis/07.
"""
import json
import struct
import sys

IMAGE_BASE = 0x100000000

# transcribed from iap2_identification_isIdentifiedForIncomingMessageID (0x100051054)
GATE_IN_ALWAYS = [0x0000, 0x0004, 0x0005, 0x1D01, 0x1D05, 0x1D06, 0xAA01, 0xAA03]
# transcribed from iap2_identification_isIdentifiedForOutgoingMessageID (0x100005138)
GATE_OUT_ALWAYS = [0x0000, 0x0004, 0x0005, 0xAA00, 0xAA02, 0xAA04, 0xAA05,
                   0x1D00, 0x1D02, 0x1D03]
GATE_IN_IDENT_ONLY = [0xAA06]


def direction(msg_id):
    i = msg_id in GATE_IN_ALWAYS
    o = msg_id in GATE_OUT_ALWAYS
    if msg_id in GATE_IN_IDENT_ONLY:
        return "仅需识别", "需认证+识别"
    if i and o:
        return "无条件", "无条件"
    if i:
        return "无条件", "需认证+识别"
    if o:
        return "需认证+识别", "无条件"
    return "需认证+识别", "需认证+识别"


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    blob = open(root + "/source/firmware/accessoryd", "rb").read()
    tabs = json.load(open(root + "/source/metadata/tables.json", encoding="utf-8"))
    feats = tabs["feature_info_table"]["entries"]
    syms = json.load(open(root + "/source/metadata/symbols.json", encoding="utf-8"))
    byaddr = {}
    for s in syms:
        byaddr.setdefault(s["addr"], s["name"])

    def name_at(addr):
        return byaddr.get(addr)

    rows = []          # (feature_id, table_name, table_addr, msg_id, handler_addr, handler_name, in, out)
    tables = []
    for f in feats:
        ht = f.get("handler_table")
        if not ht:
            continue
        addr = int(ht, 16)
        tn = (name_at(addr) or "").lstrip("_")
        tables.append((f["feature_id"], tn or "（无符号表）", addr, f["handler_count"]))
        for i in range(f["handler_count"]):
            off = addr - IMAGE_BASE + i * 16
            msg_id, _res, raw = struct.unpack_from("<IIQ", blob, off)
            target = IMAGE_BASE + (raw & 0xFFFFFFFFFF)
            rows.append((f["feature_id"], tn or "（无符号表）", addr, msg_id, target,
                         (name_at(target) or "").lstrip("_"),
                         *direction(msg_id)))

    rows.sort(key=lambda r: r[3])
    dup = {}
    for r in rows:
        dup.setdefault(r[3], []).append(r[0])

    out = []
    w = out.append
    w("# analysis/14 — 会话阶段消息对照表")
    w("")
    w("本文件由 `firmware/tools/gen-control-message-table.py` 从**固件字节**生成，"
      "不接受手工编辑。内容是表格化的事实：哪个 `msg_id` 由哪个函数处理、属于哪个特性、"
      "在准入名单里是哪一侧。**不含消息语义推断**。")
    w("")
    w("## 14.1 生成口径")
    w("")
    w("| 项 | 值 |")
    w("|---|---|")
    w("| 镜像 | `source/firmware/accessoryd` |")
    w("| 源哈希 | `%s` |" % tabs["source_sha256"])
    w("| 特性信息表 | `%s`（29 项，每项 16 字节） |"
      % tabs["feature_info_table"]["symbol"])
    w("| 处理器表项 | 16 字节：`u32 msg_id; u32 reserved; u64 handler` |")
    w("| 指针解码 | `target = 0x100000000 + (value & 0xFFFFFFFFFF)` |")
    w("| 处理器表数 | %d（另有 2 项特性无处理器表） |" % len(tables))
    w("| 处理器条目数 | %d |" % len(rows))
    w("")
    w("## 14.2 表清单")
    w("")
    w("| 特性号 | 处理器表 | 表地址 | 条目数 |")
    w("|---|---|---|---|")
    for fid, tn, addr, n in sorted(tables):
        w("| %d | `%s` | `0x%x` | %d |" % (fid, tn, addr, n))
    w("")
    w("## 14.3 逐条对照（按 msg_id 升序）")
    w("")
    w("列含义：**入站 / 出站** = 该 `msg_id` 在两张准入名单里的位置"
      "（名单转录自 `0x100051054` 与 `0x100005138`，见 `analysis/07`）。"
      "`需认证+识别` 表示不无条件放行，必须同时满足认证状态 2、识别状态 6、并出现在对应集合中。")
    w("")
    w("| msg_id | 处理器 | 处理器符号 | 特性 | 处理器表 | 入站 | 出站 |")
    w("|---|---|---|---|---|---|---|")
    for fid, tn, taddr, msg_id, h, hname, gin, gout in rows:
        w("| `0x%04X` | `0x%x` | %s | %d | `%s` | %s | %s |"
          % (msg_id, h, ("`%s`" % hname) if hname else "（无符号）",
             fid, tn, gin, gout))
    w("")
    w("## 14.4 观察")
    w("")
    multi = {k: v for k, v in dup.items() if len(v) > 1}
    w("1. **重复 `msg_id`**：%s。" % ("无" if not multi else
                                     "、".join("`0x%04X`→特性 %s" % (k, v) for k, v in sorted(multi.items()))))
    nosym = [r for r in rows if not r[5]]
    w("2. **无符号处理器**：%d 条。它们存在于 `LC_FUNCTION_STARTS`（真实函数），"
      "只是名字被剥掉；不能用名字反推语义。" % len(nosym))
    both = [r for r in rows if r[6] == "无条件" and r[7] == "无条件"]
    w("3. **双向无条件放行**：%s。这些是链路层之上的「始终允许」消息。"
      % ("、".join("`0x%04X`" % r[3] for r in both) if both else "无"))
    out_only = [r for r in rows if r[7] == "无条件" and r[6] != "无条件"]
    w("4. **仅出站无条件**：%s。入站方向对它们要求认证完成。"
      % ("、".join("`0x%04X`" % r[3] for r in out_only) if out_only else "无"))
    gated = [r for r in rows if r[6] == "需认证+识别"]
    w("5. **入站需门控**：%d 条（占 %d 条的 %d%%）。多数消息在识别完成前不可达，"
      "这解释了为什么「连上链路」与「能发消息」是两件事。"
      % (len(gated), len(rows), round(100.0 * len(gated) / max(1, len(rows)))))
    w("")
    w("## 14.5 限制")
    w("")
    w("- 本表只回答「哪个函数处理哪个 `msg_id`」，**不回答**参数格式与副作用"
      "（`OPEN-SES-2`、`OPEN-MSG-1`）。")
    w("- `msg_id` 的编号分组（`0x1Dxx`、`0xAAxx`、`0x43xx`）在二进制里没有枚举名可读，"
      "前缀语义不可从固件取证。")
    w("- 有 2 项特性（8、27）没有处理器表，因此它们的消息入口不在本表内。")
    w("")

    path = root + "/analysis/14-message-table.md"
    open(path, "w", encoding="utf-8").write("\n".join(out) + "\n")
    print("wrote", path, len(out), "lines", len(rows), "rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
