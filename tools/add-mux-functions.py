#!/usr/bin/env python3
"""把新增的 4 个复用器命令相关函数并入 function-index.json 与 analysis/09。

用法：python3 firmware/tools/add-mux-functions.py <docset_dir>
幂等：已存在的地址会被跳过。
"""
import hashlib
import json
import os
import re
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "research/protocol/bluetooth_rfcomm"

NEW = [
    {
        "address": "0x1003c4c88",
        "groups": ["rfcomm-mux-commands"],
        "why": ["信用更新后触发发送（PN 设置初始信用后调用）"],
        "evidence_status": "SAMPLED_NOT_CITED",
        "cited_in": [],
    },
    {
        "address": "0x1003c5884",
        "groups": ["rfcomm-mux-commands"],
        "why": ["复用器命令发送助手 (mux, direction, body, len) -> 组帧并发送"],
        "evidence_status": "SAMPLED_NOT_CITED",
        "cited_in": [],
    },
    {
        "address": "0x1003c6db8",
        "groups": ["rfcomm-mux-commands"],
        "why": ["DLCI 状态变化通知（TEST/FCON 路径使用）"],
        "evidence_status": "SAMPLED_NOT_CITED",
        "cited_in": [],
    },
    {
        "address": "0x1003c71e8",
        "groups": ["rfcomm-mux-commands"],
        "why": ["MSC 命令发送器：构造 0xE1/0xE3 + 长度 0x05/0x07 + 地址字节 + 信号字节"],
        "evidence_status": "CONFIRMED_BY_ANALYSIS",
        "cited_in": ["analysis/04-rfcomm-mux-link-setup.md", "spec/04-rfcomm-link-establishment.md"],
    },
    {
        "address": "0x1003c518c",
        "groups": ["rfcomm-timers"],
        "why": ["RFCOMM 会话定时器启动/重装：登记回调 0x1003c5248 + 超时值"],
        "evidence_status": "CONFIRMED_BY_ANALYSIS",
        "cited_in": ["analysis/04-rfcomm-mux-link-setup.md", "spec/04-rfcomm-link-establishment.md"],
    },
    {
        "address": "0x1003d7a1c",
        "groups": ["rfcomm-timers"],
        "why": ["按 key(0x32=50) 取配置块；+0xa 的 16 位字段是 RFCOMM 超时参数"],
        "evidence_status": "SAMPLED_NOT_CITED",
        "cited_in": [],
    },
    {
        "address": "0x1000609fc",
        "groups": ["rfcomm-timers"],
        "why": ["定时器取消 API（重装前先取消旧定时器）"],
        "evidence_status": "SAMPLED_NOT_CITED",
        "cited_in": [],
    },
    {
        "address": "0x10006135c",
        "groups": ["rfcomm-timers"],
        "why": ["定时器登记：拒绝 bit15 置位的超时值；表项步长 24，回调存在 +8"],
        "evidence_status": "CONFIRMED_BY_ANALYSIS",
        "cited_in": ["analysis/04-rfcomm-mux-link-setup.md", "spec/04-rfcomm-link-establishment.md"],
    },
    {
        "address": "0x1000615dc",
        "groups": ["rfcomm-timers"],
        "why": ["计算到期时刻 now+timeout（16 位）并以 timeout*100 调用平台钩子"],
        "evidence_status": "CONFIRMED_BY_ANALYSIS",
        "cited_in": ["analysis/04-rfcomm-mux-link-setup.md", "spec/04-rfcomm-link-establishment.md"],
    },
    {
        "address": "0x100035440",
        "groups": ["rfcomm-timers"],
        "why": ["时间源：mach_absolute_time × timebase → {u32 微秒, u16 纳秒余数}"],
        "evidence_status": "CONFIRMED_BY_ANALYSIS",
        "cited_in": ["analysis/04-rfcomm-mux-link-setup.md", "spec/04-rfcomm-link-establishment.md"],
    },
    {
        "address": "0x1003d7f28",
        "groups": ["rfcomm-timers"],
        "why": ["定时器模块 init：按配置项分配 24 字节槽表，把平台钩子写入 0x100c39fb8"],
        "evidence_status": "CONFIRMED_BY_ANALYSIS",
        "cited_in": ["analysis/04-rfcomm-mux-link-setup.md", "spec/04-rfcomm-link-establishment.md"],
    },
    {
        "address": "0x100312584",
        "groups": ["rfcomm-timers"],
        "why": ["定时器 init 包装：以第 2 参数接收平台钩子并下传给 0x1003d7f28"],
        "evidence_status": "CONFIRMED_BY_ANALYSIS",
        "cited_in": ["analysis/04-rfcomm-mux-link-setup.md", "spec/04-rfcomm-link-establishment.md"],
    },
    {
        "address": "0x100061690",
        "groups": ["rfcomm-timers"],
        "why": ["平台钩子本体：把 timeout*100 存入 0x100c25cc8 并唤醒定时器线程"],
        "evidence_status": "CONFIRMED_BY_ANALYSIS",
        "cited_in": ["analysis/04-rfcomm-mux-link-setup.md", "spec/04-rfcomm-link-establishment.md"],
    },
    {
        "address": "0x100060ff4",
        "groups": ["rfcomm-timers"],
        "why": ["定时器线程：值按毫秒拆成 timespec（/1000 与 %1000×1e6）后 pthread_cond_timedwait"],
        "evidence_status": "CONFIRMED_BY_ANALYSIS",
        "cited_in": ["analysis/04-rfcomm-mux-link-setup.md", "spec/04-rfcomm-link-establishment.md"],
    },
]


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def main():
    idx_path = os.path.join(ROOT, "function-index.json")
    idx = json.load(open(idx_path, encoding="utf-8"))
    funcs = idx["functions"]
    have = {f["address"] for f in funcs}
    added = 0
    for n in NEW:
        a = n["address"]
        if a in have:
            continue
        base = a[2:]
        raw = os.path.join(ROOT, "source/asm/bluetoothd", f"f_{base}.bin")
        asm = os.path.join(ROOT, "source/asm/bluetoothd", f"f_{base}.s")
        cfile = os.path.join(ROOT, "readable/ghidra/bluetoothd", f"f_{base}.ghidra.c")
        size = os.path.getsize(raw)
        start = int(a, 16)
        end = start + size
        # 从 .s 头部取结束地址（若与 bin 长度一致则用 bin 推算）
        head = open(asm, encoding="utf-8", errors="replace").readline()
        m = re.search(r"0x([0-9a-f]+)\.\.0x([0-9a-f]+)", head)
        if m and int(m.group(1), 16) == start:
            end = int(m.group(2), 16)
        funcs.append(
            {
                "address": a,
                "end": hex(end),
                "size": size,
                "groups": n["groups"],
                "why": n["why"],
                "asm": f"source/asm/bluetoothd/f_{base}.s",
                "raw": f"source/asm/bluetoothd/f_{base}.bin",
                "raw_sha256": sha256_file(raw),
                "assembly_sha256": sha256_file(asm),
                "decompiled": f"readable/ghidra/bluetoothd/f_{base}.ghidra.c",
                "decompile_status": "DECOMPILED_UNREVIEWED",
                "evidence_status": n["evidence_status"],
                "cited_in": n["cited_in"],
            }
        )
        added += 1
        print("added", a, size, "bytes", "decompiled" if os.path.exists(cfile) else "NO .c")

    funcs.sort(key=lambda f: int(f["address"], 16))
    idx["documented_functions"] = len(funcs)
    idx["coverage_note"] = (
        f"本套文档人工核对 {len(funcs)} / {idx['total_functions_in_binary']} 个函数起点"
        f"（{len(funcs) / idx['total_functions_in_binary'] * 100:.2f}%），不构成全栈覆盖。"
    )
    json.dump(idx, open(idx_path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("total", len(funcs), "added", added)

    # analysis/09 统计与表格
    p9 = os.path.join(ROOT, "analysis/09-function-inventory.md")
    s = open(p9, encoding="utf-8").read()
    confirmed = sum(1 for f in funcs if f["evidence_status"] == "CONFIRMED_BY_ANALYSIS")
    sampled = sum(1 for f in funcs if f["evidence_status"] == "SAMPLED_NOT_CITED")
    total = len(funcs)
    s = re.sub(r"本套文档抽取的全部 \d+ 个函数", f"本套文档抽取的全部 {total} 个函数", s)
    s = re.sub(r"本次抽取 \*\*\d+\*\* 个", f"本次抽取 **{total}** 个", s)
    s = re.sub(r"\| `CONFIRMED_BY_ANALYSIS` \| \d+ \|", f"| `CONFIRMED_BY_ANALYSIS` | {confirmed} |", s)
    s = re.sub(r"\| `SAMPLED_NOT_CITED` \| \d+ \|", f"| `SAMPLED_NOT_CITED` | {sampled} |", s)
    s = re.sub(r"\| 合计 \| \d+ \| — \|", f"| 合计 | {total} | — |", s)
    rows = []
    for f in funcs:
        if f["address"] in {n["address"] for n in NEW} and f["address"] not in s:
            cite = "、".join(f["cited_in"]) if f["cited_in"] else "—"
            role = "MSC 组帧依据" if f["evidence_status"] == "CONFIRMED_BY_ANALYSIS" else "复用器命令路径旁证"
            rows.append(
                f"| `{f['address']}` | {f['size']} | {f['groups'][0]} | {f['why'][0]} | {role} | {cite} |"
            )
    if rows:
        s = s.rstrip("\n") + "\n" + "\n".join(rows) + "\n"
    open(p9, "w", encoding="utf-8").write(s)
    print(f"analysis/09: total={total} confirmed={confirmed} sampled={sampled} rows_added={len(rows)}")


if __name__ == "__main__":
    main()
