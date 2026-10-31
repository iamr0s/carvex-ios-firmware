#!/usr/bin/env python3
# 把重连退避的 5 个函数并入索引/清单，同步计数与断言
import io
import json
import os
import re

ROOT = "research/protocol/bluetooth_rfcomm"

NEW = [
    {
        "address": "0x1005fcb40",
        "groups": ["rfcomm-reconnect"],
        "why": ["ScanCorePageScan 退避定时器：固定 300 s（0x45D964B800 ns → dispatch）"],
        "evidence_status": "CONFIRMED_BY_ANALYSIS",
        "cited_in": ["analysis/06-rfcomm-disconnect-and-cleanup.md", "spec/06-lifecycle-and-boundary.md"],
    },
    {
        "address": "0x1005fcd8c",
        "groups": ["rfcomm-reconnect"],
        "why": ["连接请求看门狗：秒参数 × 1e9 → dispatch 定时器"],
        "evidence_status": "CONFIRMED_BY_ANALYSIS",
        "cited_in": ["analysis/06-rfcomm-disconnect-and-cleanup.md", "spec/06-lifecycle-and-boundary.md"],
    },
    {
        "address": "0x1005fcaf8",
        "groups": ["rfcomm-reconnect"],
        "why": ["读设备重试计数（u8 @ dev+0x647），用于 5 次上限判定"],
        "evidence_status": "CONFIRMED_BY_ANALYSIS",
        "cited_in": ["analysis/06-rfcomm-disconnect-and-cleanup.md", "spec/06-lifecycle-and-boundary.md"],
    },
    {
        "address": "0x1006428ac",
        "groups": ["rfcomm-reconnect"],
        "why": ["看门狗调用方：按条件取 8 s / 16 s 作为 stall 超时"],
        "evidence_status": "CONFIRMED_BY_ANALYSIS",
        "cited_in": ["analysis/06-rfcomm-disconnect-and-cleanup.md", "spec/06-lifecycle-and-boundary.md"],
    },
    {
        "address": "0x100139d70",
        "groups": ["rfcomm-reconnect"],
        "why": ["页扫描定时器重设（秒），重连时用 60 s"],
        "evidence_status": "CONFIRMED_BY_ANALYSIS",
        "cited_in": ["analysis/06-rfcomm-disconnect-and-cleanup.md", "spec/06-lifecycle-and-boundary.md"],
    },
]

# 1) function-index.json
ip = os.path.join(ROOT, "function-index.json")
idx = json.load(io.open(ip, encoding="utf-8"))
have = {f["address"] for f in idx["functions"]}
added = 0
for row in NEW:
    if row["address"] in have:
        continue
    size = os.path.getsize(
        os.path.join(ROOT, "source/asm/bluetoothd", "f_%s.bin" % row["address"][2:])
    )
    row = dict(row)
    row["size"] = size
    idx["functions"].append(row)
    added += 1
idx["functions"].sort(key=lambda f: int(f["address"], 16))
json.dump(idx, io.open(ip, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
print("index total", len(idx["functions"]), "added", added)

# 2) analysis/09 表格重建
p = os.path.join(ROOT, "analysis/09-function-inventory.md")
lines = io.open(p, encoding="utf-8").read().split("\n")
addr_re = re.compile(r"^\| `0x([0-9a-f]+)`")
rows = {}
for l in lines:
    m = addr_re.match(l)
    if m:
        rows[m.group(1)] = l


def gen(f):
    g = f["groups"][0]
    role = {
        "rfcomm-timers": ("超时/时间基依据", "定时器路径旁证"),
        "rfcomm-mux-commands": ("MSC 组帧依据", "复用器命令路径旁证"),
        "rfcomm-reconnect": ("重连节奏依据", "重连路径旁证"),
    }.get(g)
    if not role:
        return None
    role = role[0] if f["evidence_status"] == "CONFIRMED_BY_ANALYSIS" else role[1]
    cite = "、".join(f["cited_in"]) if f["cited_in"] else "—"
    return "| `%s` | %d | %s | %s | %s | %s |" % (
        f["address"], f["size"], g, f["why"][0], role, cite)


for f in idx["functions"]:
    r = gen(f)
    if r:
        rows[f["address"][2:]] = r

hdr = "| 地址 | 大小 | 分组 | 抽样理由 | 本文档角色 | 引用 |"
i = lines.index(hdr)
body = lines[: i + 2]
tail = lines[i + 2:]
j = 0
while j < len(tail) and tail[j].startswith("|"):
    j += 1
table = [rows[a] for a in sorted(rows, key=lambda x: int(x, 16))]
io.open(p, "w", encoding="utf-8").write("\n".join(body + table + tail[j:]))
print("inventory rows", len(table))

# 3) verify.py 断言
vp = os.path.join(ROOT, "verify.py")
s = io.open(vp, encoding="utf-8").read()
block = '''    # 4e 重连节奏：固定步长 + 硬上限（04/06 的结论）
    bko = open(os.path.join(ROOT, "source/asm/bluetoothd/f_1005fcb40.s"),
               encoding="utf-8", errors="replace").read()
    for needle, why in [
        ("mov x1, #0xb800", "300 s 的低 16 位"),
        ("movk x1, #0xd964, lsl #16", "300 s 的中 16 位"),
        ("movk x1, #0x45, lsl #32", "300 s 的高位 0x45"),
    ]:
        ok(needle in bko, f"退避定时器汇编缺少「{why}」({needle})")
    wd = open(os.path.join(ROOT, "source/asm/bluetoothd/f_1005fcd8c.s"),
              encoding="utf-8", errors="replace").read()
    for needle, why in [
        ("mov w8, #0xca00", "1e9 的低位 0xCA00"),
        ("movk w8, #0x3b9a, lsl #16", "1e9 的高位 0x3B9A"),
        ("umull x1, w20, w8", "秒 × 1e9"),
    ]:
        ok(needle in wd, f"看门狗汇编缺少「{why}」({needle})")
    rc = open(os.path.join(ROOT, "source/asm/bluetoothd/f_1005fcaf8.s"),
              encoding="utf-8", errors="replace").read()
    ok("ldrb w19, [x19, #0x647]" in rc, "重试计数读取（dev+0x647）缺失")
    wc = open(os.path.join(ROOT, "source/asm/bluetoothd/f_1006428ac.s"),
              encoding="utf-8", errors="replace").read()
    ok("csel w21, w8, w21, eq" in wc, "看门狗 8 s / 16 s 条件选择缺失")
    sm = open(os.path.join(ROOT, "source/asm/bluetoothd/f_1001479fc.s"),
              encoding="utf-8", errors="replace").read()
    ok("cmp w0, #4" in sm, "重试上限判定（>4 即超限）缺失")
    ok("mov w1, #0x3c" in sm, "页扫描定时器 60 s 缺失")

'''
s = s.replace("    # 5 FCS 表与测试向量", block + "    # 5 FCS 表与测试向量")
io.open(vp, "w", encoding="utf-8").write(s)

# 4) 计数
def sub(path, pairs):
    q = os.path.join(ROOT, path)
    t = io.open(q, encoding="utf-8").read()
    for a, b in pairs:
        if a not in t:
            print("MISS", path, a[:50])
            continue
        t = t.replace(a, b)
    io.open(q, "w", encoding="utf-8").write(t)


sub("README.md", [
    ("本套文档抽取 **96** 个函数（0.26%）", "本套文档抽取 **101** 个函数（0.27%）"),
    ("| `function-index.json` | 96 个函数的地址", "| `function-index.json` | 101 个函数的地址"),
])
sub("STATUS.md", [
    ("仅 96 / 37,368 个函数（0.26%）", "仅 101 / 37,368 个函数（0.27%）"),
    ("抽取 96（0.26%），其中 56 个被条款引用为证据，40 个仅作旁证",
     "抽取 101（0.27%），其中 61 个被条款引用为证据，40 个仅作旁证"),
])
sub("analysis/00-method-and-environment.md", [
    ("# → bluetoothd: 96 functions, 96 selected rows", "# → bluetoothd: 101 functions, 101 selected rows"),
    ("# → 合计 completed=96 failed=0（含复用器命令族 4 个、定时器/时间基 10 个）",
     "# → 合计 completed=101 failed=0（含复用器命令族 4 个、定时器/时间基 10 个、重连 5 个）"),
    ("本套文档实际人工核对 **96 个函数**", "本套文档实际人工核对 **101 个函数**"),
])

# 5) manifest coverage
mp = os.path.join(ROOT, "manifest.json")
m = json.load(io.open(mp, encoding="utf-8"))
m["coverage"] = {
    "documented_functions": 101,
    "total_functions": 37368,
    "ratio": "0.27%",
    "cited_by_analysis": 61,
    "sampled_not_cited": 40,
    "note": "抽样覆盖发现/SDP/RFCOMM（命令族 + 定时器/时间基 + 重连节奏）/边界；不构成全二进制覆盖声明",
}
json.dump(m, io.open(mp, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
print("counts updated")
