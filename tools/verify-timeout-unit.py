#!/usr/bin/env python3
# 为"超时单位=毫秒"补 verify.py 断言，并同步 96 个函数的计数
import io
import json
import os

ROOT = "research/protocol/bluetooth_rfcomm"

# 1) verify.py 断言
p = os.path.join(ROOT, "verify.py")
s = io.open(p, encoding="utf-8").read()
block = '''    # 4d 超时单位 = 毫秒：钩子与消费者汇编必须与 04 C9.3 一致
    hook = open(os.path.join(ROOT, "source/asm/bluetoothd/f_100061690.s"),
                encoding="utf-8", errors="replace").read()
    ok("str w19, [x8, #0xcc8]" in hook, "超时钩子缺少把值写入 0x100c25cc8 的存储")
    cons = open(os.path.join(ROOT, "source/asm/bluetoothd/f_100060ff4.s"),
                encoding="utf-8", errors="replace").read()
    for needle, why in [
        ("mov w26, #0x3e8", "毫秒→秒 的除数 1000"),
        ("mov w27, #0x4240", "毫秒→纳秒 的乘数 0xF4240"),
        ("umull x9, w8, w25", "÷1000 魔数乘法"),
        ("lsr x9, x9, #0x26", "÷1000 的右移 38"),
        ("bl #0x10090b900", "调用 pthread_cond_timedwait_relative_np"),
    ]:
        ok(needle in cons, f"定时器线程汇编缺少「{why}」({needle})")

'''
s = s.replace("    # 5 FCS 表与测试向量", block + "    # 5 FCS 表与测试向量")
s = s.replace(
    'ok(b"_mach_absolute_time" in ftxt and b"_mach_timebase_info" in ftxt,\n'
    '       "导入符号 _mach_absolute_time / _mach_timebase_info 缺失")',
    'ok(b"_mach_absolute_time" in ftxt and b"_mach_timebase_info" in ftxt,\n'
    '       "导入符号 _mach_absolute_time / _mach_timebase_info 缺失")\n'
    '    ok(b"_pthread_cond_timedwait_relative_np" in ftxt,\n'
    '       "导入符号 _pthread_cond_timedwait_relative_np 缺失")',
)
io.open(p, "w", encoding="utf-8").write(s)

# 2) 计数同步 92 -> 96
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
    ("本套文档抽取 **92** 个函数（0.25%）", "本套文档抽取 **96** 个函数（0.26%）"),
    ("| `function-index.json` | 92 个函数的地址", "| `function-index.json` | 96 个函数的地址"),
])
sub("STATUS.md", [
    ("仅 92 / 37,368 个函数（0.25%）", "仅 96 / 37,368 个函数（0.26%）"),
    ("抽取 92（0.25%），其中 52 个被条款引用为证据，40 个仅作旁证",
     "抽取 96（0.26%），其中 56 个被条款引用为证据，40 个仅作旁证"),
])
sub("analysis/00-method-and-environment.md", [
    ("# → bluetoothd: 92 functions, 92 selected rows", "# → bluetoothd: 96 functions, 96 selected rows"),
    ("# → 合计 completed=92 failed=0（含复用器命令族 4 个、定时器/时间基 6 个）",
     "# → 合计 completed=96 failed=0（含复用器命令族 4 个、定时器/时间基 10 个）"),
    ("本套文档实际人工核对 **92 个函数**", "本套文档实际人工核对 **96 个函数**"),
])

# 3) manifest coverage
mp = os.path.join(ROOT, "manifest.json")
m = json.load(io.open(mp, encoding="utf-8"))
m["coverage"] = {
    "documented_functions": 96,
    "total_functions": 37368,
    "ratio": "0.26%",
    "cited_by_analysis": 56,
    "sampled_not_cited": 40,
    "note": "抽样覆盖发现/SDP/RFCOMM（命令族 + 定时器/时间基）/边界；不构成全二进制覆盖声明",
}
json.dump(m, io.open(mp, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
print("counts updated")
