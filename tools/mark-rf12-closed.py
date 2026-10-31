#!/usr/bin/env python3
# 把 OPEN-RF-12 在其余文件里的提及统一改为"已关闭"，并保持 OPEN 计数为 39
import io
import os

ROOT = "research/protocol/bluetooth_rfcomm"


def sub(path, pairs):
    p = os.path.join(ROOT, path)
    s = io.open(p, encoding="utf-8").read()
    for a, b in pairs:
        if a not in s:
            print("MISS", path, a[:60])
            continue
        s = s.replace(a, b)
    io.open(p, "w", encoding="utf-8").write(s)


sub("analysis/04-rfcomm-mux-link-setup.md", [
    (
        '补证轮次新增。目标：回答"超时值 30 到底是什么单位"（`OPEN-RF-12`）。',
        '补证轮次新增。目标：回答"超时值 30 到底是什么单位"（`OPEN-RF-12`，本轮**已关闭**）。',
    ),
])

sub("analysis/06-rfcomm-disconnect-and-cleanup.md", [
    (
        "单位**无法从本次抽样确定**：可能为 100 ms（→3 s）、1 s（→30 s）或 tick。标记 `OPEN-RF-12`。可确定的是：超时值来自配置结构 `+0x0A`，可被外部覆盖。",
        "单位已由后续补证确定为 **100 ms/单位**（`analysis/04` C9.3）：默认 30 → **3.000 s**。`OPEN-RF-12` 已关闭。超时值来自配置结构 `+0x0A`，可被外部覆盖。",
    ),
    (
        "| `OPEN-RF-12` | 定时器单位与 `FUN_1003c518c` 的语义 | 未定位时基常量 |",
        "| `OPEN-RF-12` | ~~定时器单位与 `FUN_1003c518c` 的语义~~ **已关闭**：单位 = 100 ms（30 → 3 s），见 `analysis/04` C9.3 | 已定位时基与平台定时器调用链 |",
    ),
])

sub("analysis/09-function-inventory.md", [
    (
        "| `OPEN-RF-12`（超时单位） | **已收窄**：`0x1003c518c` → `0x10006135c` → `0x1000615dc` → `0x100035440`（`_mach_absolute_time`） | 见 `analysis/04` C9 |",
        "| `OPEN-RF-12`（超时单位） | **已关闭**：`0x1003c6180` → `0x1003c518c` → `0x10006135c` → `0x1000615dc` → `0x100061690` → `0x100060ff4` | 单位 = 100 ms（30 → 3 s），见 `analysis/04` C9.3 |",
    ),
])

sub("runtime/README.md", [
    (
        "| 5 | 超时相关日志的时间差 | `OPEN-RF-12`（定时器单位） | 未执行（同上） |",
        "| 5 | 超时相关日志的时间差 | `OPEN-RF-12`（定时器单位）**已由静态证据关闭**（=100 ms，30→3 s） | 无需执行；如需实测可对照 CF-75 |",
    ),
])

sub("STATUS.md", [
    (
        "| OPEN 项 | 39 项（其中 2 项来自运行时观测；`OPEN-RF-12` 本轮关闭）",
        "| OPEN 项 | 39 项（其中 2 项来自运行时观测；`OPEN-RF-12` 本轮已关闭）",
    ),
])
print("done")
