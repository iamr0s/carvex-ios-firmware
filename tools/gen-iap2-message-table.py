#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Emit analysis/12-message-table.md from source/metadata/tables.json.

The message handler tables live in __DATA_CONST as 16-byte entries:
    { u32 msg_id; u32 reserved; u64 handler_pointer }
Handler pointers use either the rebase form (0x0010_xxxx_xxxx_xxxx) or the
chained-fixup form (0x8010_xxxx_xxxx_xxxx); both decode as
    target = 0x100000000 + (value & 0xFFFFFFFFFF)
This script does not interpret message semantics; it only tabulates what the
firmware bytes contain, and flags entries whose handler has no symbol.
"""
import json
import sys

# Stage classification.  "IN" = the table is read during link establishment
# (identify / authenticate / start session); "OUT" = table exists but belongs to
# later phases, listed for completeness only.
STAGE = {
    "Identification": ("IN", "识别阶段：识别消息"),
    "DeviceAuthentication": ("IN", "认证阶段：设备证书/挑战"),
    "AccAuthentication": ("IN", "认证阶段：配件侧认证"),
    "CarPlayStartSession": ("IN", "会话启动边界"),
    "ExternalAccessory": ("IN", "外部配件协议（EA）识别"),
    "BTConnectionStatus": ("IN", "蓝牙连接状态（链路建立通知）"),
    "OOBBTPairing": ("IN", "OOB 蓝牙配对（链路建立期）"),
    "OOBBTPairing2": ("IN", "OOB 蓝牙配对（链路建立期，第二组）"),
    "BLEPairing": ("IN", "BLE 配对（链路建立期）"),
    "Power": ("IN", "供电/充电状态（建立期会交换）"),
    "USBHostMode": ("OUT", "USB 主机模式（本轮不取证）"),
    "WiFiSharing": ("OUT", "Wi-Fi 共享"),
    "Communications": ("OUT", "通讯类消息"),
    "AppLaunch": ("OUT", "应用启动"),
    "AppLinks": ("OUT", "应用链接"),
    "AssistiveTouch": ("OUT", "辅助触控"),
    "DigitalAudio": ("OUT", "数字音频"),
    "DigitalCarKey_Matching": ("OUT", "数字车钥匙配对"),
    "HID": ("OUT", "HID"),
    "Location": ("OUT", "定位"),
    "MediaLibrary": ("OUT", "媒体库"),
    "Navigation": ("OUT", "导航"),
    "NowPlaying": ("OUT", "正在播放"),
    "Test": ("OUT", "测试消息"),
    "Vehicle": ("OUT", "车辆状态"),
    "VoiceOver": ("OUT", "VoiceOver"),
    "DestinationSharing": ("OUT", "目的地共享"),
}


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    tables = json.load(open(root + "/source/metadata/tables.json", encoding="utf-8"))
    msg = tables["message_handler_tables"]

    lines = []
    out = lines.append
    out("# analysis/12 — 消息处理器表（链路建立相关）")
    out("")
    out("对应任务书第 5 节第 12 项。本文件由 `firmware/tools/gen-iap2-message-table.py`")
    out("从 `source/metadata/tables.json` 生成，内容是**固件字节的表格化**，不含语义推断。")
    out("")
    out("## 12.1 解码规则")
    out("")
    out("A12.1（已确认）消息处理器表以 **16 字节**为一项，布局为：")
    out("")
    out("```")
    out("struct { u32 msg_id; u32 reserved; u64 handler; }")
    out("```")
    out("")
    out("A12.2（已确认）`handler` 指针有两种编码（rebase / chained fixup），统一按")
    out("`target = 0x100000000 + (value & 0xFFFFFFFFFF)` 解码。该规则对 `__DATA_CONST`")
    out("中的状态机表、特性表同样成立（见 `source/metadata/tables.json` 的 `pointer_rule`）。")
    out("")
    out("A12.3（已确认）表项按 `msg_id` 严格递增排列，扫描为线性查找；`msg_id` 为 16 位。")
    out("")
    out("## 12.2 表的总体分布")
    out("")
    out("共 **%d** 张表。" % len(msg))
    out("")
    out("| 表 | 地址 | 项数 | 阶段 | 说明 |")
    out("|---|---|---|---|---|")
    for name in sorted(msg):
        e = msg[name]
        short = name.replace("kiAP2MessageHandlerEntries_", "")
        st, desc = STAGE.get(short, ("OUT", "未分类"))
        out("| `%s` | `%s` | %d | %s | %s |" % (short, e["address"], e["count"], st, desc))
    out("")
    out("阶段标注为 `OUT` 的表**不属于本阶段的取证范围**（任务书决策 #5：消息表只覆盖")
    out("链路建立相关阶段），列出仅为完整性，不给出语义结论。")
    out("")
    out("## 12.3 链路建立相关表（逐项）")
    out("")
    for name in sorted(msg):
        e = msg[name]
        short = name.replace("kiAP2MessageHandlerEntries_", "")
        st, desc = STAGE.get(short, ("OUT", "未分类"))
        if st != "IN":
            continue
        out("### `%s` — %s" % (short, desc))
        out("")
        out("地址 `%s`，%d 项。" % (e["address"], e["count"]))
        out("")
        out("| # | 表偏移 | msg_id | handler | handler 符号 |")
        out("|---|---|---|---|---|")
        for i, x in enumerate(e["entries"]):
            sym = x.get("handler_symbol") or ""
            if not sym:
                sym = "（无符号，函数起点）"
            out("| %d | `+0x%02x` | `0x%04X` | `%s` | %s |"
                % (i, i * 16, x["msg_id"], x["handler"], sym))
        out("")
    out("## 12.4 观察与限制")
    out("")
    out("A12.4（已确认）`Identification` 表只有 3 条，且 handler 均为**无符号函数起点**")
    out("（`0x10011e6e4`、`0x10011ec18`、`0x10013bcc8`）；它们存在于 `LC_FUNCTION_STARTS`，")
    out("说明是真实函数，只是名字被剥掉。因此**不能**用符号名反推这三条消息的语义。")
    out("")
    out("A12.5（已确认）`CarPlayStartSession` 只有 1 条（`0x4301`），`ExternalAccessory` 只有 1 条")
    out("（`0xEA03`）——这两个「阶段边界」消息在固件里都是单条，说明它们不是批量消息族。")
    out("")
    out("A12.6（未确认 / `OPEN-MSG-1`）所有 handler 的**参数与副作用**未取证：本文件只确认")
    out("\"哪个 msg_id 由哪个函数处理\"，不确认处理内容。")
    out("")
    out("A12.7（未确认 / `OPEN-MSG-2`）`msg_id` 的编号空间（例如 `0x1D0x`、`0xAA1x`、`0x43xx`）")
    out("在本二进制里没有枚举名可读，前缀语义无法从固件取证。")
    out("")
    out("## 12.5 未确认点汇总")
    out("")
    out("| ID | 内容 |")
    out("|---|---|")
    out("| `OPEN-MSG-1` | 各 handler 的参数与副作用 |")
    out("| `OPEN-MSG-2` | `msg_id` 前缀分组的语义 |")
    out("| `OPEN-MSG-3` | 无符号 handler（如 Identification 的 3 个）的实际行为 |")
    out("")

    path = root + "/analysis/12-message-table.md"
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    print("wrote", path, len(lines), "lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
