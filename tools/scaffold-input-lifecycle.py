#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""创建 research/protocol/iap2_input_business_lifecycle/source 树（第四阶段）。

做法与第三阶段相同：字节一致地复制固件与 Mach-O 元数据，然后把
`research/protocol/iap2_control_session/source/metadata/selection.json` 里的函数表当作种子
（本阶段重新导出它们的字节，因此不继承任何无法在此复核的东西），再加入本阶段
需要的输入/业务/生命周期函数。未被符号覆盖的处理器按**地址**选取。

用法（仓库根执行）:  python3 firmware/tools/scaffold-input-lifecycle.py
"""
import hashlib
import json
import os
import shutil

SRC = "research/protocol/iap2_control_session"
DST = "research/protocol/iap2_input_business_lifecycle"

METADATA_COPY = [
    "summary.json",
    "segments.json",
    "sections.json",
    "load-commands.json",
    "function-starts.json",
    "symbols.json",
]

GROUPS = {
    "I": "输入：HID 报告与触摸（AssistiveTouch）",
    "N": "NowPlaying（0x50xx）",
    "G": "导航 / HUD（0x52xx、0x0D01）",
    "L": "生命周期：挂起/恢复/断开/清理",
    "P": "平台桥（feature server 一侧）",
}

# (address, label, group, note)
NEW = [
    # ---- HID（特性 11）----
    ("0x100130444", "iap2_hid_handler_6800", "I", "0x6800 处理器（5 个参数：U16/U16/U16/U8/数据）"),
    ("0x100130cf0", "iap2_hid_handler_6802", "I", "0x6802 处理器"),
    ("0x10013101c", "iap2_hid_handler_6805", "I", "0x6805 处理器（4 个参数：U16/U8/U8/数据）"),
    ("0x1001313dc", "iap2_hid_handler_6803", "I", "0x6803 处理器"),
    ("0x1000438d0", "iap2_hid_dispatch_report", "I", "HID 报告下发（未命名函数）"),
    # ---- AssistiveTouch / 触摸（特性 3）----
    ("0x10014bab4", "iap2_atouch_handler_5400", "I", "0x5400 处理器"),
    ("0x10014bbdc", "iap2_atouch_handler_5401", "I", "0x5401 处理器"),
    ("0x10014bcf4", "iap2_atouch_handler_5402", "I", "0x5402 处理器"),
    ("0x10014be18", "iap2_atouch_handler_5404", "I", "0x5404 处理器"),
    ("0x100036c08", "platform_assistiveTouch_accessoryDetached", "P", "AssistiveTouch 断开回调"),
    # ---- NowPlaying（特性 14）----
    ("0x1001499f0", "__startNowPlayingUpdatesHandler", "N", "0x5000 处理器（符号存在）"),
    ("0x10014a93c", "__stopNowPlayingUpdatesHandler", "N", "0x5002 处理器（符号存在）"),
    ("0x10014aa20", "__setNowPlayingInfoHandler", "N", "0x5003 处理器（符号存在）"),
    ("0x100081d40", "setNowPlayingInfoHandler_block_invoke", "N", "0x5003 的 block"),
    ("0x10008ef30", "platform_nowPlaying_playbackAttributesUpdate", "N", "平台侧播控属性更新"),
    ("0x10008f2e4", "platform_nowPlaying_playbackQueueListChanged", "N", "平台侧播放队列变化"),
    ("0x10008f35c", "platform_nowPlaying_setPlaybackElapsedTime", "N", "平台侧进度"),
    ("0x10008f3fc", "platform_nowPlaying_setPlaybackQueueIndex", "N", "平台侧队列索引"),
    ("0x10008f458", "platform_nowPlaying_triggerMediaItemAttributesUpdate", "N", "平台侧媒体项属性"),
    ("0x10008f588", "platform_nowPlaying_copyDefaultMediaItemAttributes", "N", "媒体项缺省属性"),
    ("0x10008f70c", "platform_nowPlaying_triggerMediaItemArtworkUpdate", "N", "媒体项封面"),
    ("0x10008f850", "platform_nowPlaying_triggerPlaybackAttributesUpdate", "N", "播控属性推送"),
    ("0x10008f978", "platform_nowPlaying_copyDefaultPlaybackAttributes", "N", "播控缺省属性"),
    ("0x10008faf8", "platform_nowPlaying_requestPlaybackQueueListInfo", "N", "请求队列信息"),
    # ---- 导航 / HUD（特性 17、23）----
    ("0x10017527c", "iap2_nav_handler_5200", "G", "0x5200 处理器"),
    ("0x10017593c", "iap2_nav_handler_5203", "G", "0x5203 处理器"),
    ("0x100175c70", "iap2_nav_handler_0d01", "G", "0x0D01 处理器"),
    ("0x1000027f4", "iap2_navigation_routeGuidanceUpdateHandler", "G", "iAP2 侧路况更新"),
    ("0x1000020f0", "platform_navigation_routeGuidanceUpdateHandler", "G", "平台侧路况更新"),
    ("0x100003b18", "platform_navigation_routeGuidanceInfoKeyForType", "G", "字段类型 → 键"),
    ("0x100003b28", "ACCNavigationRouteGuidanceUpdateInfo_keyForType", "G", "+[ACCNavigationRouteGuidanceUpdateInfo keyForType:]"),
    ("0x100004428", "__convertRouteGuidanceStateTypeForFunc", "G", "状态映射"),
    # ---- 生命周期 ----
    ("0x10003021c", "iAP2LinkDeviceActionSendSuspend", "L", "设备侧发挂起"),
    ("0x1000302a0", "iAP2LinkDeviceActionSendResume", "L", "设备侧发恢复"),
    ("0x100034db4", "iAP2LinkHandleSuspend", "L", "链路层处理挂起"),
    ("0x100034e68", "iAP2LinkHandleResume", "L", "链路层处理恢复"),
    ("0x1000cb1f0", "iAP2LinkRunLoopHandleSuspend", "L", "run loop 挂起"),
    ("0x1000cb23c", "iAP2LinkRunLoopHandleResume", "L", "run loop 恢复"),
    ("0x1000c2c58", "iap2_power_registerForSleepNotification", "L", "注册休眠通知"),
    ("0x1000c2d68", "iap2_power_unregisterForSleepNotification", "L", "注销休眠通知"),
    ("0x1000c2d7c", "iap2_power_sleepUpdateHandler", "L", "休眠回调"),
    ("0x100027c94", "platform_power_sendSleepUpdate", "L", "平台侧发休眠"),
    ("0x100027ddc", "platform_power_sendWakeUpdate", "L", "平台侧发唤醒"),
    ("0x100028150", "platform_power_registerForSleepWakeUpdate", "L", "平台侧注册睡眠/唤醒"),
    ("0x100028278", "platform_power_unregisterForSleepWakeUpdate", "L", "平台侧注销睡眠/唤醒"),
    ("0x100030d4c", "iap2_endpoint_destroy", "L", "endpoint 销毁"),
    ("0x1000311f4", "iap2_endpoint_linkStateChanged", "L", "链路状态变化"),
    ("0x100034bbc", "iAP2LinkDetached", "L", "链路 detach"),
    ("0x100031c7c", "iAP2LinkActionDetach", "L", "链路 detach 动作"),
    ("0x1000206e0", "platform_btConnectionStatus_accessoryDetached", "L", "BT 连接状态：断开"),
    # ---- 第二批：按符号名可定位的实现（发送侧、平台桥、组件解析）----
    ("0x1001316f4", "iap2_hid_sendOutReport", "I", "HID：设备→配件 out report"),
    ("0x100131864", "iap2_hid_sendGetReport", "I", "HID：设备→配件 get report"),
    ("0x100131a14", "iap2_hid_sendComponentUpdate", "I", "HID：设备→配件 component update"),
    ("0x100043704", "__hidComponentFunctionType", "I", "HID 组件功能类型"),
    ("0x100043cc8", "_parseiAPHIDComponentIdentificationParams", "I", "识别阶段的 iAP HID 组件描述"),
    ("0x1000b2c6c", "platform_hid_register_descriptor", "P", "平台：注册 HID 描述符"),
    ("0x1000b2d60", "platform_hid_in_report", "P", "平台：in report"),
    ("0x1000b2dbc", "platform_hid_get_report_response", "P", "平台：get report 响应"),
    ("0x1000b2e30", "platform_hid_send_out_report", "P", "平台：out report"),
    ("0x1000b2ed0", "platform_hid_send_get_report", "P", "平台：get report"),
    ("0x1000b2f94", "platform_hid_send_component_update", "P", "平台：component update"),
    ("0x10014569c", "iap2_nowPlaying_mediaItemAttributesUpdateHandler", "N", "设备→配件：媒体项属性"),
    ("0x100145e70", "iap2_nowPlaying_mediaItemArtworkUpdateHandler", "N", "设备→配件：封面"),
    ("0x1001465c4", "iap2_nowPlaying_playbackAttributesUpdateHandler", "N", "设备→配件：播放属性"),
    ("0x1001474b4", "iap2_nowPlaying_playbackQueueListChangedHandler", "N", "设备→配件：队列变化"),
    ("0x10014778c", "iap2_nowPlaying_playbackQueueListInfoResponseHandler", "N", "设备→配件：队列信息响应"),
    ("0x10008fbd0", "platform_nowPlaying_addSubscriber", "N", "平台：加订阅者"),
    ("0x10008fc20", "platform_nowPlaying_removeSubscriber", "N", "平台：移除订阅者"),
    ("0x1000dc778", "platform_navigation_startRouteGuidance", "G", "平台：开始导航"),
    ("0x1000dc880", "platform_navigation_stopRouteGuidance", "G", "平台：停止导航"),
    ("0x1000dc974", "platform_navigation_objectDetectionUpdateInfo", "G", "平台：目标检测"),
    ("0x1001777c0", "iap2_navigation_routeGuidanceManeuverUpdateHandler", "G", "配件→设备：机动点更新"),
    ("0x100177d80", "iap2_navigation_laneGuidanceInfoUpdateHandler", "G", "配件→设备：车道指引"),
    ("0x1001783bc", "iap2_navigation_startRoadObjectDetectionHandler", "G", "配件→设备：开始目标检测"),
    ("0x1001788f4", "iap2_navigation_stopRoadObjectDetectionHandler", "G", "配件→设备：停止目标检测"),
    ("0x10014bf24", "iap2_assistiveTouch_notifyStatusUpdateHandler", "I", "设备→配件：AssistiveTouch 状态"),
    ("0x100036ce0", "platform_assistiveTouch_setState", "P", "平台：设置 AssistiveTouch 状态"),
    ("0x100036dd4", "platform_assistiveTouch_requestStatus", "P", "平台：请求状态"),
    ("0x1001670ac", "iap2_vehicle_startStatusUpdatesHandler", "L", "0x5600 车况订阅（生命周期相邻）"),
]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def main() -> int:
    os.makedirs(os.path.join(DST, "source/firmware"), exist_ok=True)
    os.makedirs(os.path.join(DST, "source/metadata"), exist_ok=True)
    os.makedirs(os.path.join(DST, "source/asm/accessoryd"), exist_ok=True)

    src = os.path.join(SRC, "source/firmware/accessoryd")
    dst = os.path.join(DST, "source/firmware/accessoryd")
    if not os.path.exists(dst):
        shutil.copy2(src, dst)
    a, b = sha256(src), sha256(dst)
    print("binary sha256", b, "match", a == b)
    assert a == b, "binary copy mismatch"

    for name in METADATA_COPY:
        s = os.path.join(SRC, "source/metadata", name)
        d = os.path.join(DST, "source/metadata", name)
        if not os.path.exists(d):
            shutil.copy2(s, d)
        assert sha256(s) == sha256(d), name

    old = json.load(open(os.path.join(SRC, "source/metadata/selection.json"), encoding="utf-8"))
    funcs = [{"symbol": f["symbol"], "group": f["group"], "note": f["note"]} for f in old["functions"]]
    seen = set()
    seeds = []
    for f in funcs:
        k = (f["symbol"] or "").lstrip("_")
        if k in seen:
            continue
        seen.add(k)
        seeds.append(f)
    funcs = seeds
    added = 0
    for addr, label, group, note in NEW:
        funcs.append({"symbol": label, "address": addr, "group": group, "note": note})
        added += 1
    sel = {
        "image": "accessoryd",
        "note": "种子 = 第三阶段选函数表（按符号去重）；本阶段新增输入/业务/生命周期函数（多数按地址选）",
        "seed_count": len(funcs) - added,
        "added_count": added,
        "functions": funcs,
    }
    path = os.path.join(DST, "source/metadata/selection.json")
    json.dump(sel, open(path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print("wrote", path, "functions", len(funcs), "added", added)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
