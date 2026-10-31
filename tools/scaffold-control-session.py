#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Create research/protocol/iap2_control_session/source tree from the link-establishment docset.

Copies (byte-identical) the firmware binary and the Mach-O metadata, then writes
source/metadata/selection.json for this stage:

  * all 114 functions sampled in the previous stage, kept verbatim as the seed
    (their bytes are re-exported from the same binary, so nothing is inherited
    that cannot be re-verified here);
  * the session-layer functions this stage needs.

Run from the repo root:  python3 firmware/tools/scaffold-control-session.py
"""
import hashlib
import json
import os
import shutil

LINK = "research/protocol/iap2_link_establish"
DST = "research/protocol/iap2_control_session"

METADATA_COPY = [
    "summary.json",
    "segments.json",
    "sections.json",
    "load-commands.json",
    "function-starts.json",
    "symbols.json",
]

# group -> human label (kept single-letter like the previous stage)
GROUPS = {
    "X": "会话层核心：会话对象、路由、消息发送",
    "C": "控制会话（control session）",
    "X2": "unused",
}

NEW = [
    # ---- 会话对象与路由 ----
    {"symbol": "_iAP2LinkGetSessionForService", "group": "X",
     "note": "按服务号取会话对象"},
    {"symbol": "_iAP2LinkGetSessionInfo", "group": "X",
     "note": "按服务号取会话信息（含 link+0x120/+0x128 遍历）"},
    {"symbol": "_iap2_sessionRouter_processSessionData", "group": "X",
     "note": "会话路由器：把链路投递的数据分派到具体会话"},
    {"symbol": "_acc_protocolRouter_routeIncomingData", "group": "X",
     "note": "协议路由器入口（iAP1/iAP2 选择）"},
    {"symbol": "_acc_protocolRouter_initProtocolLayer", "group": "X",
     "note": "协议层初始化（注册解析器/处理器）"},
    {"symbol": "_acc_protocolRouter_destroyProtocolLayer", "group": "X",
     "note": "协议层销毁（会话释放路径）"},
    {"symbol": "_acc_endpoint2_processIncomingData", "group": "X",
     "note": "endpoint 收数据 → 协议路由器"},
    {"symbol": "_acc_endpoint2_sendOutgoingData", "group": "X",
     "note": "endpoint 发数据（下行方向）"},
    # ---- 消息编码与发送 ----
    {"symbol": "_iAP2MsgInit", "group": "X", "note": "消息对象初始化（SOM/长度）"},
    {"symbol": "_iAP2MsgGetMsgID", "group": "X", "note": "取消息 ID"},
    {"symbol": "_iAP2MsgGetMsgLen", "group": "X", "note": "取消息长度"},
    {"symbol": "_iAP2MsgCalcMessageLen", "group": "X", "note": "计算编码后长度"},
    {"symbol": "_iAP2MsgSendControl", "group": "X", "note": "控制消息发送入口"},
    {"symbol": "_iAP2MsgSendCtlDataWithSentCallback", "group": "X",
     "note": "带发送回调的控制消息发送（内含按服务号取会话）"},
    {"symbol": "_iAP2MsgPreSendCtlProcess", "group": "X", "note": "发送前处理"},
    {"symbol": "_iAP2MsgSendControlAndCallbackOnAck", "group": "X",
     "note": "ACK 后回调的控制消息发送"},
    {"symbol": "_iAP2MsgSetCallbackOnSend", "group": "X", "note": "设置发送回调"},
    {"symbol": "_iAP2MsgGetSom", "group": "X", "note": "取 SOM（0xFF/0x5A 之类）"},
    # ---- 控制会话 ----
    {"symbol": "_iap2_sessionControl_init", "group": "C", "note": "控制会话初始化"},
    {"symbol": "_iap2_sessionControl_cleanup", "group": "C", "note": "控制会话清理"},
    {"symbol": "_iap2_sessionControl_start", "group": "C", "note": "控制会话启动"},
    {"symbol": "_iap2_sessionControl_getVersion", "group": "C", "note": "版本查询"},
    {"symbol": "_iap2_sessionControl_parseIncomingMessage", "group": "C",
     "note": "控制会话消息解析/分派"},
    {"symbol": "_iap2_sessionControl_accAuthenticationStateChanged", "group": "C",
     "note": "认证状态变化 → 控制会话门控"},
    {"symbol": "_iap2_sessionControl_identificationStateChanged", "group": "C",
     "note": "识别状态变化 → 控制会话门控"},
    {"symbol": "_iap2_sessionControl_authorizationHook_authentication", "group": "C",
     "note": "认证授权钩子"},
    {"symbol": "_iap2_sessionControl_authorizationHook_identification", "group": "C",
     "note": "识别授权钩子"},
    {"symbol": "_iap2_sessionControl_sendOutgoingMessage", "group": "C",
     "note": "控制会话发消息"},
    {"symbol": "_iap2_sessionControl_sendOutgoingMessageAndCallbackOnACK", "group": "C",
     "note": "控制会话发消息并在 ACK 后回调"},
    {"symbol": "___iap2_sessionControl_cleanup_block_invoke", "group": "C",
     "note": "cleanup block 1"},
    {"symbol": "___iap2_sessionControl_cleanup_block_invoke_2", "group": "C",
     "note": "cleanup block 2"},
    {"symbol": "_iap2_CarPlayStartSession", "group": "C",
     "note": "0x4301 处理器（会话启动消息）"},
    # ---- 第二批：会话表读写点、组件注册、会话实现 ----
    {"symbol": "_iAP2LinkActionHandleData", "group": "X",
     "note": "收到数据动作：查会话并调用 DataReadyCB 的地方"},
    {"symbol": "_iAP2LinkQueueSendDataPacketInternal", "group": "X",
     "note": "发送队列（读会话表取会话号）"},
    {"symbol": "_iAP2LinkProcessOutQueue", "group": "X",
     "note": "出队列处理（读会话表）"},
    {"symbol": "_iAP2LinkQueueSendDataWithSentCallback", "group": "X",
     "note": "带回调的入队（读会话表）"},
    {"symbol": "_iAP2LinkGetSessSendPckListCount", "group": "X",
     "note": "每会话待发包计数"},
    {"symbol": "_iAP2LinkResetSend", "group": "X", "note": "发送侧重置（含会话表清零）"},
    {"symbol": "_iAP2LinkAttached", "group": "X", "note": "attach：清会话表并推进 FSM"},
    {"symbol": "_iAP2LinkDetached", "group": "X", "note": "detach：清会话表"},
    {"symbol": "_iAP2LinkSendRST", "group": "X", "note": "RST：清会话表"},
    {"symbol": "_iAP2LinkProcessInOrderPacketCMD", "group": "X",
     "note": "按消息 ID 分派（会话层消息入口）"},
    {"symbol": "_iAP2LinkCommandIsFeatureSetValid", "group": "X", "note": "特性集校验"},
    {"symbol": "_iAP2LinkCommandValidateFeatureSets", "group": "X", "note": "特性集校验"},
    {"symbol": "_iap2_endpoint_create", "group": "X", "note": "iAP2 endpoint 对象创建"},
    {"symbol": "_iap2_endpoint_setInitialized", "group": "X", "note": "endpoint 已初始化标志"},
    {"symbol": "_iap2_features_registerMessageHandlers", "group": "X",
     "note": "全局消息处理器注册"},
    {"symbol": "_iap2_features_createFeatures", "group": "X", "note": "特性创建"},
    {"symbol": "_iap2_features_createFeature", "group": "X", "note": "单特性创建"},
    {"symbol": "_iap2_features_startFeatureFromDevice", "group": "X",
     "note": "从设备侧启动特性（门控）"},
    {"symbol": "_iap2_features_startFeaturesFromDevice", "group": "X",
     "note": "批量启动特性"},
    {"symbol": "_iap2_feature_getFeature", "group": "X", "note": "查特性位（门控）"},
    {"symbol": "_iap2_feature_getFeatureInfoEntries", "group": "X",
     "note": "取特性信息表"},
    {"symbol": "_iap2_features_destroyFeatures", "group": "X", "note": "销毁特性（拆除路径）"},
    {"symbol": "_iap2_sessionFileTransfer_init", "group": "C", "note": "文件传输会话 init"},
    {"symbol": "_iap2_sessionFileTransfer_start", "group": "C", "note": "文件传输会话 start"},
    {"symbol": "_iap2_sessionFileTransfer_getVersion", "group": "C", "note": "文件传输会话版本"},
    {"symbol": "_iap2_sessionFileTransfer_cleanup", "group": "C", "note": "文件传输会话 cleanup"},
    {"symbol": "_iap2_sessionFileTransfer_handleDatagram", "group": "C",
     "note": "文件传输会话收数据"},
    {"symbol": "_iap2_sessionFileTransfer_findTransferEntry", "group": "C",
     "note": "文件传输条目查找"},
    {"symbol": "_iap2_sessionLog_init", "group": "C", "note": "会话日志 init"},
    {"symbol": "_iap2_sessionLog_start", "group": "C", "note": "会话日志 start"},
    {"symbol": "_iap2_sessionLog_cleanup", "group": "C", "note": "会话日志 cleanup"},
    {"symbol": "_iap2_sessionLog_parseIncomingMessage", "group": "C",
     "note": "会话日志收消息"},
    {"symbol": "_iap2_sessionLog_sendOutgoingMessage", "group": "C",
     "note": "会话日志发消息"},
    # ---- 第三批：会话发送实现、处理器注册表、识别门控 ----
    {"symbol": "__sendOutgoingMessage", "group": "C",
     "note": "会话发送实现（被两个 sessionControl_sendOutgoingMessage 尾调用）"},
    {"symbol": "_iap2_messageHandlers_setHandler", "group": "X",
     "note": "全局消息处理器注册（msgID → handler）"},
    {"symbol": "_iap2_messageHandlers_getHandler", "group": "X",
     "note": "全局消息处理器查找"},
    {"symbol": "_iap2_identification_isIdentifiedForIncomingMessageID", "group": "X",
     "note": "入站消息的识别门控"},
    {"symbol": "_iap2_identification_isIdentifiedForOutgoingMessageID", "group": "X",
     "note": "出站消息的识别门控"},
    {"symbol": "_iap2_identification_isIdentifiedForFeature", "group": "X",
     "note": "按特性位的识别门控"},
    {"symbol": "_iap2_identification_isIdentifiedForCarPlay", "group": "X",
     "note": "CarPlay 识别门控"},
    {"symbol": "_iap2_features_registerIdentificationParamHandlers", "group": "X",
     "note": "识别参数处理器注册"},
    {"symbol": "_iap2_features_destroyFeatures", "group": "X", "note": "特性销毁（拆除）"},
    # ---- 第四批：endpoint 生命周期（会话启动/拆除的真正入口） ----
    {"symbol": "_iap2_endpoint_linkStateChanged", "group": "X",
     "note": "链路状态变化 → 会话启停（门控）"},
    {"symbol": "_iap2_endpoint_processIncomingData", "group": "X", "note": "endpoint 收数据"},
    {"symbol": "_iap2_endpoint_sendOutgoingData", "group": "X", "note": "endpoint 发数据"},
    {"symbol": "_iap2_endpoint_destroy", "group": "X", "note": "endpoint 销毁（拆除）"},
    {"symbol": "_iap2_endpoint_isInitialized", "group": "X", "note": "endpoint 初始化状态"},
    {"symbol": "_iap2_endpoint_getMaxSendPayloadSize", "group": "X", "note": "最大发送载荷"},
    {"symbol": "_iap2_endpoint_getLinkMaxCumAck", "group": "X", "note": "CumAck 参数"},
    # ---- 第五批：参数编码原语 ----
    {"symbol": "_iAP2MsgGetParamID", "group": "X", "note": "取参数 ID"},
    {"symbol": "_iAP2MsgGetParamValueLen", "group": "X", "note": "取参数值长度"},
    {"symbol": "_iAP2MsgGetFirstParam", "group": "X", "note": "首个参数"},
    {"symbol": "_iAP2MsgGetNextParam", "group": "X", "note": "下一参数"},
    {"symbol": "_iAP2MsgInitParam", "group": "X", "note": "写参数头"},
    {"symbol": "_iAP2MsgAddU8Param", "group": "X", "note": "加 U8 参数"},
    {"symbol": "_iAP2MsgParserInit", "group": "X", "note": "消息解析器初始化（SOM 0x4040）"},
    {"symbol": "_iAP2MsgParserConsumeByte", "group": "X", "note": "逐字节消息解析"},
]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def main() -> int:
    for sub in ("source/firmware", "source/metadata", "source/asm/accessoryd",
                "readable/ghidra/accessoryd", "analysis", "spec", "runtime", "reference"):
        os.makedirs(os.path.join(DST, sub), exist_ok=True)

    src = os.path.join(LINK, "source/firmware/accessoryd")
    dst = os.path.join(DST, "source/firmware/accessoryd")
    if not os.path.exists(dst):
        shutil.copy2(src, dst)
    a, b = sha256(src), sha256(dst)
    print("binary sha256", b, "match", a == b)
    assert a == b, "binary copy mismatch"

    for name in METADATA_COPY:
        s = os.path.join(LINK, "source/metadata", name)
        d = os.path.join(DST, "source/metadata", name)
        if not os.path.exists(d):
            shutil.copy2(s, d)
        print("metadata", name, os.path.getsize(d))

    old = json.load(open(os.path.join(LINK, "source/metadata/selection.json"), encoding="utf-8"))
    funcs = [{"symbol": f["symbol"], "group": f["group"], "note": f["note"]} for f in old["functions"]]
    # 种子表里本身可能存在同符号重复项（同名别名/重复登记）——按符号去重，
    # 否则同一地址会被导出两次，导致"导出函数数"虚高。
    seen = set()
    seeds = []
    for f in funcs:
        k = f["symbol"].lstrip("_")
        if k in seen:
            print("skip duplicate seed", f["symbol"])
            continue
        seen.add(k)
        seeds.append(f)
    funcs = seeds
    have = {f["symbol"].lstrip("_") for f in funcs}
    seed_count = len(funcs)
    added = 0
    for f in NEW:
        if f["symbol"].lstrip("_") in have:
            print("skip duplicate", f["symbol"])
            continue
        funcs.append(dict(f))
        have.add(f["symbol"].lstrip("_"))
        added += 1
    sel = {
        "image": "accessoryd",
        "note": "种子 = 上一阶段选函数表（按符号去重）；本阶段新增会话层函数",
        "seed_count": seed_count,
        "added_count": added,
        "functions": funcs,
    }
    path = os.path.join(DST, "source/metadata/selection.json")
    json.dump(sel, open(path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print("wrote", path, "functions", len(funcs), "added", added)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
