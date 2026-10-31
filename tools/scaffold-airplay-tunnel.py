#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Create research/protocol/iap2_airplay_tunnel/source tree from the control-session docset.

Copies (byte-identical) the firmware binary and the Mach-O metadata, then writes
source/metadata/selection.json for this stage:

  * the session-layer functions sampled in the previous stage, kept verbatim as
    the seed (their bytes are re-exported from the same binary, so nothing is
    inherited that cannot be re-verified here);
  * the tunnel functions this stage needs (iAP2 secure-tunnel envelope, mfi4Auth
    relay, transport-server secure-tunnel plumbing).

Run from the repo root:  python3 firmware/tools/scaffold-airplay-tunnel.py
"""
import hashlib
import json
import os
import shutil

SRC = "research/protocol/iap2_control_session"
DST = "research/protocol/iap2_airplay_tunnel"

METADATA_COPY = [
    "summary.json",
    "segments.json",
    "sections.json",
    "load-commands.json",
    "function-starts.json",
    "symbols.json",
]

GROUPS = {
    "T": "隧道信封与 relay（0x5500/0x5501/0x5503、type、capabilities）",
    "S": "传输服务器与 endpoint 的 secure-tunnel 接口",
    "P": "消息/参数原语（信封内外都要用）",
}

NEW = [
    # ---- 隧道信封 ----
    {"symbol": "_mfi4Auth_util_packIntoTunnelDataiAP2Msg", "group": "T",
     "note": "打包：CFData → 0x5500/0x5501（param0=type, param1=data）"},
    {"symbol": "_mfi4Auth_util_unpackFromTunnelDataiAP2Msg", "group": "T",
     "note": "解包：0x5500/0x5501/0x5503 → CFData + type"},
    {"symbol": "_mfi4Auth_util_parseMessage", "group": "T",
     "note": "用 0x4040 SOM 解析外层消息"},
    {"symbol": "_mfi4Auth_protocol_processIncomingMessageRelay", "group": "T",
     "note": "relay 入站分派（按 msgID 决定 unpack/handler）"},
    {"symbol": "_mfi4Auth_relay_handle_iAP2RelayRemote", "group": "T",
     "note": "按 type 查 secure tunnel handler 并投递"},
    {"symbol": "_mfi4Auth_relay_StartRelayForType", "group": "T",
     "note": "启动 relay：capabilities mask / 支持的 type"},
    {"symbol": "_mfi4Auth_relay_cleanup", "group": "T", "note": "relay 清理"},
    {"symbol": "_mfi4Auth_relay_initMessage_RequestiAP2RelayRead", "group": "T",
     "note": "relay 读请求消息构造"},
    {"symbol": "_mfi4Auth_relay_initMessage_DeviceiAP2RelayRemote", "group": "T",
     "note": "relay 消息基构造"},
    {"symbol": "_mfi4Auth_relay_initMessage_DeviceiAP2RelayRemote_TypeData", "group": "T",
     "note": "带 type+data 的 relay 消息构造"},
    {"symbol": "_mfi4Auth_relay_initMessage_DeviceiAP2RelayRemote_RequestAccessoryInfoUpdate",
     "group": "T", "note": "请求配件信息更新的 relay 消息"},
    {"symbol": "_mfi4Auth_relay_handle_iAP2RelaySucceeded", "group": "T",
     "note": "relay 成功回调"},
    {"symbol": "_mfi4Auth_relay_handle_iAP2RelayFailed", "group": "T",
     "note": "relay 失败回调"},
    {"symbol": "__mfi4Auth_relay_handle_AccessoryInformationUpdate", "group": "T",
     "note": "配件信息更新消息处理"},
    # ---- 发往客户端的 secure tunnel 数据 ----
    {"symbol": "_mfi4Auth_protocol_processOutgoingSecureTunnelDataForClient", "group": "S",
     "note": "协议层把 secure tunnel 数据发给客户端"},
    {"symbol": "_mfi4Auth_endpoint_processOutgoingSecureTunnelDataForClient", "group": "S",
     "note": "endpoint 层封送 secure tunnel 数据"},
    {"symbol": "_mfi4Auth_protocol_setSecureTunnelDataReceiveTypeHandler", "group": "S",
     "note": "按 type 注册接收 handler（protocol 层）"},
    {"symbol": "_mfi4Auth_endpoint_setEndpointSecureTunnelDataReceiveTypeHandler", "group": "S",
     "note": "按 type 注册接收 handler（endpoint 层）"},
    {"symbol": "_mfi4Auth_protocol_messageHandler_handleOutgoingSecureTunnelDataForClient",
     "group": "S", "note": "messageHandler 层的出站 secure tunnel 数据"},
    {"symbol": "_mfi4Auth_protocol_messageHandler_setEndpointSecureTunnelDataReceiveTypeHandler",
     "group": "S", "note": "messageHandler 层注册 type handler"},
    # ---- 传输服务器 ----
    {"symbol": "-[ACCTransportServer receivedSecureTunnelData:forEndpointWithUUID:connectionUUID:]",
     "group": "S", "note": "传输服务器收到隧道路由数据"},
    {"symbol": "-[ACCTransportServer receivedSecureTunnelData:forEndpointWithUUID:connectionUUID:toClient:]",
     "group": "S", "note": "定向到具体客户端的隧道路由"},
    {"symbol": "-[ACCTransportServer receivedSecureTunnelDataHandler:forEndpointWithUUID:connectionUUID:]",
     "group": "S", "note": "隧道路由 handler 安装"},
    {"symbol": "_acc_endpoint2_setEndpointSecureTunnelDataReceiveTypeHandler", "group": "S",
     "note": "endpoint 对象侧注册 type handler"},
    {"symbol": "_acc_endpoint2_getTransportTypeStringWithTransportType", "group": "S",
     "note": "传输类型 → 名称（抓包里的 AirPlay/Bluetooth Classic 来源）"},
    {"symbol": "_acc_manager2_getTransportTypeStringFromTransportType", "group": "S",
     "note": "传输类型名称表的另一处"},
    {"symbol": "_acc_manager2_createEndpointForConnection", "group": "S",
     "note": "按连接创建 endpoint"},
    {"symbol": "_acc_connection2_getTransportTypeForEndpoint", "group": "S",
     "note": "从连接取 endpoint 的传输类型"},
    # ---- 参数原语 ----
    {"symbol": "_iAP2MsgAddDataParam", "group": "P", "note": "加数据参数（信封 param1）"},
    {"symbol": "_iAP2MsgGetDataAsU8", "group": "P", "note": "取 U8 参数（信封 param0=type）"},
    {"symbol": "_iAP2MsgGetDataAsData", "group": "P", "note": "取数据参数（信封 param1=data）"},
    {"symbol": "_iAP2MsgAddU8Param", "group": "P", "note": "加 U8 参数"},
    {"symbol": "_iAP2MsgParserInit", "group": "P", "note": "解析器初始化（SOM 0x4040）"},
]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def main() -> int:
    for sub in ("source/firmware", "source/metadata", "source/asm/accessoryd",
                "readable/ghidra/accessoryd", "analysis", "spec", "runtime",
                "reference-impl", "reference"):
        os.makedirs(os.path.join(DST, sub), exist_ok=True)

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
        print("metadata", name, os.path.getsize(d))

    old = json.load(open(os.path.join(SRC, "source/metadata/selection.json"), encoding="utf-8"))
    funcs = [{"symbol": f["symbol"], "group": f["group"], "note": f["note"]} for f in old["functions"]]
    seen = set()
    seeds = []
    for f in funcs:
        k = f["symbol"].lstrip("_")
        if k in seen:
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
        "note": "种子 = 控制会话阶段选函数表（按符号去重）；本阶段新增隧道函数",
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
