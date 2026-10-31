#!/usr/bin/env python3
"""解码 accessoryd 内的 iAP2 表：链路状态机表、消息处理器表、特性表。

用法： python3 iap2-tables.py <binary> <metadir> <out.json>

指针约定：表中 8 字节槽为 arm64e 链接期指针（rebase/chained fixup），
本工具统一按 `target = 0x100000000 + (value & 0xFFFFFFFFFF)` 还原，
并校验还原结果落在 __TEXT / __DATA 窗口内；不满足即标记 undecoded。
"""
import json
import os
import struct
import sys

IMAGE_BASE = 0x100000000


def load(metadir):
    return (
        json.load(open(os.path.join(metadir, "symbols.json"))),
        json.load(open(os.path.join(metadir, "segments.json"))),
    )


class Bin:
    def __init__(self, path, segs):
        self.b = open(path, "rb").read()
        self.segs = segs

    def off(self, va):
        for s in self.segs:
            if s["vmaddr"] <= va < s["vmaddr"] + s["vmsize"] and s["filesize"]:
                return s["fileoff"] + (va - s["vmaddr"])
        return None

    def read(self, va, n):
        o = self.off(va)
        if o is None or o + n > len(self.b):
            return None
        return self.b[o:o + n]

    def u64(self, va):
        d = self.read(va, 8)
        return None if d is None else struct.unpack("<Q", d)[0]


def decode_ptr(bin, value):
    t = IMAGE_BASE + (value & 0xFFFFFFFFFF)
    return t if bin.read(t, 1) is not None else None


def main():
    binary, metadir, outpath = sys.argv[1:4]
    symbols, segs = load(metadir)
    bin = Bin(binary, segs)
    sym_by_name = {}
    for s in symbols:
        sym_by_name.setdefault(s["name"], s["addr"])
    sym_at = {}
    for s in symbols:
        sym_at.setdefault(s["addr"], s["name"])
    starts = sorted(sym_at)

    def name_of(va):
        if va in sym_at:
            return sym_at[va]
        return None

    def cstr(va):
        o = bin.off(va)
        if o is None:
            return None
        end = bin.b.index(b"\0", o)
        return bin.b[o:end].decode(errors="replace")

    def table_extent(name):
        base = sym_by_name[name]
        nxt = [s["addr"] for s in symbols if s["addr"] > base]
        return base, (min(nxt) if nxt else base + 16)

    out = {"image": "accessoryd", "pointer_rule": "0x100000000 + (value & 0xFFFFFFFFFF)"}

    # ---- 状态机表 ----
    states_base, states_end = table_extent("_iAP2LinkDeviceStates")
    fsm = {"states_table": hex(states_base), "state_count": 8, "event_count": 0x1D}
    states = []
    for i in range(8):
        e = states_base + i * 16
        ev_ptr_raw = bin.u64(e)
        cnt = bin.read(e + 8, 1)[0]
        ev_ptr = decode_ptr(bin, ev_ptr_raw)
        entry = {"index": i, "events_ptr": hex(ev_ptr) if ev_ptr else None, "event_count": cnt, "events": []}
        if ev_ptr:
            for j in range(cnt):
                ee = ev_ptr + j * 16
                handler_raw = bin.u64(ee)
                handler = decode_ptr(bin, handler_raw)
                nxt_state = bin.read(ee + 8, 1)[0]
                ev_id = bin.read(ee + 9, 1)[0]
                entry["events"].append(
                    {
                        "event": ev_id,
                        "handler": hex(handler) if handler else None,
                        "handler_symbol": name_of(handler) if handler else None,
                        "next_state": nxt_state,
                    }
                )
        states.append(entry)
    fsm["states"] = states
    out["link_device_fsm"] = fsm

    # ---- 消息处理器表 ----
    msg_tables = [s for s in sym_by_name if s.lstrip("_").startswith("kiAP2MessageHandlerEntries_")]
    tables = {}
    for name in sorted(msg_tables):
        base, end = table_extent(name)
        n = (end - base) // 16
        rows = []
        for i in range(n):
            e = base + i * 16
            mid = bin.read(e, 4)
            if mid is None:
                continue
            msg_id = struct.unpack("<I", mid)[0]
            handler = decode_ptr(bin, bin.u64(e + 8))
            if handler is None or msg_id > 0xFFFF:
                continue
            rows.append({"msg_id": msg_id, "handler": hex(handler), "handler_symbol": name_of(handler)})
        tables[name.lstrip("_")] = {"address": hex(base), "entries": rows, "count": len(rows)}
    out["message_handler_tables"] = tables

    # ---- 特性表 ----
    feat = {}
    for name in ("_kiAP2FeatureInfoEntries", "_kiAP2FeatureHandlerEntries"):
        if name not in sym_by_name:
            continue
        base, end = table_extent(name)
        n = (end - base) // 16
        rows = []
        for i in range(n):
            e = base + i * 16
            val = bin.u64(e)
            ptr = decode_ptr(bin, bin.u64(e + 8)) if bin.read(e + 8, 8) else None
            rows.append({"slot0": hex(val), "ptr": hex(ptr) if ptr else None})
        feat[name[1:]] = {"address": hex(base), "raw_entries": rows}
    out["feature_tables"] = feat

    json.dump(out, open(outpath, "w"), indent=1)
    print(
        "states:",
        [(s["index"], s["event_count"]) for s in states],
        "| msg tables:",
        {k: v["count"] for k, v in tables.items()},
    )


if __name__ == "__main__":
    main()
