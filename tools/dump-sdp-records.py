#!/usr/bin/env python3
"""从 pklg 抓包里提取并解码 SDP 交互（请求/响应），用于佐证 SDP 相关条款。

用法：dump-sdp-records.py <build_dir> <out.txt>
  build_dir 需包含 logs/Bluetooth/*.pklg

输出（追加写）：
  - 每个 pklg 的统计（记录数 / ACL 包 / L2CAP 帧 / CID 分布）
  - 命中目标 UUID 的 SDP 载荷原文 + 数据元素解码
"""
import collections
import glob
import os
import struct
import sys

TYPE = {0: "NIL", 1: "UINT", 2: "INT", 3: "UUID", 4: "TEXT", 5: "BOOL", 6: "SEQ", 7: "ALT", 8: "URL"}

UUIDS = {
    "WiapGateWay": "00000000decafadedecadeafdecacafe",
    "WiapSink": "00000000decafadedecadeafdecacaff",
    "Carplay": "ec884348cd4140a29727575d50bf1fd3",
    "CarplayGateway": "2d8d2466e14d451c88bc7301abea291a",
    "AapServer": "7221ec740bad4d018f77997b2be0722a",
}


def elem(b, i):
    h = b[i]
    t = (h >> 3) & 0x1F
    s = h & 7
    i += 1
    if s == 0:
        n = 1
    elif s == 1:
        n = 2
    elif s == 2:
        n = 4
    elif s == 3:
        n = 8
    elif s == 4:
        n = 16
    elif s == 5:
        n = b[i]; i += 1
    elif s == 6:
        n = struct.unpack_from(">H", b, i)[0]; i += 2
    else:
        n = struct.unpack_from(">I", b, i)[0]; i += 4
    return t, n, b[i:i + n], i + n


def fmt_uuid(u):
    h = u.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def dump_elem(t, n, v):
    if t == 3:
        return f'UUID{"128" if n == 16 else n * 8} {fmt_uuid(v)}'
    if t == 1:
        return f"UINT{n * 8} {int.from_bytes(v, 'big')}"
    if t == 4:
        return f'TEXT "{v.decode("utf-8", "replace")}"'
    if t == 6:
        out = []
        i = 0
        while i < len(v):
            t2, n2, v2, i = elem(v, i)
            out.append(dump_elem(t2, n2, v2))
        return "SEQ[" + ", ".join(out) + "]"
    return f"{TYPE.get(t, t)} len={n} {v.hex()}"


def decode_sdp(pl, out):
    pid = pl[0]
    tid = struct.unpack_from(">H", pl, 1)[0]
    ln = struct.unpack_from(">H", pl, 3)[0]
    p = pl[5:5 + ln]
    out.append(f"  PDU={pid} tid={tid:#06x} paramlen={ln} raw={pl.hex()}")
    if pid == 6:
        t, n, v, i = elem(p, 0)
        out.append("   SearchPattern: " + dump_elem(t, n, v))
        out.append("   MaxAttrByteCount: " + str(struct.unpack_from(">H", p, i)[0]))
        i += 2
        t, n, v, i = elem(p, i)
        out.append("   AttributeIDList: " + dump_elem(t, n, v))
        out.append("   Continuation: " + (p[i:i + 1].hex() or "(none)"))
    elif pid == 5:
        out.append("   AttributeListByteCount: " + str(struct.unpack_from(">H", p, 0)[0]))
        t, n, v, i = elem(p, 2)
        out.append("   AttributeList: " + dump_elem(t, n, v))
        out.append("   Continuation: " + (p[i:i + 1].hex() or "(none)"))
    elif pid == 2:
        t, n, v, i = elem(p, 0)
        out.append("   SearchPattern: " + dump_elem(t, n, v))
        out.append("   MaxRecords: " + str(struct.unpack_from(">H", p, i)[0]))
        i += 2
        out.append("   Continuation: " + (p[i:i + 1].hex() or "(none)"))
    elif pid == 3:
        out.append("   TotalRecordCount: " + str(struct.unpack_from(">H", p, 0)[0]))
        t, n, v, i = elem(p, 4)
        out.append("   RecordHandleList: " + dump_elem(t, n, v))
        out.append("   Continuation: " + (p[i:i + 1].hex() or "(none)"))
    else:
        out.append("   " + p.hex())


def frames_of(path):
    data = open(path, "rb").read()
    pos = 0
    recs = []
    while pos + 4 <= len(data):
        (rl,) = struct.unpack_from(">I", data, pos)
        if rl < 9 or pos + 4 + rl > len(data):
            break
        recs.append((data[pos + 12], data[pos + 13:pos + 4 + rl]))
        pos += 4 + rl
    buf = {}
    frames = []
    for t, p in recs:
        if t != 3:
            continue
        hf, dl = struct.unpack_from("<HH", p, 0)
        h = hf & 0xFFF
        pb = (hf >> 12) & 3
        b = (buf.get(h, b"") + p[4:4 + dl]) if pb == 1 else p[4:4 + dl]
        while len(b) >= 4:
            ln, cid = struct.unpack_from("<HH", b, 0)
            if len(b) < 4 + ln:
                break
            frames.append((h, cid, b[4:4 + ln]))
            b = b[4 + ln:]
        buf[h] = b
    return recs, frames


def main():
    build, outpath = sys.argv[1], sys.argv[2]
    for path in sorted(glob.glob(os.path.join(build, "logs", "Bluetooth", "*.pklg"))):
        out = [f"# pklg: {os.path.basename(path)}  size={os.path.getsize(path)}",
               "# 解析：pklg 记录 -> ACL 重组 -> L2CAP -> 按 UUID 字节匹配 -> SDP 元素按 [type:5][size:3] 解码"]
        recs, frames = frames_of(path)
        out.append(f"# 记录数={len(recs)} ACL包={sum(1 for t, _ in recs if t == 3)} L2CAP帧={len(frames)}")
        out.append("# L2CAP CID 分布: " + str({hex(k): v for k, v in
                                            collections.Counter(c for _, c, _ in frames).items()}))
        for name, u in UUIDS.items():
            for lab, pat in (("BE", bytes.fromhex(u)), ("LE", bytes.fromhex(u)[::-1])):
                for h, cid, pl in frames:
                    if pat in pl:
                        out.append(f"### cid={cid:#06x} handle={h:#x} 命中 {name} ({lab})")
                        decode_sdp(pl, out)
        out.append("")
        mode = "a" if os.path.exists(outpath) else "w"
        with open(outpath, mode, encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        print(outpath, len(out), "lines", mode)


if __name__ == "__main__":
    main()
