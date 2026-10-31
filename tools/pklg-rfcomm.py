#!/usr/bin/env python3
"""从 Apple PacketLogger (.pklg) 抓包里提取 RFCOMM 帧，用于**佐证**静态结论。

只做三件事：
  1. 解析 pklg 记录（[len:4be][ts_sec:4be][ts_usec:4be][type:1][hci data]）；
  2. 重组 ACL 分片，解析 L2CAP（[len:2][cid:2][payload]），从信令通道找出 PSM=3(RFCOMM) 的 CID；
  3. 用固件里的 FCS 表按帧类别校验抓到的 RFCOMM 帧，并打印地址/控制/长度解码结果。

用法：
  pklg-rfcomm.py <file.pklg> [--binary <bluetoothd>]

CID 的帧头判定仅为候选，不是完整 RFCOMM 状态机；P/F 信用按样本结构推断，
没有重建 PN 流控状态，不能据此宣称任意会话已完成协议验证。
"""
import collections
import struct
import sys

DEFAULT_TABLE_OFFSET = 0x100934A0 // 1  # 见下方 main：偏移按地址 - 0x100000000
BASE = 0x100000000


def parse_pklg(path):
    data = open(path, "rb").read()
    pos = 0
    n = 0
    while pos + 4 <= len(data):
        (rec_len,) = struct.unpack_from(">I", data, pos)
        if rec_len < 9 or pos + 4 + rec_len > len(data):
            break
        ts_sec, ts_usec = struct.unpack_from(">II", data, pos + 4)
        typ = data[pos + 12]
        payload = data[pos + 13:pos + 4 + rec_len]
        yield n, ts_sec, ts_usec, typ, payload
        pos += 4 + rec_len
        n += 1


def load_fcs_table(binary_path):
    d = open(binary_path, "rb").read()
    off = 0x9349A0  # 0x1009349a0 - 0x100000000
    return d[off:off + 256]


def fcs(body, table):
    v = 0xFF
    for b in body:
        v = table[b ^ v]
    return v ^ 0xFF


def main():
    args = [a for a in sys.argv[1:]]
    if not args:
        print(__doc__)
        return
    path = args[0]
    binary = None
    for i, a in enumerate(args):
        if a == "--binary":
            binary = args[i + 1]
    table = load_fcs_table(binary) if binary else None

    types = collections.Counter()
    acl_by_handle = collections.defaultdict(list)
    cid_kind = {}
    l2cap_frames = []  # (handle, cid, payload)
    # 第一遍：收集 ACL 与 L2CAP
    for n, ts, tus, typ, payload in parse_pklg(path):
        types[typ] += 1
        if typ in (2, 3) and len(payload) >= 4:
            hf, dlen = struct.unpack_from("<HH", payload, 0)
            body = payload[4:4 + dlen]
            h = hf & 0x0FFF
            pb = (hf >> 12) & 0x3
            bc = (hf >> 14) & 0x3
            acl_by_handle[(typ, h)].append((n, pb, bc, body))
    for (typ, h), chunks in acl_by_handle.items():
        buf = b""
        for n, pb, bc, body in chunks:
            # HCI ACL PB 字段：0b00=首片(不可冲刷)、0b10=首片(可冲刷)、0b01=续片
            if pb == 0b01:
                buf += body
            else:
                buf = body
            while len(buf) >= 4:
                (llen, cid) = struct.unpack_from("<HH", buf, 0)
                if len(buf) < 4 + llen:
                    break
                l2cap_frames.append((h, cid, buf[4:4 + llen]))
                buf = buf[4 + llen:]

    # 第二遍：L2CAP 信令里找 PSM=3 的连接
    for h, cid, pl in l2cap_frames:
        if cid == 0x0001 and len(pl) >= 4:
            code, ident, dlen = pl[0], pl[1], struct.unpack_from("<H", pl, 2)[0]
            if code == 0x02 and dlen >= 4 and len(pl) >= 8:  # Connection Request
                psm, scid = struct.unpack_from("<HH", pl, 4)
                if psm == 0x0003:
                    cid_kind[scid] = f"RFCOMM(psm3, handle {h})"

    print(f"文件: {path}")
    print(f"记录数: {sum(types.values())}  类型分布: {dict(types)}")
    print("ACL 句柄: " + str({"%s/%03x" % ("TX" if k[0] == 2 else "RX", k[1]): len(v)
                              for k, v in acl_by_handle.items()}))
    print(f"L2CAP 帧: {len(l2cap_frames)}  CID 分布: "
          f"{ {hex(k): v for k, v in collections.Counter(c for _, c, _ in l2cap_frames).items()} }")
    # 抓包常从中途开始：没有 PSM=3 的连接请求时，用帧头特征补充判定
    CTRL = {0x2F, 0x3F, 0x43, 0x53, 0x63, 0x73, 0x0F, 0x1F, 0xEF, 0xFF}
    for h, cid, pl in l2cap_frames:
        if cid >= 0x40 and cid not in cid_kind and len(pl) >= 2:
            if (pl[0] & 1) and pl[1] in CTRL:
                cid_kind[cid] = f"RFCOMM(帧头判定, handle {h})"
    print(f"判定为 RFCOMM 的 CID: {cid_kind}")

    rf = [(h, cid, pl) for h, cid, pl in l2cap_frames if cid in cid_kind]
    print(f"RFCOMM 帧数: {len(rf)}")
    ok = bad = 0
    shown = 0
    for h, cid, pl in rf:
        if len(pl) < 4:
            continue
        addr, ctrl = pl[0], pl[1]
        ea = addr & 1
        cr = (addr >> 1) & 1
        dlci = addr >> 2
        l0 = pl[2]
        if l0 & 1:
            ilen, hdr = l0 >> 1, 3
        else:
            ilen, hdr = struct.unpack_from("<H", pl, 2)[0] >> 1, 4
        # PF UIH may carry one credit octet outside information length.
        # Without the negotiated state this is only a structural inference.
        credit = int((ctrl & 0xEF) == 0xEF and bool(ctrl & 0x10)
                     and len(pl) == hdr + ilen + 2)
        total_ok = len(pl) == hdr + credit + ilen + 1
        scope = 2 if (ctrl & 0xEF) == 0xEF else hdr
        good = None
        if table is not None and total_ok:
            # 24A446: UIH FCS = address/control；SABM/DISC/UA/DM = address/control/length.
            # 信用字节（P/F=1）与信息字段都不进入 UIH FCS。
            good = fcs(pl[:scope], table) == pl[-1]
            ok += 1 if good else 0
            bad += 0 if good else 1
        if shown < 40:
            shown += 1
            print(f"  [{h:03x}/{cid:04x}] addr={addr:02x} EA={ea} C/R={cr} DLCI={dlci} "
                  f"ctrl={ctrl:02x} len={ilen} 总长符={total_ok} FCS(scope={'addr/ctrl' if scope == 2 else 'addr/ctrl/len'})={'OK' if good else ('BAD' if good is False else 'n/a')}"
                  f"  {pl[:min(len(pl), 24)].hex(' ')}")
    if table is not None:
        print(f"FCS 校验: OK={ok} BAD={bad}")


if __name__ == "__main__":
    main()
