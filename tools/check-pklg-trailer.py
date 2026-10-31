#!/usr/bin/env python3
"""检查 .pklg 抓包中 RFCOMM UIH 帧的末字节是否等于 FCS(地址, 控制)。

用途：按 UIH 的两字节覆盖范围验证 FCS；同一地址/控制的 FCS 不随载荷变化是正常行为。
此轻量工具只检查未分片、单字节长度的候选帧；不能替代完整状态机。
判据：对每个 UIH 帧，末字节 == CRC8([地址][控制])，且与该帧的 length/信息字段无关。

用法：
    python3 check-pklg-trailer.py <bluetoothd> <pklg> [<pklg> ...]
"""
import struct
import sys


def load_table(binary_path):
    d = open(binary_path, "rb").read()
    off = 0x9349A0  # 0x1009349a0 - 0x100000000，FCS 表
    return d[off:off + 256]


def fcs(data, table):
    c = 0xFF
    for x in data:
        c = table[c ^ x]
    return c ^ 0xFF


CTRL_NAMES = {0x2F: "SABM", 0x3F: "SABM+P/F", 0x43: "DISC", 0x63: "UA",
              0x53: "DISC+P", 0x73: "UA+F", 0x1F: "DM+F",
              0x0F: "DM", 0xEF: "UIH", 0xFF: "UIH+P/F"}
VALID_CTRL = set(CTRL_NAMES)


def frames(path):
    """产出 (地址, 控制, 信息, 尾字节)。"""
    b = open(path, "rb").read()
    off = 0
    while off + 13 <= len(b):
        ln = struct.unpack_from(">I", b, off)[0]
        if ln < 9 or off + 4 + ln > len(b):
            break
        typ = b[off + 12]
        pl = b[off + 13:off + 4 + ln]
        off += 4 + ln
        if typ not in (2, 3) or len(pl) < 5:
            continue
        hf = struct.unpack_from("<H", pl, 0)[0]
        if ((hf >> 12) & 3) not in (0, 2):      # PB=0/2 视为帧首
            continue
        dlen = struct.unpack_from("<H", pl, 2)[0]
        q = pl[4:4 + dlen]
        if len(q) < 4:
            continue
        l2len, cid = struct.unpack_from("<HH", q, 0)
        if l2len > len(q) - 4 or cid < 0x40:
            continue
        info = q[4:4 + l2len]
        if len(info) < 4 or not (info[0] & 1) or info[1] not in VALID_CTRL:
            continue
        if not (info[2] & 1):
            continue
        n = info[2] >> 1
        yield info[0], info[1], info[3:3 + n], info[3 + n:]


def main():
    table = load_table(sys.argv[1])
    fam = {}
    tails = {}
    for path in sys.argv[2:]:
        for addr, ctrl, body, tail in frames(path):
            if not tail:
                continue
            key = "UIH" if (ctrl & 0xEF) == 0xEF else "control"
            d = fam.setdefault(key, {"n": 0, "two": 0, "three": 0})
            d["n"] += 1
            if tail[-1] == fcs(bytes([addr, ctrl]), table):
                d["two"] += 1
            if tail[-1] == fcs(bytes([addr, ctrl, 2 * len(body) + 1]), table):
                d["three"] += 1
            tails.setdefault((addr, ctrl), set()).add(tail[-1])
    for key, d in sorted(fam.items()):
        n = d["n"]
        print(f"[{key}] 帧数 {n}")
        print(f"   末字节 == FCS(地址, 控制)          : {d['two']} ({d['two'] / n:.1%})")
        print(f"   末字节 == FCS(地址, 控制, 长度): {d['three']} ({d['three'] / n:.1%})")
    multi = {k: v for k, v in tails.items() if len(v) > 1}
    print(f"同一(地址,控制)出现多个末字节的组数: {len(multi)}/{len(tails)}")
    for k, v in list(multi.items())[:5]:
        print("   ", hex(k[0]), hex(k[1]), sorted(hex(x) for x in v))


if __name__ == "__main__":
    main()
