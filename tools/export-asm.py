#!/usr/bin/env python3
"""按符号名导出指定函数的原始汇编与原始字节。

用法：
  python3 export-asm.py <binary> <metadata-dir> <selection.json> <outdir>

selection.json 形如：
  {"image": "accessoryd",
   "functions": [{"symbol": "_iAP2LinkCreate", "group": "L", "note": "..."}]}

输出：
  <outdir>/f_<addr>.s      Capstone 反汇编，头部两行固定
  <outdir>/f_<addr>.bin    原始字节（与固件该区间逐字节相同）
  <outdir>/index.json      清单
"""
import hashlib
import json
import os
import sys

import capstone

HEADER_TOOL = "Capstone 5.0.7 CS_ARCH_ARM64; no rewriting"
UNREVIEWED = "unreviewed: 未人工确认（机器输出，字节为固件原始值）"


def main():
    binary, metadir, selfile, outdir = sys.argv[1:5]
    blob = open(binary, "rb").read()
    sha = hashlib.sha256(blob).hexdigest()
    symbols = json.load(open(os.path.join(metadir, "symbols.json"), encoding="utf-8"))
    starts = json.load(open(os.path.join(metadir, "function-starts.json"), encoding="utf-8"))
    sel = json.load(open(selfile, encoding="utf-8"))
    image = sel["image"]
    os.makedirs(outdir, exist_ok=True)

    text_seg = None
    for s in json.load(open(os.path.join(metadir, "segments.json"), encoding="utf-8")):
        if s["segname"] == "__TEXT":
            text_seg = s
    base = text_seg["vmaddr"]
    starts_sorted = sorted(set(starts))

    byname = {}
    for s in symbols:
        byname.setdefault(s["name"], []).append(s["addr"])

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.skipdata = True

    index = []
    missing = []
    used = set()
    for item in sel["functions"]:
        sym = item.get("symbol") or ""
        if item.get("address"):
            # 允许按地址选函数（符号被剥掉时）；symbol 仅作标签
            addrs = [int(item["address"], 16)]
            sym = sym or "(unnamed)"
        else:
            looks = [sym, "_" + sym, "__" + sym]
            addrs = None
            for cand in looks:
                if byname.get(cand):
                    addrs = byname[cand]
                    sym = cand
                    break
        if not addrs:
            missing.append(item["symbol"])
            continue
        start = addrs[0]
        if start in used:
            print("skip duplicate address", hex(start))
            continue
        used.add(start)
        nxt = [a for a in starts_sorted if a > start]
        if nxt:
            end = nxt[0]
        else:
            nxtsym = [s["addr"] for s in symbols if s["addr"] > start]
            end = min(nxtsym) if nxtsym else start + 4
        if end <= start:
            end = start + 4
        size = end - start
        off = start - base
        raw = blob[off:off + size]
        if len(raw) != size:
            raise SystemExit(f"{sym} 超出文件范围")
        common = f"0x{start:x}-0x{end:x}"
        s_path = os.path.join(outdir, f"f_{start:x}.s")
        with open(s_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(f"; {image} {common}; source SHA256 {sha}; original firmware bytes\n")
            fh.write(f"; disassembly: {HEADER_TOOL}\n")
            fh.write(f"; {UNREVIEWED}\n")
            for ins in md.disasm(raw, start):
                fh.write(f"0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}\n")
        with open(os.path.join(outdir, f"f_{start:x}.bin"), "wb") as fh:
            fh.write(raw)
        index.append(
            {
                "symbol": sym,
                "address": f"0x{start:x}",
                "end": f"0x{end:x}",
                "size": size,
                "group": item.get("group", ""),
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
                "bin": f"f_{start:x}.bin",
                "asm": f"f_{start:x}.s",
            }
        )
    json.dump(
        {
            "image": image,
            "source_sha256": sha,
            "source_size": len(blob),
            "address_rule": "end = 下一个 LC_FUNCTION_STARTS 起点（末函数回退到下一个符号地址）",
            "tool": HEADER_TOOL,
            "count": len(index),
            "functions": index,
            "missing_symbols": missing,
        },
        open(os.path.join(outdir, "index.json"), "w"),
        indent=1,
    )
    print(f"exported {len(index)} functions, missing {len(missing)}")
    for m in missing:
        print("  MISSING", m)


if __name__ == "__main__":
    main()
