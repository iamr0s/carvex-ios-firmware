#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Extract the iAP2 feature-info table from accessoryd into tables.json.

The table is `__kiAP2FeatureInfoEntries` (0x10021b550).  Each entry is 16 bytes:

    +0x00  u32  feature id              (index into endpoint->featureSlots)
    +0x08  u64  pointer to info struct

and the info struct (`PTR__kiAP2FeatureInfo_*`) is:

    +0x00  u64  create function
    +0x08  u64  message-handler table pointer
    +0x10  u16  handler count
    +0x22  u8   feature id (repeated)

All reads are raw little-endian reads of the shipped image; nothing is inferred.
"""
import hashlib
import json
import struct
import sys

DOCSET = sys.argv[1] if len(sys.argv) > 1 else "research/protocol/iap2_control_session"
BIN = DOCSET + "/source/firmware/accessoryd"
BASE = 0x100000000
TABLE = 0x10021b550
COUNT = 0x1D
OUT = DOCSET + "/source/metadata/tables.json"


def main() -> int:
    blob = open(BIN, "rb").read()
    sha = hashlib.sha256(blob).hexdigest()

    def u32(addr):
        return struct.unpack_from("<I", blob, addr - BASE)[0]

    def u64(addr):
        return struct.unpack_from("<Q", blob, addr - BASE)[0]

    def u16(addr):
        return struct.unpack_from("<H", blob, addr - BASE)[0]

    def u8(addr):
        return blob[addr - BASE]

    def ptr(raw):
        return BASE + (raw & 0xFFFFFFFFFF)

    rows = []
    for i in range(COUNT):
        ent = TABLE + i * 16
        fid = u32(ent)
        info_raw = u64(ent + 8)
        if info_raw == 0:
            rows.append({"index": i, "feature_id": fid, "info": None})
            continue
        info = ptr(info_raw)
        create = ptr(u64(info))
        htab_raw = u64(info + 8)
        hcount = u16(info + 0x10)
        idbyte = u8(info + 0x22)
        rows.append({
            "index": i,
            "feature_id": fid,
            "info": "0x%x" % info,
            "create": "0x%x" % create if create != BASE else None,
            "handler_table": "0x%x" % ptr(htab_raw) if htab_raw else None,
            "handler_count": hcount,
            "id_byte": idbyte,
        })

    out = {
        "image": "accessoryd",
        "source_sha256": sha,
        "pointer_rule": "target = 0x100000000 + (value & 0xFFFFFFFFFF)",
        "feature_info_table": {
            "symbol": "__kiAP2FeatureInfoEntries",
            "address": "0x10021b550",
            "entry_size": 16,
            "count": COUNT,
            "entries": rows,
        },
    }
    json.dump(out, open(OUT, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print("wrote", OUT, "entries", len(rows))
    named = [r for r in rows if r.get("handler_table")]
    print("with handler table:", len(named), "total handlers:",
          sum(r["handler_count"] for r in named))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
