#!/usr/bin/env python3
"""List images embedded in the extracted dyld shared cache (read-only)."""
import struct, sys, json
from pathlib import Path
REPO = Path(__file__).resolve().parents[3]
DSC = REPO / "firmware/extracted/24A446/dyld/dyld_shared_cache_arm64e"
def images():
    with open(DSC, "rb") as f:
        head = f.read(0x200)
        if struct.unpack_from("<I", head, 0)[0] != 0x646C7964:
            raise SystemExit("not dyld cache")
        off = struct.unpack_from("<Q", head, 0x88)[0]
        count = struct.unpack_from("<Q", head, 0x90)[0]
        f.seek(off); table = f.read(32 * count)
        rows = []
        for i in range(count):
            uuid, addr, size, path_off = struct.unpack_from("<16sQII", table, i * 32)
            rows.append((addr, size, path_off))
        rows.sort()
        out = []
        for addr, size, path_off in rows:
            f.seek(path_off); buf = bytearray()
            while True:
                c = f.read(1)
                if not c or c == b"\0": break
                buf += c
            out.append((addr, size, buf.decode("utf-8", "replace")))
        return out
if __name__ == "__main__":
    imgs = images()
    pat = sys.argv[1].lower() if len(sys.argv) > 1 else None
    for addr, size, path in imgs:
        if pat is None or pat in path.lower():
            print(f"0x{addr:x}\t{size}\t{path}")
    if pat is None:
        print(f"TOTAL {len(imgs)}", file=sys.stderr)
