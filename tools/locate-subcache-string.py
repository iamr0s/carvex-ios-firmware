import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DSC = ROOT / "firmware/extracted/24A446/dyld/dyld_shared_cache_arm64e"
SUBCACHE = ROOT / "firmware/extracted/24A446/dyld/dyld_shared_cache_arm64e.05"
SUBCACHE_ADDR = 0x190400000   # ipsw dyld info: .05 __TEXT 映射
SUBCACHE_FILE_OFF = 0x0
NEEDLE = b"SubSU"


def load_images():
    with open(DSC, "rb") as handle:
        head = handle.read(0x100)
        off = struct.unpack_from("<Q", head, 0x88)[0]
        count = struct.unpack_from("<Q", head, 0x90)[0]
        handle.seek(off)
        table = handle.read(32 * count)
        rows = [struct.unpack_from("<16sQII", table, i * 32) for i in range(count)]
        paths = {}
        for _, _, _, path_off in rows:
            if path_off in paths:
                continue
            handle.seek(path_off)
            buf = bytearray()
            while True:
                ch = handle.read(1)
                if not ch or ch == b"\x00":
                    break
                buf += ch
            paths[path_off] = buf.decode("utf-8", "replace")
    return sorted((addr, size, paths[p]) for _, addr, size, p in rows)


def main() -> None:
    images = load_images()
    with open(SUBCACHE, "rb") as handle:
        blob = handle.read()
    pos = blob.find(NEEDLE)
    if pos < 0:
        raise SystemExit("needle not found in subcache")
    while pos >= 0 and pos < len(blob):
        vaddr = SUBCACHE_ADDR + (pos - SUBCACHE_FILE_OFF)
        hit = next(((a, s, p) for a, s, p in images if a <= vaddr < a + s), None)
        print(f"offset 0x{pos:x} -> vaddr 0x{vaddr:x} -> {hit[2] if hit else 'UNMAPPED'}")
        pos = blob.find(NEEDLE, pos + 1)
        if pos > len(blob):
            break


if __name__ == "__main__":
    main()
