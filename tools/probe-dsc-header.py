import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DSC = ROOT / "firmware/extracted/24A446/dyld/dyld_shared_cache_arm64e"
size = 0
with open(DSC, "rb") as h:
    h.seek(0, 2)
    size = h.tell()
    h.seek(0)
    head = h.read(0x200)

print("file size", hex(size), "magic", hex(struct.unpack_from("<I", head, 0)[0]))
for off in range(0x40, 0x180, 4):
    val = struct.unpack_from("<Q", head, off)[0]
    cnt = struct.unpack_from("<Q", head, off + 8)[0]
    if 0 < val < size and 0 < cnt < 20000 and val + 32 * cnt <= size and val % 8 == 0:
        print(f"candidate off=0x{off:x} imagesTextOffset=0x{val:x} count={cnt}")
