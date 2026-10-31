import struct

BIN = "/tmp/mtb/MediaToolbox"
blob = open(BIN, "rb").read()

for name in (b"SubSU", b"BePxT", b"AfPxT", b"BefEn", b"EmEnc"):
    idx = blob.find(name)
    print(name.decode(), "first occurrence file offset", hex(idx) if idx >= 0 else "none")

# 字符串所在的 vaddr（假设 __TEXT 起始 0x196990000 ↔ file 0）
BASE = 0x196990000
target = BASE + blob.find(b"BePxT")
print("BePxT vaddr", hex(target))
packed = struct.pack("<Q", target)
hits = []
pos = 0
while True:
    pos = blob.find(packed, pos)
    if pos < 0:
        break
    hits.append(pos)
    pos += 1
print("pointer-sized references to BePxT:", len(hits), [hex(h) for h in hits[:10]])
