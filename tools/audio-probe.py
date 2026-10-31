"""24A446 dyld shared cache probe: images / string scan / disasm / cfstrings."""
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

REPO = Path(__file__).resolve().parents[2]
DSC_DIR = REPO / "firmware/extracted/24A446/dyld"


class Cache:
    def __init__(self, folder: Path):
        self.maps = []
        self.files = {}
        self.slide = []
        self.images = []
        for path in sorted(folder.glob("dyld_shared_cache_arm64e*")):
            f = path.open("rb")
            h = f.read(512)
            if not h.startswith(b"dyld_v"):
                f.close()
                continue
            self.files[path] = f
            off, count = struct.unpack_from("<II", h, 16)
            f.seek(off)
            for _ in range(count):
                a, size, fo, _, _ = struct.unpack("<QQQII", f.read(32))
                self.maps.append((a, a + size, fo, path))
            off, count = struct.unpack_from("<II", h, 0x138)
            if off and count < 100:
                f.seek(off)
                entries = [struct.unpack("<QQQQQQII", f.read(56)) for _ in range(count)]
                for a, size, fo, slide_off, slide_size, flags, _mp, _ip in entries:
                    if slide_size:
                        f.seek(slide_off)
                        data = f.read(24)
                        version, _page, _cnt = struct.unpack_from("<III", data)
                        if version == 5:
                            self.slide.append((a, a + size, struct.unpack_from("<Q", data, 16)[0]))
            if path.name == "dyld_shared_cache_arm64e":
                text_off, text_cnt = struct.unpack_from("<QQ", h, 0x88)
                f.seek(text_off)
                for _ in range(text_cnt):
                    uuid, addr, size, path_off = struct.unpack("<16sQII", f.read(32))
                    self.images.append([addr, size, path_off])
                for entry in self.images:
                    f.seek(entry[2])
                    buf = bytearray()
                    while True:
                        ch = f.read(1)
                        if not ch or ch == b"\x00":
                            break
                        buf += ch
                    entry[2] = buf.decode("utf-8", "replace")
        self.images.sort()
        self.base = min(m[0] for m in self.maps)

    def read(self, addr: int, n: int) -> bytes:
        for a, b, fo, path in self.maps:
            if a <= addr and addr + n <= b:
                f = self.files[path]
                f.seek(fo + addr - a)
                return f.read(n)
        raise ValueError(f"unmapped {addr:#x}+{n}")

    def ptr(self, slot: int) -> int:
        raw = struct.unpack("<Q", self.read(slot, 8))[0]
        for a, b, base in self.slide:
            if a <= slot < b:
                target = base + (raw & ((1 << 34) - 1))
                if not raw >> 63:
                    target |= ((raw >> 34) & 255) << 56
                return target
        return raw

    def cstr(self, addr: int) -> str:
        out = bytearray()
        while len(out) < 4096:
            ch = self.read(addr + len(out), 1)
            if ch == b"\x00":
                break
            out += ch
        return out.decode("utf-8", "replace")

    def cfstr(self, addr: int) -> str:
        length = struct.unpack("<Q", self.read(addr + 24, 8))[0]
        if not 0 < length < 4096:
            raise ValueError("not CFString")
        return self.read(self.ptr(addr + 16), length).decode("utf-8", "replace")


def main() -> None:
    cache = Cache(DSC_DIR)
    cmd = sys.argv[1]

    if cmd == "images":
        pat = sys.argv[2] if len(sys.argv) > 2 else ""
        for addr, size, path in cache.images:
            if pat.lower() in path.lower():
                print(f"{addr:#x} +{size:#x}  {path}")

    elif cmd == "scanstr":
        start, end, pat = int(sys.argv[2], 16), int(sys.argv[3], 16), sys.argv[4]
        chunk = 1 << 20
        needle = pat.encode()
        addr = start
        seen = set()
        while addr < end:
            n = min(chunk, end - addr)
            block = cache.read(addr, n)
            pos = block.find(needle)
            while pos != -1:
                lo = pos
                while lo > 0 and 32 <= block[lo - 1] < 127:
                    lo -= 1
                hi = pos
                while hi < len(block) and 32 <= block[hi] < 127:
                    hi += 1
                text = block[lo:hi].decode()
                if (addr + lo, text) not in seen:
                    seen.add((addr + lo, text))
                    print(f"{addr + lo:#x}  {text}")
                pos = block.find(needle, hi)
            addr += n

    elif cmd == "hex":
        addr = int(sys.argv[2], 16)
        n = int(sys.argv[3], 0) if len(sys.argv) > 3 else 16
        print(cache.read(addr, n).hex(" "))

    elif cmd == "dis":
        addr = int(sys.argv[2], 16)
        n = int(sys.argv[3], 0) if len(sys.argv) > 3 else 12
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        for i in md.disasm(cache.read(addr, n * 4), addr):
            print(f"{i.address:#x}: {i.mnemonic:8s} {i.op_str}")

    elif cmd == "cf":
        print(repr(cache.cfstr(int(sys.argv[2], 16))))

    elif cmd == "findptr":
        # 找 8 字节链式指针指向 target 的槽位
        start, end, target = int(sys.argv[2], 16), int(sys.argv[3], 16), int(sys.argv[4], 16)
        chunk = 1 << 20
        hit = 0
        for base_addr, base_b, base_slide in cache.slide:
            lo = max(start, base_addr)
            hi = min(end, base_b)
            addr = lo
            while addr < hi:
                n = min(chunk, hi - addr)
                try:
                    block = cache.read(addr, n)
                except ValueError:
                    addr += n
                    continue
                view = memoryview(block)
                for off in range(0, n - 7, 8):
                    raw = int.from_bytes(view[off:off + 8], "little")
                    if not raw >> 63:
                        continue
                    cand = base_slide + (raw & ((1 << 34) - 1))
                    if cand == target:
                        print(f"{addr + off:#x} -> {cand:#x}")
                        hit += 1
                addr += n
        print(f"hits={hit}")

    elif cmd == "adrp":
        # 找把某页装进寄存器的 ADRP（用于定位字符串簇的引用点）
        start, end, page = int(sys.argv[2], 16), int(sys.argv[3], 16), int(sys.argv[4], 16)
        block = cache.read(start, end - start)
        for off in range(0, len(block) - 3, 4):
            ins = int.from_bytes(block[off:off + 4], "little")
            if ins & 0x9F000000 != 0x90000000:
                continue
            immlo = (ins >> 29) & 3
            immhi = (ins >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & (1 << 20):
                imm -= 1 << 21
            va = start + off
            if (va & ~0xFFF) + (imm << 12) == page:
                rd = ins & 0x1F
                print(f"{va:#x}  adrp x{rd}, {page:#x}")

    elif cmd == "table":
        addr = int(sys.argv[2], 16)
        n = int(sys.argv[3], 0) if len(sys.argv) > 3 else 16
        for i in range(n):
            slot = addr + i * 8
            try:
                p = cache.ptr(slot)
            except ValueError:
                break
            try:
                s = cache.cstr(p)
                ok = all(32 <= ord(c) < 127 for c in s) and s
            except ValueError:
                ok = False
            print(f"[{i:2d}] {p:#x}  {repr(s) if ok else '<non-string>'}")

    elif cmd == "strings":
        start, end = int(sys.argv[2], 16), int(sys.argv[3], 16)
        minlen = int(sys.argv[4]) if len(sys.argv) > 4 else 4
        block = cache.read(start, end - start)
        i = 0
        while i < len(block):
            if 32 <= block[i] < 127:
                j = i
                while j < len(block) and 32 <= block[j] < 127:
                    j += 1
                if j - i >= minlen:
                    print(f"{start + i:#x}  {block[i:j].decode()}")
                i = j
            else:
                i += 1

    elif cmd == "refs":
        # 找 adrp+add 解析到目标地址的代码点（字符串/数据 xref）
        start, end, target = int(sys.argv[2], 16), int(sys.argv[3], 16), int(sys.argv[4], 16)
        block = cache.read(start, end - start)
        words = [int.from_bytes(block[i:i + 4], "little") for i in range(0, len(block) - 3, 4)]
        for idx, ins in enumerate(words):
            if ins & 0x9F000000 != 0x90000000:
                continue
            va = start + idx * 4
            immlo = (ins >> 29) & 3
            immhi = (ins >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & (1 << 20):
                imm -= 1 << 21
            page = (va & ~0xFFF) + (imm << 12)
            if target - page >= 0x1000:
                continue
            rd = ins & 0x1F
            for k in range(1, 5):
                if idx + k >= len(words):
                    break
                nx = words[idx + k]
                if nx & 0xFFC00000 == 0x91000000:  # ADD (immediate, 64-bit)
                    rn = (nx >> 5) & 0x1F
                    imm12 = (nx >> 10) & 0xFFF
                    shift = (nx >> 22) & 3
                    off = imm12 << (12 if shift == 1 else 0)
                    if rn == rd and page + off == target:
                        print(f"{va:#x}  (add at {va + k * 4:#x})")

    elif cmd == "calls":
        start, end, target = int(sys.argv[2], 16), int(sys.argv[3], 16), int(sys.argv[4], 16)
        block = cache.read(start, end - start)
        for off in range(0, len(block) - 3, 4):
            ins = int.from_bytes(block[off:off + 4], "little")
            if ins & 0xFC000000 != 0x94000000:  # BL
                continue
            imm = ins & 0x3FFFFFF
            if imm & (1 << 25):
                imm -= 1 << 26
            va = start + off
            if va + imm * 4 == target:
                print(f"{va:#x}  bl {target:#x}")

    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
