#!/usr/bin/env python3
"""Read-only literal-reference scanner for thin arm64e Mach-O images.

Finds C-string literals matching a regex set, then locates the code that loads
each literal address (ADRP+ADD / ADR / ADRP+LDR) and reports the enclosing
function start from LC_FUNCTION_STARTS. No symbol names are invented here.
"""
import argparse, bisect, hashlib, json, re, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ipsw-research'))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_OP_IMM, CS_OP_REG, CS_OP_MEM
from firmware_image import Image

STR_SECTIONS = [('__TEXT', '__cstring'), ('__TEXT', '__oslogstring'),
                ('__TEXT', '__objc_methname'), ('__TEXT', '__objc_classname'),
                ('__TEXT', '__ustring'), ('__TEXT', '__const')]


def cstrings(im, sections):
    out = []
    for key in sections:
        sec = im.sections.get(key)
        if not sec:
            continue
        addr, size, _ = sec
        try:
            blob = im.read(addr, size)
        except ValueError:
            continue
        pos = 0
        while pos < len(blob):
            end = blob.find(b'\0', pos)
            if end < 0:
                break
            raw = blob[pos:end]
            if len(raw) >= 4:
                try:
                    text = raw.decode('utf-8')
                except UnicodeDecodeError:
                    text = None
                if text is not None:
                    out.append((addr + pos, text))
            pos = end + 1
    return out


def scan(im, targets):
    """targets: dict addr -> string. Returns list of reference records."""
    text = im.sections[('__TEXT', '__text')]
    start, size, _ = text
    code = im.read(start, size)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True  # __text contains inline literal pools; do not stop there
    pages = {}
    hits = []
    for ins in md.disasm(code, start):
        m = ins.mnemonic
        if m == 'adrp':
            try:
                reg = ins.operands[0].reg
                imm = ins.operands[1].imm
            except (IndexError, AttributeError):
                continue
            pages[reg] = imm
            continue
        if m == 'add' and len(ins.operands) == 3:
            src, imm = ins.operands[1], ins.operands[2]
            if src.type == CS_OP_REG and imm.type == CS_OP_IMM and src.reg in pages:
                target = pages[src.reg] + imm.imm
                if target in targets:
                    hits.append((target, ins.address, 'ADRP_ADD'))
            continue
        if m == 'adr' and len(ins.operands) == 2:
            dst, imm = ins.operands[0], ins.operands[1]
            if imm.type == CS_OP_IMM and imm.imm in targets:
                hits.append((imm.imm, ins.address, 'ADR'))
            continue
        if m in ('ldr', 'ldrb', 'ldrh', 'ldrsw') and len(ins.operands) == 2:
            mem = ins.operands[1]
            if mem.type == CS_OP_MEM and mem.mem.base in pages:
                # Pointer slot loaded from a page we know; record only as weak.
                target = pages[mem.mem.base] + mem.mem.disp
                if target in targets:
                    hits.append((target, ins.address, 'ADRP_LDR'))
    return hits


def enclosing(starts, addr):
    i = bisect.bisect_right(starts, addr) - 1
    return starts[i] if i >= 0 else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('binary')
    ap.add_argument('--regex', required=True)
    ap.add_argument('--out')
    ap.add_argument('--max-string', type=int, default=200)
    a = ap.parse_args()
    path = Path(a.binary)
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    im = Image(path)
    rx = re.compile(a.regex, re.I)
    matched = [(addr, s) for addr, s in cstrings(im, STR_SECTIONS)
               if len(s) <= a.max_string and rx.search(s)]
    targets = {addr: s for addr, s in matched}
    hits = scan(im, targets)
    rows = []
    for str_addr, ref, kind in hits:
        fn = enclosing(im.starts, ref)
        rows.append({'string': targets[str_addr], 'string_address': hex(str_addr),
                     'reference': hex(ref), 'function_start': hex(fn) if fn else None,
                     'kind': kind})
    rows.sort(key=lambda r: (r['function_start'] or '', r['reference']))
    result = {'binary': path.name, 'sha256': digest,
              'text_section': [hex(im.sections[('__TEXT', '__text')][0]),
                               hex(im.sections[('__TEXT', '__text')][1])],
              'function_starts': len(im.starts),
              'matched_literals': len(matched), 'hits': rows}
    text = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if a.out:
        Path(a.out).write_text(text)
        print(f'{path.name}: {len(matched)} literals, {len(rows)} refs -> {a.out}')
    else:
        print(text)


if __name__ == '__main__':
    main()
