#!/usr/bin/env python3
"""Select original functions from a thin arm64e Mach-O and produce:
   - source/asm/<binary>/f_<addr>.s   (original bytes + Capstone disassembly)
   - source/asm/<binary>/f_<addr>.bin (original function bytes, untouched)
   - a Ghidra request file for CachePhoneFunctions.java

Function boundaries come from LC_FUNCTION_STARTS only. Nothing is invented.
"""
import argparse, bisect, hashlib, json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ipsw-research'))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from firmware_image import Image


def sha_bytes(b):
    return hashlib.sha256(b).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', required=True)
    ap.add_argument('--selection', required=True, help='json: {group: [{address, why}]}')
    ap.add_argument('--asm-out', required=True)
    ap.add_argument('--request-out', required=True)
    ap.add_argument('--source-kind', default='NATIVE_MACHO')
    a = ap.parse_args()

    src = Path(a.binary)
    data = src.read_bytes()
    digest = sha_bytes(data)
    im = Image(src)
    text_start, text_len, _ = im.sections[('__TEXT', '__text')]
    text_end = text_start + text_len
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True

    asm_dir = Path(a.asm_out)
    asm_dir.mkdir(parents=True, exist_ok=True)
    selection = json.loads(Path(a.selection).read_text())
    rows, functions, seen = [], [], {}
    for group, items in selection.items():
        for item in items:
            at = int(item['address'], 0)
            if at not in im.starts:
                raise SystemExit(f'NOT A FUNCTION START: {item["address"]}')
            idx = bisect.bisect_right(im.starts, at)
            end = min(im.starts[idx], text_end) if idx < len(im.starts) else text_end
            raw = im.read(at, end - at)
            stem = asm_dir / f'f_{at:x}'
            asm_lines = [
                f'; {src.name} {at:#x}..{end:#x}; source SHA256 {digest}; original firmware bytes',
                '; disassembly: Capstone 5.0.7 (ARM64, little endian, skipdata); no rewriting',
            ]
            for ins in md.disasm(raw, at):
                asm_lines.append(f'{ins.address:#x}: {ins.bytes.hex()} {ins.mnemonic} {ins.op_str}')
            asm = '\n'.join(asm_lines) + '\n'
            (stem.with_suffix('.bin')).write_bytes(raw)
            (stem.with_suffix('.s')).write_text(asm)
            if at in seen:
                seen[at]['groups'].append(group)
                continue
            entry = {'address': hex(at), 'end': hex(end), 'size': end - at,
                     'raw_sha256': sha_bytes(raw), 'assembly_sha256': sha_bytes(asm.encode()),
                     'groups': [group], 'why': [item.get('why', '')]}
            seen[at] = entry
            functions.append(entry)
    functions.sort(key=lambda r: int(r['address'], 0))
    for f in functions:
        rows.append({k: f[k] for k in ('address', 'end', 'size', 'raw_sha256', 'assembly_sha256')}
                    | {'groups': f['groups'], 'why': f['why']})
    index = {'binary': src.name, 'source_sha256': digest, 'source_kind': a.source_kind,
             'function_boundaries': 'LC_FUNCTION_STARTS', 'count': len(functions),
             'functions': rows}
    (asm_dir / 'index.json').write_text(json.dumps(index, ensure_ascii=False, indent=2) + '\n')
    request = {'source': src.name, 'source_sha256': digest, 'source_kind': a.source_kind,
               'timeout_seconds': 90,
               'functions': [{k: f[k] for k in ('address', 'end', 'raw_sha256')} for f in functions]}
    Path(a.request_out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.request_out).write_text(json.dumps(request, ensure_ascii=False, indent=2) + '\n')
    print(f'{src.name}: {len(functions)} functions, {len(rows)} selected rows')


if __name__ == '__main__':
    main()
