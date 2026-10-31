#!/usr/bin/env python3
"""导出 Mach-O 元数据：段表、节表、加载命令、函数起点、符号表统计。

用法：
  python3 macho-meta.py <binary> <outdir>

输出（outdir 下）：
  segments.json      段/节表
  load-commands.json 加载命令摘要
  function-starts.json  LC_FUNCTION_STARTS 解出的起点
  symbols.json       符号表（地址/名字/类型）
  summary.json       汇总（大小、sha256、uuid、加密信息、计数）
"""
import hashlib
import json
import os
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_FUNCTION_STARTS = 0x26
LC_UUID = 0x1B
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_MAIN = 0x80000028
LC_DYLD_INFO_ONLY = 0x80000022
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_DYLD_EXPORTS_TRIE = 0x80000033

CMD_NAMES = {
    0x1: "LC_SEGMENT",
    0x2: "LC_SYMTAB",
    0x3: "LC_SYMSEG",
    0x4: "LC_THREAD",
    0x5: "LC_UNIXTHREAD",
    0x6: "LC_LOADFVMLIB",
    0x7: "LC_IDFVMLIB",
    0x8: "LC_IDENT",
    0x9: "LC_FVMFILE",
    0xA: "LC_PREPAGE",
    0xB: "LC_DYSYMTAB",
    0xC: "LC_LOAD_DYLIB",
    0xD: "LC_ID_DYLIB",
    0xE: "LC_LOAD_DYLINKER",
    0xF: "LC_ID_DYLINKER",
    0x10: "LC_PREBOUND_DYLIB",
    0x11: "LC_ROUTINES",
    0x12: "LC_SUB_FRAMEWORK",
    0x13: "LC_SUB_UMBRELLA",
    0x14: "LC_SUB_CLIENT",
    0x15: "LC_SUB_LIBRARY",
    0x16: "LC_TWOLEVEL_HINTS",
    0x17: "LC_PREBIND_CKSUM",
    0x18: "LC_LOAD_WEAK_DYLIB",
    0x19: "LC_SEGMENT_64",
    0x1A: "LC_ROUTINES_64",
    0x1B: "LC_UUID",
    0x1C: "LC_RPATH",
    0x1D: "LC_CODE_SIGNATURE",
    0x1E: "LC_SEGMENT_SPLIT_INFO",
    0x1F: "LC_REEXPORT_DYLIB",
    0x20: "LC_LAZY_LOAD_DYLIB",
    0x21: "LC_ENCRYPTION_INFO",
    0x22: "LC_DYLD_INFO",
    0x23: "LC_DYLD_INFO_ONLY",
    0x24: "LC_LOAD_UPWARD_DYLIB",
    0x25: "LC_VERSION_MIN_MACOSX",
    0x26: "LC_FUNCTION_STARTS",
    0x27: "LC_DYLD_ENVIRONMENT",
    0x28: "LC_MAIN",
    0x29: "LC_DATA_IN_CODE",
    0x2A: "LC_SOURCE_VERSION",
    0x2B: "LC_DYLIB_CODE_SIGN_DRS",
    0x2C: "LC_ENCRYPTION_INFO_64",
    0x2D: "LC_LINKER_OPTION",
    0x2E: "LC_LINKER_OPTIMIZATION_HINT",
    0x2F: "LC_VERSION_MIN_TVOS",
    0x30: "LC_VERSION_MIN_WATCHOS",
    0x31: "LC_NOTE",
    0x32: "LC_BUILD_VERSION",
    0x33: "LC_DYLD_EXPORTS_TRIE",
    0x34: "LC_DYLD_CHAINED_FIXUPS",
}


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def cstr(b, o):
    end = b.index(b"\0", o)
    return b[o:end].decode(errors="replace")


def main():
    path, outdir = sys.argv[1], sys.argv[2]
    blob = open(path, "rb").read()
    os.makedirs(outdir, exist_ok=True)
    if u32(blob, 0) != MH_MAGIC_64:
        raise SystemExit("不是 64 位 Mach-O")

    cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, _res = struct.unpack_from(
        "<IIIIIII", blob, 4
    )
    off = 32
    segments, sections, cmds = [], [], []
    symtab = None
    fstarts = None
    uuid = None
    enc = None
    entry = None
    for _ in range(ncmds):
        cmd, size = u32(blob, off), u32(blob, off + 4)
        name = CMD_NAMES.get(cmd, f"0x{cmd:x}")
        ent = {"cmd": name, "cmdsize": size, "offset": off}
        if cmd == LC_SEGMENT_64:
            segname = cstr(blob, off + 8)
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", blob, off + 24)
            maxprot, initprot, nsects, sflags = struct.unpack_from("<IIII", blob, off + 56)
            ent.update(
                segname=segname,
                vmaddr=vmaddr,
                vmsize=vmsize,
                fileoff=fileoff,
                filesize=filesize,
                maxprot=maxprot,
                initprot=initprot,
                nsects=nsects,
                flags=sflags,
            )
            segments.append({k: ent[k] for k in ("segname", "vmaddr", "vmsize", "fileoff", "filesize", "initprot", "nsects")})
            so = off + 72
            for _i in range(nsects):
                sname = cstr(blob, so)
                sseg = cstr(blob, so + 16)
                addr, sz = struct.unpack_from("<QQ", blob, so + 32)
                foff, align, reloff, nreloc, sflags2 = struct.unpack_from("<IIIII", blob, so + 48)
                sections.append(
                    {
                        "segment": sseg,
                        "section": sname,
                        "addr": addr,
                        "size": sz,
                        "fileoff": foff,
                        "align": align,
                        "flags": sflags2,
                    }
                )
                so += 80
        elif cmd == LC_SYMTAB:
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", blob, off + 8)
            symtab = {"symoff": symoff, "nsyms": nsyms, "stroff": stroff, "strsize": strsize}
            ent.update(symtab)
        elif cmd == LC_FUNCTION_STARTS:
            fstarts = {"dataoff": u32(blob, off + 8), "datasize": u32(blob, off + 12)}
            ent.update(fstarts)
        elif cmd == LC_UUID:
            uuid = blob[off + 8:off + 24].hex()
            u = uuid
            uuid = f"{u[0:8]}-{u[8:12]}-{u[12:16]}-{u[16:20]}-{u[20:32]}"
            ent["uuid"] = uuid
        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            cryptoff, cryptsize, cryptid = struct.unpack_from("<III", blob, off + 8)
            enc = {"cryptoff": cryptoff, "cryptsize": cryptsize, "cryptid": cryptid}
            ent.update(enc)
        elif cmd == LC_MAIN:
            entryoff, stacksize = struct.unpack_from("<QQ", blob, off + 8)
            entry = {"entryoff": entryoff, "stacksize": stacksize}
            ent.update(entry)
        cmds.append(ent)
        off += size

    funcs = []
    if fstarts:
        data = blob[fstarts["dataoff"]:fstarts["dataoff"] + fstarts["datasize"]]
        # ULEB128 增量编码，基准为 __TEXT 起址
        base = next(s["vmaddr"] for s in segments if s["segname"] == "__TEXT")
        cur = base
        i = 0
        while i < len(data):
            val = 0
            shift = 0
            while True:
                byte = data[i]
                i += 1
                val |= (byte & 0x7F) << shift
                shift += 7
                if not byte & 0x80:
                    break
            if val == 0:
                break
            cur += val
            funcs.append(cur)

    syms = []
    if symtab:
        for i in range(symtab["nsyms"]):
            e = symtab["symoff"] + i * 16
            strx, ntype, sect, desc, value = struct.unpack_from("<IBBHQ", blob, e)
            if value == 0:
                continue
            end = blob.index(b"\0", symtab["stroff"] + strx)
            nm = blob[symtab["stroff"] + strx:end].decode(errors="replace")
            syms.append({"addr": value, "name": nm, "type": ntype, "sect": sect, "desc": desc})
    syms.sort(key=lambda s: s["addr"])

    summary = {
        "path": os.path.abspath(path),
        "size": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "magic": hex(u32(blob, 0)),
        "cputype": cputype,
        "cpusubtype": cpusubtype,
        "filetype": filetype,
        "ncmds": ncmds,
        "sizeofcmds": sizeofcmds,
        "flags": hex(flags),
        "uuid": uuid,
        "encryption": enc,
        "entry": entry,
        "segment_count": len(segments),
        "section_count": len(sections),
        "function_starts": len(funcs),
        "symtab": symtab,
        "symbol_count": len(syms),
        "sect_create_date": None,
    }
    sects = [s for s in sections if s["section"] == "__text"]
    if sects:
        summary["text_section"] = sects[0]

    json.dump(summary, open(os.path.join(outdir, "summary.json"), "w"), indent=2)
    json.dump(segments, open(os.path.join(outdir, "segments.json"), "w"), indent=2)
    json.dump(sections, open(os.path.join(outdir, "sections.json"), "w"), indent=2)
    json.dump(cmds, open(os.path.join(outdir, "load-commands.json"), "w"), indent=2)
    json.dump(funcs, open(os.path.join(outdir, "function-starts.json"), "w"), indent=2)
    json.dump(syms, open(os.path.join(outdir, "symbols.json"), "w"), indent=2)
    print(json.dumps({k: summary[k] for k in ("size", "sha256", "uuid", "encryption", "function_starts", "symbol_count")}, indent=2))


if __name__ == "__main__":
    main()
