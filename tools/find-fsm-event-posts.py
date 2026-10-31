#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scan accessoryd for call sites of iAP2FSMHandleEvent and decode the event id.

For every `bl` whose target is the FSM dispatcher, walk backwards a few
instructions looking for the `mov w1, #imm` / `movz w1, #imm` that supplies the
event id. Output one TSV row per call site:

    call_site   event   caller_symbol   caller_addr

This answers "who posts which FSM event" (OPEN-FSM-3), which is what a client
implementation needs in order to reproduce the startup transcript.
"""
import bisect
import json
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG

FSM = 0x10000639C


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    fw = open(root + "/source/firmware/accessoryd", "rb").read()
    segs = json.load(open(root + "/source/metadata/segments.json", encoding="utf-8"))
    sy = json.load(open(root + "/source/metadata/symbols.json", encoding="utf-8"))
    fs = json.load(open(root + "/source/metadata/function-starts.json", encoding="utf-8"))

    text = next(s for s in segs if s["segname"] == "__TEXT")
    base, size, off = text["vmaddr"], text["filesize"], text["fileoff"]
    blob = fw[off:off + size]

    names = {}
    for s in sy:
        if s["name"].startswith("_") and s["addr"] not in names:
            names[s["addr"]] = s["name"]

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    md.skipdata = True
    insns = {}          # addr -> (mnemonic, ops string, w1_imm or None)
    calls = []          # (addr, target)
    for ins in md.disasm(blob, base):
        imm = None
        if ins.mnemonic in ("mov", "movz", "orr") and len(ins.operands) == 2:
            if ins.operands[0].type == ARM64_OP_REG and ins.reg_name(ins.operands[0].reg) == "w1":
                if ins.operands[1].type == ARM64_OP_IMM:
                    imm = ins.operands[1].imm
        key = ins.address - base
        insns[ins.address] = (ins.mnemonic, ins.op_str, imm)
        if ins.mnemonic in ("bl", "b") and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
            if ins.operands[0].imm == FSM:
                calls.append(ins.address)

    rows = []
    for site in calls:
        ev = None
        for back in range(1, 12):
            prev = insns.get(site - 4 * back)
            if prev is None:
                continue
            mnem, ops, imm = prev
            if imm is not None:
                ev = imm
                break
            if mnem.startswith("b") or mnem in ("ret",):
                break
        i = bisect.bisect_right(fs, site) - 1
        caller = fs[i] if i >= 0 else 0
        rows.append((site, ev, names.get(caller, "<unnamed>"), caller))

    print("call_site\tevent\tcaller_symbol\tcaller_addr")
    for site, ev, name, caller in rows:
        print("0x%x\t%s\t%s\t0x%x" % (site, ("0x%02x" % ev) if ev is not None else "-", name, caller))
    print("# %d call sites, %d with decoded event, %d instructions" % (len(rows), sum(1 for r in rows if r[1] is not None), len(insns)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
