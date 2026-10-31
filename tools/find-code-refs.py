#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Find code references (adrp+add / adrp+ldr) to given target addresses.

Usage: python3 _xref.py <macho> <hexaddr> [<hexaddr> ...]
"""
import json
import re
import subprocess
import sys
import tempfile
import os

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

BIN = sys.argv[1]
TARGETS = {int(a, 16) for a in sys.argv[2:]}

meta = tempfile.mkdtemp()
r = subprocess.run([sys.executable, "firmware/tools/macho-meta.py", BIN, meta],
                   capture_output=True, text=True)
if r.returncode != 0:
    print("meta failed", (r.stderr or r.stdout)[-300:])
    raise SystemExit(1)
secs = json.load(open(os.path.join(meta, "sections.json"), encoding="utf-8"))
text = [s for s in secs if s["section"] == "__text"][0]
data = open(BIN, "rb").read()[text["fileoff"]:text["fileoff"] + text["size"]]
base = text["addr"]

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
pages = {}
hits = {}
ADRP = re.compile(r"^(x\d+), #(0x[0-9a-f]+)$")
ADD = re.compile(r"^(x\d+), (x\d+), #(0x[0-9a-f]+)$")
LDR = re.compile(r"^(x\d+), \[(x\d+), #(0x[0-9a-f]+)\]$")

for ins in md.disasm(data, base):
    m = ins.mnemonic
    if m == "adrp":
        g = ADRP.match(ins.op_str)
        if g:
            pages[g.group(1)] = int(g.group(2), 16)
        continue
    if m not in ("add", "ldr"):
        continue
    g = (ADD if m == "add" else LDR).match(ins.op_str)
    if not g:
        continue
    dst, src, imm = g.group(1), g.group(2), int(g.group(3), 16)
    if src not in pages:
        continue
    tgt = pages[src] + imm
    if tgt in TARGETS:
        hits.setdefault(tgt, []).append(ins.address)

for t in sorted(TARGETS):
    refs = hits.get(t, [])
    print("0x%x  refs=%d  %s" % (t, len(refs), " ".join("0x%x" % a for a in refs[:12])))
