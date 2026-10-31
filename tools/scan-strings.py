#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scan __cstring/__oslogstring/__objc_methname of a Mach-O for regexes."""
import json
import os
import re
import subprocess
import sys
import tempfile

BIN = sys.argv[1]
PATTERNS = [re.compile(p, re.I) for p in sys.argv[2:]]

meta = tempfile.mkdtemp()
out = subprocess.run([sys.executable, "firmware/tools/macho-meta.py", BIN, meta],
                     capture_output=True, text=True)
if out.returncode != 0:
    print("meta failed", (out.stderr or out.stdout)[-400:])
    raise SystemExit(1)
secs = json.load(open(os.path.join(meta, "sections.json"), encoding="utf-8"))
data = open(BIN, "rb").read()
seen = set()
n = 0
for s in secs:
    if s["section"] not in ("__cstring", "__oslogstring", "__objc_methname"):
        continue
    blob = data[s["fileoff"]:s["fileoff"] + s["size"]]
    for m in re.finditer(rb"[\x20-\x7e]{3,}\x00", blob):
        t = m.group(0)[:-1].decode("ascii")
        if any(p.search(t) for p in PATTERNS) and t not in seen:
            seen.add(t)
            print(hex(s["addr"] + m.start()), t)
            n += 1
print("### hits", n)
