#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Query the direct-call graph built by build-callgraph.py.

Usage:
  python3 xrefs.py <callgraph.json> <symbols.json> <addr-or-symbol> [...]
  python3 xrefs.py ... --callees <addr>
  python3 xrefs.py ... --depth 2 <addr>      # BFS over callers, 2 levels

Prints "0xADDR symbol <- caller" lines.  Symbol names come from the Mach-O
symtab and are used only as labels; absence of a name means "stripped".
"""
import json
import sys


def load(path):
    return json.load(open(path, encoding="utf-8"))


def main() -> int:
    cg_path, sym_path = sys.argv[1], sys.argv[2]
    rest = sys.argv[3:]
    mode = "callers"
    depth = 1
    addrs = []
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--callees":
            mode = "callees"
        elif a == "--depth":
            i += 1
            depth = int(rest[i])
        else:
            addrs.append(a)
        i += 1

    cg = load(cg_path)
    for c in addrs:
        if c.startswith("0x"):
            start = int(c, 16)
        else:
            raise SystemExit("need a hex address: " + c)
        print("== 0x%x" % start)
        seen = {start}
        frontier = [start]
        for level in range(depth):
            nxt = []
            for a in frontier:
                key = "0x%x" % a
                if mode == "callers":
                    for src in cg["callers"].get(key, []):
                        if src in seen:
                            continue
                        seen.add(src)
                        nxt.append(int(src, 16))
                        print("  L%d caller 0x%x  <- 0x%x" % (level + 1, int(src, 16), a))
                else:
                    for t in cg["calls"].get(key, []) + cg["tails"].get(key, []):
                        if t in seen:
                            continue
                        seen.add(t)
                        nxt.append(int(t, 16))
                        print("  L%d callee 0x%x  -> 0x%x" % (level + 1, int(t, 16), a))
            frontier = nxt
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
