#!/usr/bin/env python3
"""重建 manifest.json 的 files 清单（哈希），并同步运行时观测登记。

用法：python3 firmware/tools/refresh-manifest.py <docset_dir>
"""
import hashlib
import json
import os
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "research/protocol/bluetooth_rfcomm"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def order_key(p):
    # 根文件在前，其余按路径字典序
    return (0 if "/" not in p else 1, p)


def main():
    mpath = os.path.join(ROOT, "manifest.json")
    m = json.load(open(mpath, encoding="utf-8"))
    files = []
    for dp, dns, fns in os.walk(ROOT):
        dns.sort()
        for fn in sorted(fns):
            full = os.path.join(dp, fn)
            rel = os.path.relpath(full, ROOT).replace("\\", "/")
            if rel == "manifest.json":
                continue
            files.append({"path": rel, "size": os.path.getsize(full), "sha256": sha256(full)})
    files.sort(key=lambda e: order_key(e["path"]))
    m["files"] = files

    docs = m.setdefault("documents", {})
    docs["runtime"] = [
        "runtime/README.md",
        "runtime/observations/findings-sdp-hci.md",
    ]
    docs["runtime_raw"] = sorted(
        p["path"] for p in files if p["path"].startswith("runtime/observations/") and p["path"].endswith(".txt")
    )

    # OPEN 项：从文档里自动发现（id -> 出现位置），保证清单与正文一致
    import re
    found = {}
    for e in files:
        rel = e["path"]
        if not rel.endswith(".md"):
            continue
        txt = open(os.path.join(ROOT, rel), encoding="utf-8", errors="replace").read()
        for line in txt.splitlines():
            if "已关闭" in line or "~~" in line or re.search(r"已由.{0,16}关闭", line):
                continue  # 关闭项（含删除线/已由…关闭）不再计入 OPEN 清单
            for m_ in re.finditer(r"OPEN-[A-Z]+-[0-9]+[a-z]?", line):
                found.setdefault(m_.group(0), set()).add(rel)
    items = [{"id": k, "where": sorted(v)} for k, v in sorted(found.items())]
    m["open_items"] = items
    m["open_item_count"] = len(items)
    m["runtime_status"] = "first-pass-done (SDP/HCI captures of 3 non-24A446 builds; corroboration only)"

    with open(mpath, "w", encoding="utf-8") as f:
        json.dump(m, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"files={len(m['files'])} open_items={m['open_item_count']} runtime_raw={len(docs['runtime_raw'])}")


if __name__ == "__main__":
    main()
