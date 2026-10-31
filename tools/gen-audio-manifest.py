#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build manifest.json for the airplay_audio_mic_channel docset.

用法： python3 firmware/tools/gen-audio-manifest.py research/protocol/airplay_audio_mic_channel
"""
import hashlib
import json
import os
import re
import sys


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    root = (sys.argv[1] if len(sys.argv) > 1
            else "research/protocol/airplay_audio_mic_channel")
    files = []
    for base, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if not d.startswith(".git") and d != "__pycache__"]
        for n in sorted(names):
            p = os.path.join(base, n)
            rel = os.path.relpath(p, root).replace("\\", "/")
            if rel == "manifest.json":
                continue
            files.append({"path": rel, "size": os.path.getsize(p), "sha256": sha256(p)})
    files.sort(key=lambda x: x["path"])

    rules = set()
    for item in files:
        if not item["path"].startswith("spec/") or not item["path"].endswith(".md"):
            continue
        with open(os.path.join(root, item["path"]), encoding="utf-8") as f:
            rules.update(re.findall(r"^#### (R-[0-9]+\.[0-9]+) ", f.read(), re.M))

    registry = {}
    with open(os.path.join(root, "spec/10-open-items.md"), encoding="utf-8") as f:
        for line in f:
            m = re.match(r"^\| *`?(OPEN-[A-Z]+-[0-9]+)`? *\|", line)
            if m:
                registry[m.group(1)] = item_path = "spec/10-open-items.md"

    manifest = {
        "docset": os.path.basename(os.path.abspath(root)),
        "build": "24A446",
        "device": "iPhone18,1",
        "scope": "AirPlay audio / microphone channel",
        "source_images": [
            "dyld_shared_cache_arm64e (AirPlaySender @0x2519xxxxx, APTransport @0x24fdxxxxx)",
            "accessoryd (iAP2 side, only for boundary references)",
        ],
        "counts": {
            "files": len(files),
            "analysis_docs": sum(1 for f in files if f["path"].startswith("analysis/")),
            "spec_docs": sum(1 for f in files if f["path"].startswith("spec/")),
            "rules": len(rules),
            "refimpl_files": sum(1 for f in files if f["path"].startswith("reference-impl/")),
            "vectors": None,
        },
        "open_items": registry,
        "open_item_count": len(registry),
        "files": files,
    }

    vectors = os.path.join(root, "reference-impl/test_vectors.json")
    if os.path.exists(vectors):
        with open(vectors, encoding="utf-8") as f:
            manifest["counts"]["vectors"] = len(json.load(f).get("cases", []))

    path = os.path.join(root, "manifest.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1, ensure_ascii=False)
        f.write("\n")
    print(f"wrote {path} files={len(files)} rules={len(rules)} open={len(registry)} "
          f"vectors={manifest['counts']['vectors']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
