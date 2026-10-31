#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run every docset verifier and classify dependency failures separately from content failures.

Usage:
  python3 firmware/tools/verify-all.py
  python3 firmware/tools/verify-all.py --only iap2_link_establish iap2_control_session
  python3 firmware/tools/verify-all.py --json out.json

Exit code:
  0  all discovered verifiers passed (or were skipped for a missing dependency)
  1  at least one verifier failed for a non-dependency reason
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "research" / "protocol"
DEP_PAT = re.compile(
    r"ModuleNotFoundError: No module named ['\"]([^'\"]+)['\"]|"
    r"No module named ['\"]([^'\"]+)['\"]|"
    r"ImportError: Failed to load the (Unicorn) dynamic library|"
    r"cannot import name ['\"]([^'\"]+)['\"]"
)
DEPS = {"capstone", "unicorn", "lzfse", "Crypto", "cryptography"}


def discover(only: list[str]) -> list[Path]:
    found = sorted(p for p in DOCS.glob("*/verify.py") if p.is_file())
    if only:
        wanted = set(only)
        found = [p for p in found if p.parent.name in wanted]
    return found


def classify(text: str) -> tuple[str, str]:
    """Return (status, detail). status in PASS/SKIP/FAIL."""
    m = DEP_PAT.search(text)
    if m:
        dep = next((g for g in m.groups() if g), "unknown")
        if dep in DEPS or "Unicorn" in text:
            return "SKIP", f"missing dependency: {dep}"
    return "FAIL", "non-dependency failure"


def run_one(path: Path, timeout: int) -> dict:
    start = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, "-B", str(path)],
            cwd=str(path.parent),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        rc = proc.returncode
    except subprocess.TimeoutExpired as exc:
        out = ((exc.stdout or "") if isinstance(exc.stdout, str) else "") + "\nTIMEOUT"
        rc = 124
    elapsed = round(time.time() - start, 1)
    if rc == 0:
        status, detail = "PASS", "exit 0"
    else:
        status, detail = classify(out)
        if status == "FAIL":
            # Show the last meaningful line for a quick triage.
            lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
            detail = lines[-1][:240] if lines else f"exit {rc}"
    return {
        "docset": path.parent.name,
        "status": status,
        "detail": detail,
        "seconds": elapsed,
        "exit": rc,
        "tail": "\n".join(out.splitlines()[-8:]),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--only", nargs="*", default=[], help="docset directory names")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--json", type=Path, default=None)
    args = ap.parse_args()

    paths = discover(args.only)
    if not paths:
        print("no verifiers found", file=sys.stderr)
        return 1

    results = []
    for path in paths:
        print(f"===== {path.parent.name} =====", flush=True)
        r = run_one(path, args.timeout)
        results.append(r)
        print(f"[{r['status']}] {r['detail']} ({r['seconds']}s)", flush=True)
        if r["status"] == "FAIL":
            print(r["tail"], flush=True)

    counts = {k: sum(1 for r in results if r["status"] == k) for k in ("PASS", "SKIP", "FAIL")}
    print("\n===== summary =====")
    for r in results:
        print(f"{r['status']:4}  {r['docset']:34}  {r['detail']}")
    print(f"\nPASS={counts['PASS']} SKIP={counts['SKIP']} FAIL={counts['FAIL']}")

    if args.json:
        args.json.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"json: {args.json}")

    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
