import re
import sys

paths = sys.argv[1:]
KEY = b"APSenderSession"

for path in paths:
    data = open(path, "rb").read()
    positions = [m.start() for m in re.finditer(re.escape(KEY), data)]
    print(f"=== {path}: {len(positions)} hit(s)")
    for i in positions[:6]:
        window = data[max(0, i - 400):i + 600]
        # 只保留可打印片段，长度 >= 6
        runs = re.findall(rb"[\x20-\x7e]{6,}", window)
        print(f"--- @{i}")
        for run in runs[:12]:
            print("   ", run.decode("ascii", "replace"))
