import lzfse

path = "/mnt/d/carplay-host/sysdiagnose_2026.10.16_22-11-51+0800_iPhone-OS_iPhone_23G90/system_logs.logarchive/Special/0000000000008fbb.tracev3"
d = open(path, "rb").read()
print("size", len(d), "bvx2 count", d.count(b"bvx2"), "bom count", d.count(b"bom"))
i = d.find(b"bvx2")
print("first bvx2", i)
if i >= 0:
    try:
        out = lzfse.decompress(d[i:])
        print("decompressed", len(out))
        for k in (b"timestampInfo", b"APSenderSession", b"SETUP"):
            print(k, k in out)
    except Exception as exc:
        print("decompress failed", type(exc).__name__, exc)
print("head", d[:16].hex())
