# carvex-ios-firmware

[中文](README.md) | English

This is the firmware evidence repository for the `carvex-carplay-research` workspace and
the **CarVeX** multi-protocol connectivity layer in `iamr0s/carvex-android`. It currently
covers only the sender-side behavior of **CarPlay**. It stores binaries extracted from the
iPhone IPSW, decompiled text, analysis tools and environment configuration.

## Why this exists

The era seems to open wider and close tighter at the same time. Each vendor turns its protocol into a fence and its ecosystem into a rope, claiming openness while enclosing territory; users are lifted high and then discarded when no longer useful.

We want interoperability to return to the protocol itself: not a vendor configuration table, not a lock-in to one ecosystem, but behavior derived from the protocol stack, negotiated fields and capability bits so that phones and head units can connect as broadly as possible.

> “These walls are funny. First you hate 'em, then you get used to 'em. Enough time passes, you get so you depend on them. That's institutionalized.”
>
> — Red, *The Shawshank Redemption*

## Donation

If this project has helped you, you are welcome to donate as a thank-you. Donations are optional and do not constitute any support commitment.

<p align="center">
  <img src="assets/donation/alipay.jpg" width="200" alt="Alipay">
  <img src="assets/donation/wxpay.jpg" width="200" alt="WeChat Pay">
  <img src="assets/donation/binance.jpg" width="200" alt="Binance Pay">
</p>

<p align="center">Alipay · WeChat Pay · Binance Pay</p>

## Baseline

| Field | Value |
|---|---|
| Device | iPhone 17 Pro (iPhone18,1, V53AP) |
| iOS | 27.0.1 |
| Build | 24A446 |
| IPSW file | `iPhone18,1_27.0.1_24A446_Restore.ipsw` |
| Size | 12,725,905,286 bytes |
| SHA256 | `7ee7aaa896ef257e26aa54edb2a4ac7f6f6e8e5c20279b124bee38b809c2a6a5` |

**The IPSW is not redistributed here.** Obtain the matching version through Apple's
developer downloads or a trusted IPSW index such as [ipsw.me](https://ipsw.me/)
(select iPhone18,1 / iOS 27.0.1 / 24A446), place it at
`ipsw/iPhone18,1_27.0.1_24A446_Restore.ipsw`, and verify:

```bash
sha256sum ipsw/iPhone18,1_27.0.1_24A446_Restore.ipsw
```

Source and checksum records are in `ipsw/SOURCE.md` and `ipsw/SHA256SUMS.partial`.
Apple signature/trust-chain verification has not been performed.


## Extract provenance

Every binary, component and header under `extracted/24A446/` comes from the same IPSW.
No other version or device is mixed in:

- Firmware: `iPhone18,1_27.0.1_24A446_Restore.ipsw`
- Phone model: iPhone 17 Pro (device identifier `iPhone18,1`, hardware `V53AP`)
- iOS: 27.0.1
- Build: 24A446

The `24A446` directory name is the build number.

| Path | Source | Contents |
|---|---|---|
| `extracted/24A446/binaries/` | the IPSW above | Key Mach-O files such as CarKit, AirPlaySender and accessoryd |
| `extracted/24A446/components/` | the IPSW above | Application and framework component files from the same firmware |
| `extracted/24A446/headers/` | the IPSW above | Headers reconstructed from the same binaries |
| `analysis/` | derived from the extracts above | Not the product of another firmware |

Provenance records:

- `extracted/24A446/extraction-summary.json`: `firmware`, `ios_version`, `build`, `device`, `ipsw_release`.
- `extracted/24A446/component-manifest.json`: image-to-file mapping with size and SHA256.
- `extracted/24A446/filesystem-manifest.json`: filesystem extraction inventory.

If another version or device is added later, place it in a separate directory such as
`extracted/<BUILD>_<DEVICE>/`, extend the table above, and never overwrite or mix `24A446`.

## Tracked

- `extracted/24A446/binaries/`, `components/` and `headers/`: key Mach-O files, components
  and headers extracted from the IPSW.
- Manifests, reports and extraction logs under `extracted/24A446/`.
- Top-level summaries, key JSON, assembly and focused analysis under `analysis/`.
  Per-function slice directories, Ghidra projects and caches stay local.
- Scripts, configuration and environment notes under `tools/` and `setup/`.
- `ipsw/SOURCE.md` and `ipsw/SHA256SUMS.partial`.

## Not tracked

- The raw `*.ipsw`.
- `extracted/*/images/` (decrypted/system images) and `extracted/*/dyld/` (dyld shared cache).
- `headunits/` (head-unit firmware).
- Ghidra projects/caches, tool installations, `setup/downloads/` and archives.

These are too large or belong to third-party firmware and must be obtained locally.
Extracted binaries are tracked so a full IPSW download and re-extraction is not required
for routine analysis.

## Usage

```bash
# 1. Prepare and verify the IPSW
sha256sum ipsw/iPhone18,1_27.0.1_24A446_Restore.ipsw

# 2. Install the toolchain
cd setup && sudo bash install-linux-tools.sh

# 3. Re-extract with the ipsw extract command recorded in SOURCE.md
# 4. Run the Python analysis tools in this repository
```

## Related repositories

- `iamr0s/carvex-carplay-research`: research documents, phone-side protocol research and
  connection analysis.
- `iamr0s/carvex-android`: CarVeX, the Android implementation of CarPlay.

## Boundaries

- Original firmware bytes and extracts are evidence; function names, strings and
  decompiler output under `analysis/` are indexes and cannot stand alone as protocol proof.
- Extracts are used to derive state machines and events from the protocol stack; configuration
  is runtime input and cannot replace the state machine.
- This firmware evidence applies only to the CarPlay path and must not be generalized to
  HiCar, CarLife, ICCOA or another protocol.
- Do not modify Apple firmware or head-unit firmware.
- Matching hashes prove only identical files, not a valid Apple signature or lawful source.
- This repository is not a runnable product and claims no head-unit interoperability.
