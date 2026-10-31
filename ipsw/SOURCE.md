# SOURCE — iPhone IPSW（24A446）

| 字段 | 值 |
|---|---|
| 文件 | `iPhone18,1_27.0.1_24A446_Restore.ipsw` |
| 路径 | `firmware/ipsw/iPhone18,1_27.0.1_24A446_Restore.ipsw` |
| 大小 | 12,725,905,286 字节 |
| SHA256 | `7ee7aaa896ef257e26aa54edb2a4ac7f6f6e8e5c20279b124bee38b809c2a6a5` |
| iOS 版本 | 27.0.1 |
| Build | 24A446 |
| 设备 | iPhone 17 Pro（iPhone18,1，V53AP，A19 Pro / t8150） |
| OS Type | Production |
| FileSystem DMG | `043-68786-664.dmg.aea` |
| SystemOS DMG | `043-69814-710.dmg.aea` |
| AppOS DMG | `043-69297-793.dmg` |
| 来源 | 用户提供；获取渠道未记录（待补） |
| 校验方式 | `sha256sum`；`ipsw info`（ipsw 3.1.739） |
| 签名校验 | 未执行 Apple 签名/信任链校验 |

## 关键二进制（已与现有证据比对）

| 二进制 | 路径（现有提取物） | 大小 | SHA256 | 与 docset 副本 |
|---|---|---|---|---|
| `accessoryd` | `firmware/extracted/24A446/components/24A446__iPhone18,1/root/System/Library/PrivateFrameworks/CoreAccessories.framework/Support/accessoryd` | 4,330,752 | `2b0a2010e6d2605e07d87f05659c932e03de34476a76431196a9bb58da7dc4fe` | 4/4 一致 |
| `AirPlaySender` | `firmware/extracted/24A446/binaries/AirPlaySender/AirPlaySender` | 4,397,312 | `304b8a4a688028f58fc851ec700c905a49f17132aaa9dc04acd93a8bd50cd63f` | 4/4 一致 |
| `AirPlaySupport` | `firmware/extracted/24A446/binaries/AirPlaySupport/AirPlaySupport` | 1,536,072 | `d90a26393a5f761e1a8c98ce08f2acd90b9a630c4697054d07e8b3381ebf6a15` | 1/1 一致 |
| `CarKit` | `firmware/extracted/24A446/binaries/CarKit/CarKit` | 1,091,424 | `d7a56e9b821f7cc5b6563ec239614fa37778a876fdf1403516e6cb9c458c6dbb` | 无 docset 副本 |

## 新提取

命令：

```bash
ipsw extract --files --pattern '.*accessoryd$' \
  -o firmware/ipsw/_s1 \
  firmware/ipsw/iPhone18,1_27.0.1_24A446_Restore.ipsw
```

状态：**已完成**（RC=0）。产物在 `firmware/ipsw/_s1/24A446__iPhone18,1/root/`：

| 文件 | 大小 | SHA256 |
|---|---:|---|
| `System/Library/PrivateFrameworks/CoreAccessories.framework/Support/accessoryd` | 4,330,752 | `2b0a2010e6d2605e07d87f05659c932e03de34476a76431196a9bb58da7dc4fe` |
| `usr/libexec/audioaccessoryd` | 4,082,672 | `7c8b7d036ca10680329b6a606f4076ce137788fa550ccb6929be8e091ba70b78` |
| `usr/libexec/caraccessoryd` | 1,121,168 | `cbccbf0f66d9a0433c696b586044c8fd3a5f0e0a9a0cd9bddeecec77ce1883bc` |
| `usr/libexec/dockaccessoryd` | 3,078,336 | `7c8bf21b6467b15e960d628dcd103a41359d230efa144b1d777d51d44670e71b` |

目标二进制 `CoreAccessories.framework/Support/accessoryd` 与现有副本一致；其余三个是同类 daemon，未在 docset 中使用，仅作记录。

## 备注

- `firmware/extracted/24A446/extraction-summary.json` 记录了同一源文件名与 build/device，但此前没有 IPSW 本体的哈希；本文件补上 SHA256。
- 现有提取物与 docset 副本的哈希一致，说明 4 套 docset 的 `source/firmware/accessoryd` 来自同一二进制，且与当前 IPSW 的提取物一致。
- 哈希一致只证明“文件相同”，不证明来源合法或 Apple 签名有效；签名校验待补。
