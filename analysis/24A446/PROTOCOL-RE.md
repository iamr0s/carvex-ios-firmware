# RFCOMM / iAP2 / AirPlay 第一批逆向结果

可以从这份固件继续还原三层协议的实现。本次已经把部分机器码翻译成可编译的 C，并与原始 ARM64 指令执行结果对照；完整握手状态机和端到端互通仍未完成。

来源限定为本目录的 `iPhone18,1_27.0.1_24A446_Restore.ipsw`。下列地址均为 24A446 的静态、未加 ASLR slide 的虚拟地址。产物是根据指令语义重新编写的代码和分析记录，不是恢复出的苹果原始源码。

## 本次得到的内容

| 层 | 主要实现位置 | 已确认或还原 | 尚未闭合 |
| --- | --- | --- | --- |
| 蓝牙 RFCOMM | `bluetoothd`；上层通过 `Platform-Bluetooth`、`MobileBluetooth` | 收帧入口、按控制字节分派、两种 FCS 检查、CID 会话查找与连接入口 | SDP 服务注册与通道选择、完整建链/断链、PN/MSC、credit 和计时状态机 |
| iAP2 | `accessoryd`；客户端接口包括 `CoreAccessories`、`AccessoryiAP2Shim`、`IAP` | 两个校验和分支、SYN 字节解析、Detection 动作、SYN 语义验证入口、CarPlay 启动处理入口 | 完整 Link 状态迁移、识别/认证顺序选择、全部 CSM/TLV、承载切换与异常分支 |
| AirPlay | `AirPlaySender`、`AirPlaySupport`；密钥派生继续进入 `CoreUtils` | HK Pair Verify 选择分支、Transient Pairing 判断、派生接口调用链、控制 SETUP 和配对入口定位 | 实际选中的认证组合、完整配对字节/KDF 参数、控制加密、SETUP/RECORD、媒体及事件 |

## 可编译的 C 与验证

| 文件 | 还原范围 | 对照结果 |
| --- | --- | --- |
| [reconstructed/rfcomm_fcs.c](reconstructed/rfcomm_fcs.c) | RFCOMM FCS 生成与两种检查函数 | 原始 CRC 表 256 项一致；4,000 组 ARM64/C 对照一致 |
| [reconstructed/iap2_primitives.c](reconstructed/iap2_primitives.c) | 校验和、SYN 原始布局解析 | 244 组校验和与 125 组 SYN 对照一致 |
| [reconstructed/airplay_pairing_branches.c](reconstructed/airplay_pairing_branches.c) | 两个配对相关函数的分支决策 | 768 组分支对照一致 |

共 5,137 组局部函数对照，未发现差异。详细输入、源文件 SHA-256、覆盖范围和方法分别记录在：

- [rfcomm-fcs-verification.json](rfcomm-fcs-verification.json)
- [primitive-verification.json](primitive-verification.json)
- [airplay-branch-verification.json](airplay-branch-verification.json)

验证使用 Unicorn 执行原始 ARM64 算术和分支指令，与 GCC 编译的重建 C 比较。iAP2 校验和与 AirPlay 函数的指针认证入口/返回指令被跳过或归一化；iAP2 的诊断日志关闭。AirPlay 的外部属性查询和设置查询使用受控替身，验证的是分支组合，不包含这些外部服务或密码算法。这里没有进行 iPhone/车机实机互通测试。

## RFCOMM

这次补提取了 `bluetoothd` 和 `bluetoothuserd`，位置在 `bluetooth-components/`。`bluetoothd` 的内部符号已经被裁剪，因此使用诊断字符串、ADRP/ADD 引用和 `LC_FUNCTION_STARTS` 确定函数边界。完整证据见 [rfcomm-locations.json](rfcomm-locations.json)，反汇编在 `assembly/bluetoothd.sub_*.s`。

| 地址 | 定位依据/作用 |
| --- | --- |
| `0x1003c18a4` | 引用 `OI_Rfcomm_GetSessionByCID`；接收入口实际调用它取得会话 |
| `0x1003c2b00` | 引用 `OI_RFCOMM_Connect failed` 的连接路径候选 |
| `0x1003c59a0` | 引用 `OI_Rfcomm_ReceiveFrame invalid frame length`，并执行控制帧分类与 FCS 检查 |
| `0x1003c6ba4` | 针对三字节头部的 FCS 检查 |
| `0x1003c6be4` | UIH 路径使用的两字节头部 FCS 检查 |
| `0x1003c73f0` | 引用非法 RFCOMM command 的诊断并按内部命令值分派 |

收帧函数确认了以下行为：

1. 先按 CID 查会话；找不到会话或帧长度不超过 3 时结束处理。
2. 读取控制字节，清除 `0x10` 后分类。
3. 识别 `0x2f / 0x43 / 0x63 / 0x0f / 0xef`。这些值与 Linux 官方 RFCOMM 定义中的 SABM / DISC / UA / DM / UIH 对应。[Linux RFCOMM 定义](https://github.com/torvalds/linux/blob/master/include/net/bluetooth/rfcomm.h)
4. 控制帧的 FCS 检查使用地址、原始控制字节及长度字节；UIH 的 FCS 检查使用地址和原始控制字节。分类时清除的位仍包含在 FCS 输入中。
5. 原始检查函数返回 `0` 表示匹配，`255` 表示不匹配。

原始查表位于 `0x1009349a0`。重建代码使用等价的逐位运算，并对照了全部表项。例子 `03 3f 01` 的 FCS 为 `1c`，已与原始检查函数核对。

在上层，`Platform-Bluetooth` 的 `pluginBTDevice:btAccessoryManager:btDevice:` 通过缓存跳板调用 `MobileBluetooth::_BTAccessoryManagerPlugInDevice`。`MobileBluetooth` 还提供 `BTDeviceGetComPortForService` 和带 sandbox extension 的变体，字符串显示它们走 XPC。这些 API 入口与下层 RFCOMM 收帧实现需要通过调用关系继续连接，不能仅凭同属蓝牙就视为同一个状态机。

## iAP2

`accessoryd` 保留了大量与本任务直接相关的函数符号。原始符号、类信息和字符串在 [raw/accessoryd.txt](raw/accessoryd.txt)。

| 地址 | 函数 | 当前分析 |
| --- | --- | --- |
| `0x100008ae8` | `iAP2PacketCalcChecksum` | 已重建并对照机器码 |
| `0x100103230` | `iAP2PacketParseSYNData` | 已重建并对照机器码 |
| `0x10002fac8` | `iAP2LinkDeviceActionSendDetect` | 已反汇编；可见序号/ACK 重置、参数复制、连接回调和 Detection 回调 |
| `0x1000333f4` | `iAP2LinkValidateSynParam` | 已反汇编；含各 SYN 字段与会话参数的语义验证路径 |
| `0x10016d3ac` | `iap2_CarPlayStartSession` | 已反汇编；入口检查消息 ID `0x4301`，具体字段/方向继续追踪 |

校验和函数有两个明确分支：类型 `0` 对字节求和取负并保留低 8 位；类型 `1` 使用两个累加器、每 20 字节折叠和 16 位结果。选择哪种模式仍应追踪实际调用方。

SYN 解析器的前 10 个线上字节对应以下字段。字段名称由 `ValidateSynParam` 的字段访问及诊断文本交叉确认；多字节值按大端输入转入本机布局。

| 线上偏移 | 宽度 | 字段 |
| --- | ---: | --- |
| 0 | 1 | linkVersion |
| 1 | 1 | maxOutstandingPackets |
| 2 | 2 | maxPacketSize |
| 4 | 2 | retransmitTimeout |
| 6 | 2 | cumAckTimeout |
| 8 | 1 | maxRetransmissions |
| 9 | 1 | maxCumAck |

解析器对版本 `0`、`1`、大于 `1` 分别处理后继内容。版本 `1` 的会话描述符从偏移 10 开始，以三个线上字节为一项；其中第二字节的低 7 位和最高位被拆开存储。语义验证日志包含 `id / type / ver / unrel`。大于 `1` 的分支还读取一个前缀计数及相关字节，目前不为这部分擅自赋予协议语义名称。

重建的 `parse_syn_raw` 刻意保留了该函数的原始写入布局，便于验证；实际协议实现还需要调用方的长度前置条件和语义验证。返回成功、或仿真中进入了大于 `1` 的分支，都不表示对应版本已通过协议协商。此处的 linkVersion 也不能代替某一 control session 描述符中的 version。

## AirPlay

| 地址 | 函数 | 当前分析 |
| --- | --- | --- |
| `0x251a61618` | `apsession_requiresHKPairVerify` | 已重建选择分支并验证 |
| `0x251a6169c` | `apsession_isTransientPairingSupported` | 已重建，随上项一起验证 |
| `0x2519bd76c` | `coreUtilsPairing_DeriveKey` | 已确认跨库派生调用 |
| `0x251a9f364` | `sdpsession_sendSetup` | 已保存反汇编；具体协议分支仍需确认 |
| `0x251a59338` | `apsession_requestControlSetupWithResponse` | 已定位控制 SETUP 入口 |
| `0x251a5e858` | `apsession_ensurePaired` | 已定位配对入口 |
| `0x2519bbf24` | `apsession_setupStreamCreatingResponseInternal` | 已定位流设置实现入口 |

HK Pair Verify 选择函数先取得 CoreMedia 对象的派生存储，再读取 endpoint 的 `AccessControlType` 和私有存储偏移 `0xe0` 的字段。可确认的分支为：AccessControlType 的低 32 位等于 `1`，或该私有字段等于 `3`，或字段等于 `10` 且 transient 判断结果为零时，返回需要 HK Pair Verify。私有字段数值的枚举含义尚未确定。

Transient 判断先读取 `SupportsTransientPairing`。当私有字段为 `10` 时，它改用内部设置查询的返回值；C 重建保留了返回值截断到低 8 位的行为。

派生包装函数把私有存储 `+0x8` 的句柄及其他参数转交给 `CoreUtils::PairingSessionDeriveKey`。因此，确定具体盐、info、方向和输出长度，还要沿调用方和 CoreUtils 继续分析。仅找到包装函数不足以确定一套完整 KDF。

缓存跳板的真实目标通过原始跳转指令和 `ipsw dyld a2s` 解析确认：

- `0x25810ac50` → `0x18ee2f3ac`，`CoreMedia::_CMBaseObjectGetDerivedStorage`。
- `0x258109860` → `0x226e639bc`，`AirPlaySupport::_APSGetFBOPropertyInt64`。
- `0x258109e20` → `0x226e67f30`，`AirPlaySupport::_APSSettingsGetIntWithDefault`。
- `0x25810ba10` → `0x18be5021c`，`CoreUtils::_PairingSessionDeriveKey`。

AirPlaySender 同时容纳多类会话路径。当前不能把 `sdpsession_sendSetup` 的存在直接当成 CarPlay 必经流程，也不能把 HK Pair Verify 的选择逻辑扩展成所有 CarPlay 安全组合的统一规则。

## 继续还原的顺序

围绕手机侧 Phone HOST，下一步适合按实际可达调用链串联：RFCOMM 服务与通道 → iAP2 Detection/SYN → control session 的识别与认证分支 → 无线参数和承载切换 → AirPlay 安全协商与控制 SETUP → 媒体、事件和断开恢复。

每一步应产出调用关系、消息字段、边界条件、状态转移及抓包对应位置。不同构建的既有 sysdiagnose 可以作结构线索，但地址、枚举和运行行为需要分别核验，当前没有据此宣称 24A446 的实机互通通过。

复现对照测试（WSL 中已安装 GCC 与 python3-unicorn）：

```powershell
Set-Location D:\ios-carplay
wsl -d Ubuntu-24.04 -u root --cd /mnt/d/ios-carplay --exec python3 tools/ipsw-research/verify-reconstructed-primitives.py
wsl -d Ubuntu-24.04 -u root --cd /mnt/d/ios-carplay --exec python3 tools/ipsw-research/verify-airplay-branches.py
wsl -d Ubuntu-24.04 -u root --cd /mnt/d/ios-carplay --exec python3 tools/ipsw-research/verify-rfcomm-fcs.py
```
