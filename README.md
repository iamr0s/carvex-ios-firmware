# carvex-ios-firmware

[中文](README.md) | [English](README.en.md)

本仓库是 `carvex-carplay-research` 工作区的固件证据仓库，服务于 `iamr0s/carvex-android`
中的 **CarVeX** 多协议互联层；当前它只覆盖 **CarPlay** 这一条协议的发送端行为。
它保存从 iPhone IPSW 提取的二进制、反编译文本、分析工具和环境配置。

## 为什么做这件事

时代仿佛越开越阔，也越收越紧。各家以协议为藩篱，以生态为绳缆，口称开放，实则圈地；用户被高高捧起，又常被用完即弃，如祭祀中的刍狗。

我们想把互通重新落回协议本身：不靠某家的配置表，不把用户拴进某个生态，而是按协议栈、协商字段和能力位，让手机与车机尽可能广泛地连接。

> “这些墙很有意思。起初你恨它，后来你习惯它；日子够久，你会发现自己离不开它。这就叫体制化。”
>
> —— 瑞德，《肖申克的救赎》

## 捐赠

如果这个项目对你有帮助，欢迎自愿捐赠以示感谢。捐赠不构成任何支持承诺。

<p align="center">
  <img src="assets/donation/alipay.jpg" width="200" alt="支付宝">
  <img src="assets/donation/wxpay.jpg" width="200" alt="微信支付">
  <img src="assets/donation/binance.jpg" width="200" alt="Binance Pay">
</p>

<p align="center">支付宝 · 微信支付 · Binance Pay</p>

## 基线

| 字段 | 值 |
|---|---|
| 设备 | iPhone 17 Pro（iPhone18,1，V53AP） |
| iOS | 27.0.1 |
| Build | 24A446 |
| IPSW 文件 | `iPhone18,1_27.0.1_24A446_Restore.ipsw` |
| 大小 | 12,725,905,286 字节 |
| SHA256 | `7ee7aaa896ef257e26aa54edb2a4ac7f6f6e8e5c20279b124bee38b809c2a6a5` |

**IPSW 不随仓库分发。** 请通过 Apple 官方开发者下载或可信 IPSW 索引获取对应版本，
例如 [ipsw.me](https://ipsw.me/)（选择 iPhone18,1 / iOS 27.0.1 / 24A446）。
获取后放到 `ipsw/iPhone18,1_27.0.1_24A446_Restore.ipsw`，并核对：

```bash
sha256sum ipsw/iPhone18,1_27.0.1_24A446_Restore.ipsw
```

来源和校验记录见 `ipsw/SOURCE.md` 与 `ipsw/SHA256SUMS.partial`。签名/Apple 信任链
校验尚未执行。


## 提取物来源

`extracted/24A446/` 下的所有二进制、组件和头文件都来自同一份 IPSW，不混入其他版本或机型：

- 固件：`iPhone18,1_27.0.1_24A446_Restore.ipsw`
- 手机型号：iPhone 17 Pro（机型标识 `iPhone18,1`，硬件 `V53AP`）
- iOS：27.0.1
- Build：24A446

目录名 `24A446` 就是 Build 号。

| 路径 | 来源 | 说明 |
|---|---|---|
| `extracted/24A446/binaries/` | 上述 IPSW | 关键 Mach-O，如 CarKit、AirPlaySender、accessoryd |
| `extracted/24A446/components/` | 上述 IPSW | 同一固件中的应用和框架组件文件 |
| `extracted/24A446/headers/` | 上述 IPSW | 从同一批二进制重建的头文件 |
| `analysis/` | 由上述提取物生成 | 不是另一份固件的产物 |

来源记录：

- `extracted/24A446/extraction-summary.json`：`firmware`、`ios_version`、`build`、`device`、`ipsw_release`。
- `extracted/24A446/component-manifest.json`：每个 image 到提取文件、大小和 SHA256 的映射。
- `extracted/24A446/filesystem-manifest.json`：文件系统提取清单。

如果以后加入其他版本或机型，必须放到 `extracted/<BUILD>_<DEVICE>/` 这类独立目录，
并在上表补充来源；不得覆盖或混用 `24A446`。

## 入库内容

- `extracted/24A446/binaries/`、`components/`、`headers/`：从 IPSW 提取的关键 Mach-O、
  组件和头文件。
- `extracted/24A446/` 下的 manifest、报告和提取日志。
- `analysis/` 顶层的汇总文本、关键 JSON、汇编结果和专项分析；按函数拆分的切片目录、Ghidra 工程和缓存保留本地。
- `tools/` 与 `setup/` 下的脚本、配置和环境说明。
- `ipsw/SOURCE.md`、`ipsw/SHA256SUMS.partial`。

## 不入库

- 原始 `*.ipsw`。
- `extracted/*/images/`（解密/系统镜像）和 `extracted/*/dyld/`（dyld shared cache）。
- `headunits/`（车机固件）。
- Ghidra 工程/缓存、工具安装目录、`setup/downloads/` 和压缩包。

这些内容体积过大或属于第三方固件，需要本地自行获取。提取二进制入库是为了避免每次
都下载和重新解包完整 IPSW。

## 使用

```bash
# 1. 准备 IPSW 并校验
sha256sum ipsw/iPhone18,1_27.0.1_24A446_Restore.ipsw

# 2. 安装工具链
cd setup && sudo bash install-linux-tools.sh

# 3. 按 SOURCE.md 中的 ipsw extract 命令重新提取
# 4. 运行本仓库的 Python 分析工具
```

## 相关仓库

- `iamr0s/carvex-carplay-research`：研究文档、手机端协议研究和连接分析。
- `iamr0s/carvex-android`：CarVeX，CarPlay 的 Android 实现。

## 边界

- 原始固件字节和提取物是证据；`analysis/` 中的函数名、字符串和反编译输出只是索引，
  不能单独作为协议结论。
- 提取物用于推导协议栈框架的状态机与事件；配置只是运行输入，不能替代状态机。
- 这些固件证据只适用于 CarPlay 路径，不能外推到 HiCar、CarLife、ICCOA 等协议。
- 不修改 Apple 固件或车机固件。
- 哈希一致只证明文件相同，不证明 Apple 签名有效或来源合法。
- 本仓库不是可运行产品，也不声称与任何车机互通。
