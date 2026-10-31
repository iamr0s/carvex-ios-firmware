# iOS CarPlay 组件提取结果

来源：本目录提供的 iPhone 17 Pro / iOS 27.0.1 / 24A446 固件。

已导出 42 个相关缓存映像、1299 个重建头文件，保存完整缓存文件组的 82 个文件。
文件系统关键词匹配得到 1343 个候选文件，其中 35 个是 Mach-O 文件。关键词匹配包含界面、资源及配件服务等候选材料，不表示每个文件都是 CarPlay 核心协议实现。

二进制位置：`binaries/`；类声明：`headers/`；服务和资源：`components/`。

导出文件的原始路径、大小和 SHA-256 见 `component-manifest.json` 和 `filesystem-manifest.json`。

验证：全部导出命令与已执行的类声明导出命令成功，逐个检查了导出文件的大小和 Mach-O 标识；CarKit、AirPlaySender、accessoryd 又通过 ipsw Mach-O 解析器检查。没有执行这些 iOS 程序或验证协议互通。

## 缓存组件

| 组件 | 重建头文件数 |
| --- | ---: |
| AssistiveTouch-iOS | 0 |
| BLEPairing-iOS | 0 |
| Communications-iOS | 0 |
| HID | 0 |
| Navigation-iOS | 0 |
| OOBBTPairing-iOS | 0 |
| IOKit | 0 |
| Platform-Bluetooth | 0 |
| System | 0 |
| WiFiSharing | 0 |
| IOAccessoryManager | 0 |
| NFC | 0 |
| USBHost | 0 |
| CarPlay | 215 |
| AccessoryCommunications | 5 |
| AccessoryNavigation | 15 |
| AccessoryiAP2Shim | 6 |
| AirPlayAndHandoffSettingsSupport | 0 |
| AirPlayKit | 51 |
| AirPlayOverlays | 13 |
| AirPlayOverlaysServer | 17 |
| AirPlayReceiver | 13 |
| AirPlayReceiverKit | 23 |
| AirPlayRoutePrediction | 16 |
| AirPlaySender | 18 |
| AirPlaySenderKit | 10 |
| AirPlaySenderUI | 6 |
| AirPlaySupport | 10 |
| CarKit | 119 |
| CarKitNavigation | 21 |
| CarPlayAssetUI | 59 |
| CarPlayDesignLibrary | 0 |
| CarPlayDisplayUtils | 0 |
| CarPlayServices | 37 |
| CarPlaySetup | 16 |
| CarPlaySupport | 282 |
| CarPlayUI | 158 |
| CarPlayUIServices | 156 |
| CoreAccessories | 23 |
| CoreAccessoriesFeatures | 3 |
| IAP | 7 |
| libswiftCarPlay.dylib | 0 |

## 系统服务与可执行文件

- `extracted/24A446/components/24A446__iPhone18,1/root/Applications/AirPlaySenderUIApp.app/AirPlaySenderUIApp` (184752 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/Applications/CarPlaySettings.app/CarPlaySettings` (1734128 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/Applications/CarPlaySetup.app/CarPlaySetup` (130240 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/Applications/CarPlaySplashScreen.app/CarPlaySplashScreen` (100352 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/Applications/CarPlayWallpaper.app/CarPlayWallpaper` (160928 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/Applications/WidgetRenderer_CarPlay.app/WidgetRenderer_CarPlay` (84256 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/Accounts/Notification/CoreAccessoriesAccountNotificationPlugin.bundle/CoreAccessoriesAccountNotificationPlugin` (70928 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/Audio/Plug-Ins/HAL/AirPlayHalogen.driver/AirPlayHalogen` (154096 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/Audio/Plug-Ins/HAL/CarPlayHalogen.driver/CarPlayHalogen` (111952 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/CoreServices/CarPlay.app/CarPlay` (70560 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/CoreServices/CarPlayTemplateUIHost.app/CarPlayTemplateUIHost` (183392 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/ExtensionKit/Extensions/PnRCarPlayOnDeviceWorker.appex/PnRCarPlayOnDeviceWorker` (102704 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/PreferenceBundles/AccessoryDeveloperSettings.bundle/AccessoryDeveloperSettings` (109824 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/PreferenceBundles/AirPlayAndHandoffSettings.bundle/AirPlayAndHandoffSettings` (179728 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/PreferenceBundles/CarKitSettings.bundle/CarKitSettings` (661520 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/PrivateFrameworks/AirPlaySenderKit.framework/XPCServices/AirPlaySenderService.xpc/AirPlaySenderService` (146640 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/PrivateFrameworks/CarKit.framework/PlugIns/CarPlayDiagnostics.appex/CarPlayDiagnostics` (71776 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/PrivateFrameworks/CarPlayUIServices.framework/XPCServices/CarPlayScreenshotService.xpc/CarPlayScreenshotService` (99408 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/PrivateFrameworks/CoreAccessories.framework/Support/accessoryd` (4330752 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/PrivateFrameworks/CoreAccessories.framework/XPCServices/ACCAppLinksIconService.xpc/ACCAppLinksIconService` (82576 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/PrivateFrameworks/CoreAccessories.framework/XPCServices/ACCCarPlayService.xpc/ACCCarPlayService` (120688 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/PrivateFrameworks/CoreAccessories.framework/XPCServices/ACCHWComponentAuthService.xpc/ACCHWComponentAuthService` (832032 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/PrivateFrameworks/CoreAccessoriesFeatures.framework/XPCServices/ACCFeatureAudioProductService.xpc/ACCFeatureAudioProductService` (132640 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/PrivateFrameworks/CoreAccessoriesFeatures.framework/XPCServices/ACCMediaLibraryFeature.xpc/ACCMediaLibraryFeature` (599728 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/PrivateFrameworks/CoreAccessoriesFeatures.framework/XPCServices/ACCNowPlayingFeature.xpc/ACCNowPlayingFeature` (329136 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/PrivateFrameworks/IAP.framework/Support/iapd` (1440608 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/PrivateFrameworks/UIKitCore.framework/CarPlayArtwork.bundle/CarPlayArtwork` (34896 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/System/Library/UserEventPlugins/com.apple.accessoryd.matching.plugin/com.apple.accessoryd.matching` (745232 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/usr/libexec/airplayd` (89840 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/usr/libexec/audioaccessoryd` (4082672 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/usr/libexec/caraccessoryd` (1121168 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/usr/libexec/carkitd` (1287040 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/usr/libexec/dockaccessoryd` (3078336 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/usr/libexec/fairplaydeviceidentityd` (6608272 bytes)
- `extracted/24A446/components/24A446__iPhone18,1/root/usr/sbin/fairplayd.H2` (18196720 bytes)

这些文件用于静态分析；它们不是原始源码，独立库的部分元数据仍可能依赖原始缓存。该构建与此前其他 iOS 构建的 sysdiagnose 地址和 UUID 不可直接混用。
