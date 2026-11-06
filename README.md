# WirelessAdb-LSPosed

**LSPosed / Vector 模块**：开机首次解锁后自动开启无线 ADB，并在状态页实时管理在线客户端连接与运行日志。

包名：`dev.wirelessadb.autostart`  
当前版本：`1.1.1`

<p align="center">
  <img src="docs/screenshot.png" alt="无线 ADB 自启状态页" width="360" />
</p>

## 功能

- **TLS 模式**：系统「无线调试」（`adb_wifi_enabled`），端口随机，需配对
- **TCP 模式**：等价 `adb tcpip <port>`，默认 `5555`，电脑可直接 `adb connect IP:5555`（针对严格 SELinux 厂商 ROM 支持自动回退 Root 设置属性）
- **在线客户端监控与管理（新增，全程免 Root）**：
  - 依托 `system_server` 内核 `NETLINK_INET_DIAG`（`SOCK_DIAG_BY_FAMILY`）原生枚举活跃连接（绕过 Android 12–16+ 对 `/proc/net/tcp*` 的 SELinux `neverallow` 限制，无需给应用授予 Root 即可实时显示连入 IP、端口与连入时间）
  - 支持为各客户端 IP 添加**自定义设备备注**，点击 IP 一键复制
  - 支持通过 `system_server` `SOCK_DESTROY` **免 Root 一键强制踢掉单个会话或指定 IP 的全部连接**（亦保留 `ss -K` Root 兜底）
  - 自动在运行记录中追加**客户端连入 / 断开**时间日志
- **安全与稳定性加固**：
  - 组件间广播与日志 Provider 采用应用签名级权限（`protectionLevel="signature"`）与调用方 UID 校验保护
  - 仅在亮屏交互或前台打开界面时按需刷新连接状态，息屏零唤醒、零额外耗电
- 监听无线调试关闭（仅 TLS）、Wi‑Fi 恢复、亮屏，必要时重新开启
- 地址变化时自动复制到剪贴板（等待微信输入法跨设备粘贴就绪）
- 获取 IP 时校验 Wi‑Fi 传输能力并跳过 `172.19.*` VPN 虚拟地址

## 安装

1. 安装 Release APK（若从旧签名版本切换，请先卸载原版再安装）
2. 在 **LSPosed / Vector** 中启用本模块，作用域勾选 **系统框架**（`android`）
3. （可选）如需使用「一键断开客户端」或受限 ROM 下 Root 属性兜底，在 **KernelSU / SukiSU / Magisk** 中为本应用授予 Root 权限
4. 重启手机并完成首次解锁

> 仅建议在可信局域网使用。切换 TCP 会重启 adbd，当前 ADB 会话可能断开。

## 构建

```bash
./gradlew :app:assembleRelease
```

产物：`app/build/outputs/apk/release/app-release.apk`

需要本机已配置 Android SDK（`local.properties` 中的 `sdk.dir`，或环境变量 `ANDROID_HOME`）。

## 许可

MIT
