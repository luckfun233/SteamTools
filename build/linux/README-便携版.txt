Watt Toolkit - Linux 自建加速版（便携包）
========================================

这个包是什么
------------
基于 Watt Toolkit（原 Steam++）源码构建的 Linux x64 便携版，包含本分支的加速修复：
- 加速页内置 GitHub / Hugging Face 加速组，服务端接口不可用时不再空白
- 加速设置页新增“实验性加速”区域（内置组开关、DevSidecar 规则同步）
- 自建包不再弹“非官方渠道”提示

运行
----
1. 解压到一个固定目录（不要放在 /tmp）。
2. 首次运行：
       chmod +x Steam++
       ./Steam++
3. 想出现在应用菜单里：
       ./install.sh

说明
----
- 这是自包含包，不需要单独安装 .NET 运行时。
- Linux 下加速走系统代理模式；首次启动加速时按提示安装本地根证书。
- 加速插件位于 modules/Accelerator，反代进程 Steam++.Accelerator 必须和插件 DLL 在同一目录。
- 日志与配置：
      ~/.local/share/WattToolkit 或 ~/.config/Steam++
  具体路径以应用内“打开配置目录”为准。
- 卸载：删除解压目录，并删除 ~/.local/share/applications/watt-toolkit.desktop 与图标。

已知限制
--------
- 仅构建了 linux-x64。
- 本次构建未在带图形界面的桌面上实机验证，只验证了程序能启动到显示初始化阶段。
- 如果启动报缺少 libX11 / fontconfig，请安装发行版对应的 Avalonia 运行依赖。

校验
----
SHA256 见同目录的 .sha256 文件。
