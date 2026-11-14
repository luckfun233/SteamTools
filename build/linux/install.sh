#!/usr/bin/env bash
# Watt Toolkit（Linux 自建包）便携版安装脚本
# 作用：给当前目录的 Steam++ 可执行权限，并把 .desktop 菜单项和图标注册到当前用户目录。
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="$DIR/Steam++"
ICON_DIR="$HOME/.local/share/icons/hicolor/256x256/apps"
DESKTOP_DIR="$HOME/.local/share/applications"

if [ ! -f "$APP" ]; then
  echo "找不到 $APP，请在解压后的目录内运行此脚本。" >&2
  exit 1
fi

chmod +x "$APP"
chmod +x "$DIR/modules/Accelerator/Steam++.Accelerator" 2>/dev/null || true
mkdir -p "$ICON_DIR" "$DESKTOP_DIR"
cp -f "$DIR/steampp.png" "$ICON_DIR/steampp.png"

cat > "$DESKTOP_DIR/watt-toolkit.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Watt Toolkit
Comment=Steam 工具箱（Linux 自建加速版）
Exec="$APP" %U
Icon=steampp
Terminal=false
Categories=Utility;Game;
StartupWMClass=Steam++
EOF

update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor" 2>/dev/null || true

echo "已注册菜单项：$DESKTOP_DIR/watt-toolkit.desktop"
echo "如果移动了解压目录，请重新运行本脚本。"
