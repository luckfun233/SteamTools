#!/bin/sh
# Watt Toolkit (Steam++) Linux 启动脚本
cd "$(dirname "$0")" || exit 1
chmod +x ./Steam++ 2>/dev/null
if [ -z "$LANG" ]; then
    export LANG=en_US.UTF-8
fi
exec ./Steam++
