using System;

namespace System.Application.Services.Implementation
{
    /// <summary>
    /// 共享层到 Android 原生 ByeDPI 进程的桥。Android 启动时注册实现；
    /// 桌面/测试环境没有注册时自动退化为 C# 分片。
    /// </summary>
    public static class ByedpiRuntime
    {
        public static Func<bool>? EnsureStarted;
        public static Action? Stop;
        public static Func<bool>? IsRunning;
        public static Func<int>? GetPort;
        public static Func<string, bool>? ShouldUse;
    }
}
