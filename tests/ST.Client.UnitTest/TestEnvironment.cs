using NUnit.Framework;
using System;
using System.IO;

namespace System.Application;

/// <summary>
/// 单元测试运行前初始化应用目录，避免设置系统因 IOPath 未初始化而抛异常。
/// </summary>
[SetUpFixture]
public class TestEnvironment
{
    [OneTimeSetUp]
    public void Setup()
    {
        var root = Path.Combine(Path.GetTempPath(), "watt-unit-test-" + Guid.NewGuid().ToString("N"));
        var appData = Path.Combine(root, "appdata");
        var cache = Path.Combine(root, "cache");
        Directory.CreateDirectory(appData);
        Directory.CreateDirectory(cache);
        IOPath.InitFileSystem(() => appData, () => cache);
    }
}
