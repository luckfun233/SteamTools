namespace NetAccel.Core.Models;

/// <summary>
/// 应用数据目录。优先使用 NETACCEL_HOME 环境变量，便于 CLI 与测试隔离。
/// </summary>
public static class AppPaths
{
    public const string AppName = "NetAccel";

    public static string Home { get; set; } = ResolveHome();

    public static string SettingsFile => Path.Combine(Home, "settings.json");

    public static string CustomRulesFile => Path.Combine(Home, "rules", "custom_rules.json");

    public static string RemoteRulesCacheFile => Path.Combine(Home, "rules", "remote_config.json5");

    public static string LogDirectory => Path.Combine(Home, "logs");

    public static string CrashLogFile => Path.Combine(Home, "crash.log");

    static string ResolveHome()
    {
        var overridden = Environment.GetEnvironmentVariable("NETACCEL_HOME");
        if (!string.IsNullOrWhiteSpace(overridden)) return overridden.Trim();

        if (OperatingSystem.IsWindows())
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            return Path.Combine(appData, AppName);
        }

        if (OperatingSystem.IsMacOS())
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            return Path.Combine(home, "Library", "Application Support", AppName);
        }

        var xdg = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME");
        if (!string.IsNullOrWhiteSpace(xdg)) return Path.Combine(xdg, AppName);

        var userHome = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Path.Combine(userHome, ".config", AppName);
    }

    public static void EnsureDirectories()
    {
        Directory.CreateDirectory(Home);
        Directory.CreateDirectory(Path.GetDirectoryName(SettingsFile)!);
        Directory.CreateDirectory(Path.GetDirectoryName(CustomRulesFile)!);
        Directory.CreateDirectory(LogDirectory);
    }
}
