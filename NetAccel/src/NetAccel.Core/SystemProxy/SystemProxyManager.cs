using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using NetAccel.Core.Models;

namespace NetAccel.Core.SystemProxy;

/// <summary>
/// 操作系统代理开关。只修改“手动代理”，并在开启前保存原始值，
/// 关闭时尽量原样恢复，避免用户关闭应用后断网。
/// </summary>
public sealed class SystemProxyManager
{
    readonly string stateFilePath;

    public SystemProxyManager(string? stateFilePath = null)
    {
        this.stateFilePath = stateFilePath ?? Path.Combine(AppPaths.Home, "system-proxy-state.json");
    }

    public bool IsEnabledByUs => File.Exists(stateFilePath);

    public bool Enable(int httpPort, int socksPort, out string message)
    {
        try
        {
            if (OperatingSystem.IsWindows()) return EnableWindows(httpPort, out message);
            if (OperatingSystem.IsLinux()) return EnableLinux(httpPort, socksPort, out message);
            if (OperatingSystem.IsMacOS()) return EnableMac(httpPort, socksPort, out message);

            message = "当前系统不支持自动设置代理";
            return false;
        }
        catch (Exception ex)
        {
            message = "设置系统代理失败: " + ex.Message;
            return false;
        }
    }

    public bool Disable(out string message)
    {
        try
        {
            if (!File.Exists(stateFilePath))
            {
                message = "没有需要恢复的系统代理设置";
                return true;
            }

            var state = JsonSerializer.Deserialize<State>(File.ReadAllText(stateFilePath));
            if (state == null)
            {
                message = "代理状态文件损坏";
                return false;
            }

            bool restored;
            if (state.Platform == "windows")
            {
                if (!OperatingSystem.IsWindows())
                {
                    message = "当前系统不是 Windows，无法恢复注册表代理设置";
                    return false;
                }
                restored = RestoreWindows(state, out message);
            }
            else
            {
                restored = state.Platform switch
                {
                    "gnome" => RestoreGnome(state, out message),
                    "kde" => RestoreKde(state, out message),
                    "macos" => RestoreMac(state, out message),
                    _ => Fail($"未知的平台状态: {state.Platform}", out message),
                };
            }

            if (restored) TryDelete(stateFilePath);
            return restored;
        }
        catch (Exception ex)
        {
            message = "恢复系统代理失败: " + ex.Message;
            return false;
        }
    }

    static bool Fail(string reason, out string message)
    {
        message = reason;
        return false;
    }

    static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch
        {
            // ignore
        }
    }

    void SaveState(State state)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(stateFilePath)!);
        File.WriteAllText(stateFilePath, JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true }));
    }

    // ---------------- Windows ----------------

    const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
    const int INTERNET_OPTION_REFRESH = 37;

    [DllImport("wininet.dll", SetLastError = true)]
    static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    bool EnableWindows(int httpPort, out string message)
    {
        const string keyPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(keyPath, writable: true);
        if (key == null)
        {
            message = "无法打开 Windows 代理注册表项";
            return false;
        }

        var previousEnable = key.GetValue("ProxyEnable")?.ToString() ?? "0";
        var previousServer = key.GetValue("ProxyServer")?.ToString() ?? string.Empty;
        var previousOverride = key.GetValue("ProxyOverride")?.ToString() ?? string.Empty;

        SaveState(new State
        {
            Platform = "windows",
            Values = new Dictionary<string, string>
            {
                ["ProxyEnable"] = previousEnable,
                ["ProxyServer"] = previousServer,
                ["ProxyOverride"] = previousOverride,
            },
        });

        key.SetValue("ProxyEnable", 1, Microsoft.Win32.RegistryValueKind.DWord);
        key.SetValue("ProxyServer", $"127.0.0.1:{httpPort}", Microsoft.Win32.RegistryValueKind.String);
        key.SetValue("ProxyOverride", "<local>", Microsoft.Win32.RegistryValueKind.String);

        InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);

        message = $"系统代理已设置为 127.0.0.1:{httpPort}";
        return true;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    static bool RestoreWindows(State state, out string message)
    {
        const string keyPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(keyPath, writable: true);
        if (key == null)
        {
            message = "无法打开 Windows 代理注册表项";
            return false;
        }

        if (state.Values.TryGetValue("ProxyEnable", out var enable) && int.TryParse(enable, out var enabled))
        {
            key.SetValue("ProxyEnable", enabled, Microsoft.Win32.RegistryValueKind.DWord);
        }
        if (state.Values.TryGetValue("ProxyServer", out var server))
        {
            key.SetValue("ProxyServer", server, Microsoft.Win32.RegistryValueKind.String);
        }
        if (state.Values.TryGetValue("ProxyOverride", out var proxyOverride))
        {
            key.SetValue("ProxyOverride", proxyOverride, Microsoft.Win32.RegistryValueKind.String);
        }

        InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);

        message = "系统代理已恢复";
        return true;
    }

    // ---------------- Linux / GNOME ----------------

    bool EnableLinux(int httpPort, int socksPort, out string message)
    {
        if (HasGsettings())
        {
            var values = new Dictionary<string, string>
            {
                ["mode"] = GsettingsGet("org.gnome.system.proxy", "mode") ?? "'none'",
                ["http:host"] = GsettingsGet("org.gnome.system.proxy.http", "host") ?? "''",
                ["http:port"] = GsettingsGet("org.gnome.system.proxy.http", "port") ?? "0",
                ["https:host"] = GsettingsGet("org.gnome.system.proxy.https", "host") ?? "''",
                ["https:port"] = GsettingsGet("org.gnome.system.proxy.https", "port") ?? "0",
                ["socks:host"] = GsettingsGet("org.gnome.system.proxy.socks", "host") ?? "''",
                ["socks:port"] = GsettingsGet("org.gnome.system.proxy.socks", "port") ?? "0",
            };

            SaveState(new State { Platform = "gnome", Values = values });

            GsettingsSet("org.gnome.system.proxy", "mode", "manual");
            GsettingsSet("org.gnome.system.proxy.http", "host", "127.0.0.1");
            GsettingsSet("org.gnome.system.proxy.http", "port", httpPort.ToString());
            GsettingsSet("org.gnome.system.proxy.https", "host", "127.0.0.1");
            GsettingsSet("org.gnome.system.proxy.https", "port", httpPort.ToString());
            GsettingsSet("org.gnome.system.proxy.socks", "host", "127.0.0.1");
            GsettingsSet("org.gnome.system.proxy.socks", "port", socksPort.ToString());
            GsettingsSet("org.gnome.system.proxy", "ignore-hosts",
                "['localhost', '127.0.0.0/8', '::1', '*.local']");

            message = $"GNOME 系统代理已设置为 127.0.0.1:{httpPort}";
            return true;
        }

        if (HasKdeConfig())
        {
            SaveState(new State
            {
                Platform = "kde",
                Values = new Dictionary<string, string>
                {
                    ["ProxyType"] = ReadKde("ProxyType") ?? "0",
                    ["httpProxy"] = ReadKde("httpProxy") ?? string.Empty,
                    ["httpsProxy"] = ReadKde("httpsProxy") ?? string.Empty,
                },
            });

            RunKde("--key", "ProxyType", "1");
            RunKde("--key", "httpProxy", $"http://127.0.0.1:{httpPort}");
            RunKde("--key", "httpsProxy", $"http://127.0.0.1:{httpPort}");
            RunKde("--key", "NoProxyFor", "localhost,127.0.0.1,::1");

            message = $"KDE 系统代理已设置为 127.0.0.1:{httpPort}";
            return true;
        }

        message = "未检测到 GNOME/KDE 桌面环境。请手动设置 HTTP 代理 127.0.0.1:" +
                  $"{httpPort}，或在终端执行 export https_proxy=http://127.0.0.1:{httpPort}";
        return false;
    }

    static bool RestoreGnome(State state, out string message)
    {
        GsettingsSet("org.gnome.system.proxy", "mode", Unquote(state.Values.GetValueOrDefault("mode", "'none'")));
        GsettingsSet("org.gnome.system.proxy.http", "host", Unquote(state.Values.GetValueOrDefault("http:host", "''")));
        GsettingsSet("org.gnome.system.proxy.http", "port", Unquote(state.Values.GetValueOrDefault("http:port", "0")));
        GsettingsSet("org.gnome.system.proxy.https", "host", Unquote(state.Values.GetValueOrDefault("https:host", "''")));
        GsettingsSet("org.gnome.system.proxy.https", "port", Unquote(state.Values.GetValueOrDefault("https:port", "0")));
        GsettingsSet("org.gnome.system.proxy.socks", "host", Unquote(state.Values.GetValueOrDefault("socks:host", "''")));
        GsettingsSet("org.gnome.system.proxy.socks", "port", Unquote(state.Values.GetValueOrDefault("socks:port", "0")));

        message = "GNOME 系统代理已恢复";
        return true;
    }

    static bool RestoreKde(State state, out string message)
    {
        RunKde("--key", "ProxyType", Unquote(state.Values.GetValueOrDefault("ProxyType", "0")));
        RunKde("--key", "httpProxy", Unquote(state.Values.GetValueOrDefault("httpProxy", string.Empty)));
        RunKde("--key", "httpsProxy", Unquote(state.Values.GetValueOrDefault("httpsProxy", string.Empty)));
        message = "KDE 系统代理已恢复";
        return true;
    }

    static string Unquote(string value)
    {
        value = value.Trim();
        if (value.Length >= 2 && value[0] == '\'' && value[^1] == '\'') return value[1..^1];
        return value;
    }

    static bool HasGsettings()
    {
        var (code, output, _) = Run("gsettings", "list-schemas");
        return code == 0 && output.Contains("org.gnome.system.proxy", StringComparison.Ordinal);
    }

    static string? GsettingsGet(string schema, string key)
    {
        var (code, output, _) = Run("gsettings", $"get {schema} {key}");
        return code == 0 ? output.Trim() : null;
    }

    static void GsettingsSet(string schema, string key, string value)
    {
        Run("gsettings", $"set {schema} {key} \"{value.Replace("\"", "\\\"")}\"");
    }

    static bool HasKdeConfig()
    {
        var (code, _, _) = Run("which", "kwriteconfig5");
        if (code == 0) return true;
        (code, _, _) = Run("which", "kwriteconfig6");
        return code == 0;
    }

    static string? RunKde(params string[] args)
    {
        var tool = File.Exists("/usr/bin/kwriteconfig6") ? "kwriteconfig6" : "kwriteconfig5";
        var all = new[] { "--file", "kioslaverc", "--group", "Proxy Settings" }.Concat(args).ToArray();
        var (code, output, _) = Run(tool, string.Join(" ", all.Select(QuoteArg)));
        return code == 0 ? output.Trim() : null;
    }

    static string? ReadKde(string key)
    {
        var tool = File.Exists("/usr/bin/kreadconfig6") ? "kreadconfig6" : "kreadconfig5";
        var (code, output, _) = Run(tool,
            string.Join(" ", new[] { "--file", "kioslaverc", "--group", "Proxy Settings", "--key", key }
                .Select(QuoteArg)));
        return code == 0 ? output.Trim() : null;
    }

    // ---------------- macOS ----------------

    bool EnableMac(int httpPort, int socksPort, out string message)
    {
        var service = GetPrimaryNetworkService();
        if (string.IsNullOrEmpty(service))
        {
            message = "未找到可用的 macOS 网络服务";
            return false;
        }

        SaveState(new State
        {
            Platform = "macos",
            Values = new Dictionary<string, string>
            {
                ["service"] = service,
                ["web"] = Run("networksetup", $"-getwebproxy \"{service}\"").Output,
                ["secure"] = Run("networksetup", $"-getsecurewebproxy \"{service}\"").Output,
                ["socks"] = Run("networksetup", $"-getsocksfirewallproxy \"{service}\"").Output,
            },
        });

        Run("networksetup", $"-setwebproxy \"{service}\" 127.0.0.1 {httpPort}");
        Run("networksetup", $"-setsecurewebproxy \"{service}\" 127.0.0.1 {httpPort}");
        Run("networksetup", $"-setsocksfirewallproxy \"{service}\" 127.0.0.1 {socksPort}");

        message = $"macOS 系统代理已设置为 127.0.0.1:{httpPort}（{service}）";
        return true;
    }

    static bool RestoreMac(State state, out string message)
    {
        var service = state.Values.GetValueOrDefault("service", string.Empty);
        if (string.IsNullOrEmpty(service))
        {
            message = "macOS 代理状态缺少网络服务名";
            return false;
        }

        RestoreMacProxy(state.Values.GetValueOrDefault("web"), "-setwebproxy", service);
        RestoreMacProxy(state.Values.GetValueOrDefault("secure"), "-setsecurewebproxy", service);
        RestoreMacProxy(state.Values.GetValueOrDefault("socks"), "-setsocksfirewallproxy", service);

        message = "macOS 系统代理已恢复";
        return true;
    }

    static void RestoreMacProxy(string? output, string setCommand, string service)
    {
        if (string.IsNullOrEmpty(output)) return;

        string? server = null;
        var port = 0;
        var enabled = false;
        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("Server:", StringComparison.OrdinalIgnoreCase))
                server = trimmed[7..].Trim();
            else if (trimmed.StartsWith("Port:", StringComparison.OrdinalIgnoreCase))
                int.TryParse(trimmed[5..].Trim(), out port);
            else if (trimmed.StartsWith("Enabled:", StringComparison.OrdinalIgnoreCase))
                enabled = trimmed[8..].Trim().Equals("Yes", StringComparison.OrdinalIgnoreCase);
        }

        if (enabled && !string.IsNullOrEmpty(server) && port > 0)
        {
            Run("networksetup", $"{setCommand} \"{service}\" {server} {port}");
        }
        else
        {
            var offCommand = setCommand switch
            {
                "-setwebproxy" => "-setwebproxystate",
                "-setsecurewebproxy" => "-setsecurewebproxystate",
                _ => "-setsocksfirewallproxystate",
            };
            Run("networksetup", $"{offCommand} \"{service}\" off");
        }
    }

    static string? GetPrimaryNetworkService()
    {
        var (code, output, _) = Run("networksetup", "-listallnetworkservices");
        if (code != 0) return null;

        foreach (var line in output.Split('\n').Skip(1))
        {
            var name = line.Trim();
            if (name.Length == 0 || name.StartsWith("*", StringComparison.Ordinal)) continue;
            return name;
        }
        return null;
    }

    // ---------------- 进程执行 ----------------

    static (int Code, string Output, string Error) Run(string fileName, string arguments)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });

            if (process == null) return (-1, string.Empty, "无法启动进程");
            var output = process.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();
            if (!process.WaitForExit(5000))
            {
                try
                {
                    process.Kill();
                }
                catch
                {
                    // ignore
                }
                return (-1, output, "执行超时");
            }
            return (process.ExitCode, output, error);
        }
        catch (Exception ex)
        {
            return (-1, string.Empty, ex.Message);
        }
    }

    static string QuoteArg(string arg)
        => arg.Contains(' ') ? $"\"{arg}\"" : arg;

    sealed class State
    {
        public string Platform { get; set; } = string.Empty;
        public Dictionary<string, string> Values { get; set; } = new();
    }
}
