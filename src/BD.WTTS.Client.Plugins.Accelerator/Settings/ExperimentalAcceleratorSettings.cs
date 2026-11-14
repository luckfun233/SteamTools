using System.Text.Json;

// ReSharper disable once CheckNamespace
namespace BD.WTTS.Settings;

/// <summary>
/// 实验性加速设置。独立存放于插件数据目录，避免影响上游的 Settings 源生成文件。
/// </summary>
public sealed class ExperimentalAcceleratorOptions
{
    /// <summary>
    /// 是否合并客户端内置的 GitHub / Hugging Face 加速组。
    /// 关闭后如果服务端接口不可用，加速页将没有任何加速组。
    /// </summary>
    public bool EnableBuiltInGroups { get; set; } = true;

    /// <summary>
    /// 是否加载 DevSidecar 兼容规则。
    /// </summary>
    public bool EnableDevSidecarRules { get; set; }

    /// <summary>
    /// DevSidecar 远程配置地址，只允许 HTTPS。
    /// </summary>
    public string DevSidecarConfigUrl { get; set; } = DevSidecarRuleGroups.DefaultConfigUrl;

    /// <summary>
    /// 是否在启动/刷新加速列表时从远程同步 DevSidecar 配置。
    /// 关闭时只读取上次成功同步的本地缓存。
    /// </summary>
    public bool SyncDevSidecarOnStartup { get; set; } = true;

    public ExperimentalAcceleratorOptions Clone() => new()
    {
        EnableBuiltInGroups = EnableBuiltInGroups,
        EnableDevSidecarRules = EnableDevSidecarRules,
        DevSidecarConfigUrl = DevSidecarConfigUrl,
        SyncDevSidecarOnStartup = SyncDevSidecarOnStartup,
    };
}

public static class ExperimentalAcceleratorSettings
{
    static readonly object sync = new();
    static ExperimentalAcceleratorOptions? current;

    public static string ConfigFilePath => Path.Combine(
        BD.WTTS.Plugins.Plugin.Instance.AppDataDirectory,
        "experimental_accelerator.json");

    public static ExperimentalAcceleratorOptions Current
    {
        get
        {
            if (current != null) return current;
            lock (sync)
            {
                current ??= Load();
                return current;
            }
        }
    }

    public static void Save()
    {
        lock (sync)
        {
            if (current == null) return;
            var dir = Path.GetDirectoryName(ConfigFilePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var json = JsonSerializer.Serialize(current, JsonOptions);
            File.WriteAllText(ConfigFilePath, json);
        }
    }

    static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    static ExperimentalAcceleratorOptions Load()
    {
        try
        {
            if (File.Exists(ConfigFilePath))
            {
                var json = File.ReadAllText(ConfigFilePath);
                var options = JsonSerializer.Deserialize<ExperimentalAcceleratorOptions>(json, JsonOptions);
                if (options != null) return options;
            }
        }
        catch (Exception ex)
        {
            Log.Warn(nameof(ExperimentalAcceleratorSettings), ex, "读取实验性加速设置失败，使用默认值");
        }
        return new ExperimentalAcceleratorOptions();
    }
}
