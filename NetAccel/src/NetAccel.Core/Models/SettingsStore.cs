using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetAccel.Core.Models;

/// <summary>
/// 设置持久化。读取失败时优先回退到 .bak，再回退到默认值，绝不让配置文件损坏导致启动失败。
/// </summary>
public sealed class SettingsStore
{
    static readonly JsonSerializerOptions jsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public string FilePath { get; }

    public SettingsStore(string? filePath = null)
    {
        FilePath = filePath ?? AppPaths.SettingsFile;
    }

    public AccelSettings Load()
    {
        var settings = TryRead(FilePath) ?? TryRead(FilePath + ".bak") ?? AccelSettings.CreateDefault();
        if (settings.Normalize())
        {
            TrySave(settings);
        }
        return settings;
    }

    public bool Save(AccelSettings settings)
    {
        settings.Normalize();
        return TrySave(settings);
    }

    static AccelSettings? TryRead(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            var json = File.ReadAllText(path);
            if (string.IsNullOrWhiteSpace(json)) return null;
            return JsonSerializer.Deserialize<AccelSettings>(json, jsonOptions);
        }
        catch
        {
            return null;
        }
    }

    bool TrySave(AccelSettings settings)
    {
        try
        {
            var dir = Path.GetDirectoryName(FilePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            var json = JsonSerializer.Serialize(settings, jsonOptions);
            var tmp = FilePath + ".tmp";
            File.WriteAllText(tmp, json);

            if (File.Exists(FilePath))
            {
                File.Copy(FilePath, FilePath + ".bak", overwrite: true);
                File.Delete(FilePath);
            }
            File.Move(tmp, FilePath);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
