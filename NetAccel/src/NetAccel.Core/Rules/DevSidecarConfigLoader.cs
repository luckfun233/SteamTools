using System.Net.Http;
using System.Text.Json;
using NetAccel.Core.Models;

namespace NetAccel.Core.Rules;

/// <summary>
/// 读取并转换 DevSidecar 的 remote_config.json5（只实现与加速相关的子集）。
/// 下载失败时自动回退本地缓存；非 HTTPS 地址会被拒绝。
/// </summary>
public sealed class DevSidecarConfigLoader
{
    public const string DefaultConfigUrl = "https://ds-official-config.bestar.de5.net/remote_config.json5";

    static readonly HttpClient httpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(20),
    };

    readonly string cacheFilePath;

    public DevSidecarConfigLoader(string? cacheFilePath = null)
    {
        this.cacheFilePath = cacheFilePath ?? AppPaths.RemoteRulesCacheFile;
    }

    public string CacheFilePath => cacheFilePath;

    public async Task<ProxyRuleSet> LoadAsync(string? url = null, CancellationToken cancellationToken = default)
    {
        url = string.IsNullOrWhiteSpace(url) ? DefaultConfigUrl : url.Trim();

        if (!Uri.TryCreate(url, UriKind.Absolute, out var configUri) ||
            !string.Equals(configUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            // 不允许明文 HTTP，避免规则被中间人篡改。
            return LoadCache();
        }

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.TryAddWithoutValidation("User-Agent", "NetAccel/1.0 (DevSidecar Compatible)");
            using var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(text)) throw new InvalidDataException("DevSidecar 配置内容为空");

            TryWriteCache(text);
            return Parse(text);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return LoadCache();
        }
    }

    public ProxyRuleSet LoadCache()
    {
        try
        {
            if (!File.Exists(cacheFilePath)) return ProxyRuleSet.Empty;
            return Parse(File.ReadAllText(cacheFilePath));
        }
        catch
        {
            return ProxyRuleSet.Empty;
        }
    }

    void TryWriteCache(string text)
    {
        try
        {
            var dir = Path.GetDirectoryName(cacheFilePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var tmp = cacheFilePath + ".tmp";
            File.WriteAllText(tmp, text);
            if (File.Exists(cacheFilePath)) File.Delete(cacheFilePath);
            File.Move(tmp, cacheFilePath);
        }
        catch
        {
            // 缓存失败不影响本次使用
        }
    }

    public static ProxyRuleSet Parse(string json) => Parse(json, null);

    public static ProxyRuleSet Parse(string json, string? groupOverride)
        => TryParse(json, groupOverride, out var rules, out _) ? rules : ProxyRuleSet.Empty;

    public static bool TryParse(
        string json,
        string? groupOverride,
        out ProxyRuleSet rules,
        out string? error)
    {
        rules = ProxyRuleSet.Empty;
        error = null;
        try
        {
            var normalized = Json5.ToJson(json);
            using var doc = JsonDocument.Parse(normalized, new JsonDocumentOptions
            {
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip,
                MaxDepth = 64,
            });
            rules = Convert(doc.RootElement, groupOverride);
            if (rules.Rules.Count == 0 &&
                rules.PresetIps.Count == 0 &&
                rules.ExcludePatterns.Count == 0)
            {
                error = "没有解析到任何规则，请检查 intercepts 的域名和路径结构。";
            }
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    static ProxyRuleSet Convert(JsonElement root, string? groupOverride)
    {
        var rules = new List<ProxyRule>();
        var excludes = new List<string>();
        var presetIps = new Dictionary<string, IReadOnlyList<string>>();

        JsonElement intercepts = default;
        var hasIntercepts = false;

        if (TryGetObject(root, "server", out var server))
        {
            if (TryGetObject(server, "preSetIpList", out var preset)) ReadPresetIps(preset, presetIps);
            hasIntercepts = TryGetObject(server, "intercepts", out intercepts);
        }
        else
        {
            // 自定义规则允许省略 server 包装，直接写 intercepts / preSetIpList / excludeIpList。
            if (TryGetObject(root, "preSetIpList", out var preset)) ReadPresetIps(preset, presetIps);

            if (TryGetObject(root, "intercepts", out var directIntercepts))
            {
                intercepts = directIntercepts;
                hasIntercepts = true;
            }
            else if (IsInterceptMap(root))
            {
                intercepts = root;
                hasIntercepts = true;
            }
        }

        if (hasIntercepts) ConvertIntercepts(intercepts, groupOverride, rules);

        if (TryGetObject(root, "proxy", out var proxy))
        {
            if (TryGetObject(proxy, "excludeIpList", out var exclude)) ReadExcludes(exclude, excludes);
        }
        else if (TryGetObject(root, "excludeIpList", out var directExclude))
        {
            ReadExcludes(directExclude, excludes);
        }

        return new ProxyRuleSet(rules, excludes, presetIps);
    }

    static void ConvertIntercepts(
        JsonElement intercepts,
        string? groupOverride,
        List<ProxyRule> rules)
    {
        foreach (var domainItem in intercepts.EnumerateObject())
        {
            if (IsReservedKey(domainItem.Name)) continue;
            if (domainItem.Value.ValueKind != JsonValueKind.Object) continue;

            var group = groupOverride ?? ProxyRuleGroups.Classify(domainItem.Name);

            foreach (var pathItem in domainItem.Value.EnumerateObject())
            {
                if (pathItem.Value.ValueKind != JsonValueKind.Object) continue;

                var action = pathItem.Value;
                var rule = new ProxyRule
                {
                    DomainPattern = domainItem.Name,
                    Group = group,
                    PathPattern = pathItem.Name == ".*" ? null : pathItem.Name,
                    Sni = GetString(action, "sni"),
                    VerifyHost = GetString(action, "verifyHost"),
                    Redirect = NormalizeTarget(GetString(action, "redirect")),
                    Proxy = NormalizeTarget(GetString(action, "proxy")),
                    BackupProxies = ReadTargetList(action, "backup"),
                    RequestHeaders = ReadHeaderReplacements(action, "requestReplace"),
                    ResponseHeaders = ReadHeaderReplacements(action, "responseReplace"),
                    UnVerifySsl = GetBool(action, "unVerifySsl"),
                    Description = GetString(action, "desc") ?? GetString(action, "remark"),
                };

                if (TryGetBool(action, "abort", out var abort) && abort)
                {
                    rule = CloneWithBlock(rule);
                }

                // 只保留真正有动作的规则，减少匹配开销。
                if (rule.RequiresMitm || rule.Block) rules.Add(rule);
            }
        }
    }

    static void ReadPresetIps(JsonElement preset, Dictionary<string, IReadOnlyList<string>> presetIps)
    {
        foreach (var item in preset.EnumerateObject())
        {
            var ips = ReadIpList(item.Value);
            if (ips.Count > 0) presetIps[item.Name] = ips;
        }
    }

    static void ReadExcludes(JsonElement exclude, List<string> excludes)
    {
        // DevSidecar 里 null/false 表示从排除列表移除，只有 true 才排除。
        foreach (var item in exclude.EnumerateObject())
        {
            if (item.Value.ValueKind == JsonValueKind.True) excludes.Add(item.Name);
        }
    }

    static readonly string[] reservedKeys =
    {
        "server", "proxy", "plugin", "app", "help", "intercepts",
        "preSetIpList", "excludeIpList", "compatible", "ech",
    };

    static bool IsReservedKey(string name)
    {
        foreach (var key in reservedKeys)
        {
            if (string.Equals(name, key, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    static bool IsInterceptMap(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) return false;

        var count = 0;
        foreach (var domain in root.EnumerateObject())
        {
            if (IsReservedKey(domain.Name)) continue;
            if (domain.Value.ValueKind != JsonValueKind.Object) return false;

            foreach (var path in domain.Value.EnumerateObject())
            {
                if (path.Value.ValueKind != JsonValueKind.Object &&
                    path.Value.ValueKind != JsonValueKind.Null)
                {
                    return false;
                }
            }
            count++;
        }
        return count > 0;
    }

    static ProxyRule CloneWithBlock(ProxyRule rule) => new()
    {
        DomainPattern = rule.DomainPattern,
        Group = rule.Group,
        PathPattern = rule.PathPattern,
        Block = true,
        Description = rule.Description,
    };

    static IReadOnlyDictionary<string, string?> ReadHeaderReplacements(JsonElement action, string name)
    {
        var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        if (!TryGetObject(action, name, out var replace)) return result;
        if (!TryGetObject(replace, "headers", out var headers)) return result;

        foreach (var header in headers.EnumerateObject())
        {
            if (header.Value.ValueKind != JsonValueKind.String) continue;
            var value = header.Value.GetString();
            result[header.Name] = string.IsNullOrEmpty(value) ||
                string.Equals(value, "[remove]", StringComparison.OrdinalIgnoreCase)
                    ? null
                    : value;
        }
        return result;
    }

    static IReadOnlyList<string> ReadTargetList(JsonElement action, string name)
    {
        var result = new List<string>();
        if (!action.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Array) return result;

        foreach (var item in value.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String) continue;
            var target = NormalizeTarget(item.GetString());
            if (!string.IsNullOrEmpty(target)) result.Add(target);
        }
        return result;
    }

    static IReadOnlyList<string> ReadIpList(JsonElement element)
    {
        var result = new List<string>();
        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var ip in element.EnumerateArray())
            {
                if (ip.ValueKind != JsonValueKind.String) continue;
                var value = ip.GetString();
                if (!string.IsNullOrWhiteSpace(value)) result.Add(value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var ip in element.EnumerateObject())
            {
                if (ip.Value.ValueKind == JsonValueKind.True || ip.Value.ValueKind == JsonValueKind.Object)
                {
                    result.Add(ip.Name);
                }
            }
        }
        return result;
    }

    static string? NormalizeTarget(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        value = value.Trim();
        if (value.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) return null;
        if (!value.Contains("://", StringComparison.Ordinal)) value = "https://" + value.TrimStart('/');
        return value;
    }

    static bool TryGetObject(JsonElement element, string name, out JsonElement value)
    {
        if (element.ValueKind == JsonValueKind.Object &&
            element.TryGetProperty(name, out value) &&
            value.ValueKind == JsonValueKind.Object)
        {
            return true;
        }
        value = default;
        return false;
    }

    static string? GetString(JsonElement element, string name)
    {
        if (element.ValueKind == JsonValueKind.Object &&
            element.TryGetProperty(name, out var value) &&
            value.ValueKind == JsonValueKind.String)
        {
            return value.GetString();
        }
        return null;
    }

    static bool GetBool(JsonElement element, string name) => TryGetBool(element, name, out var value) && value;

    static bool TryGetBool(JsonElement element, string name, out bool value)
    {
        if (element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var prop))
        {
            if (prop.ValueKind == JsonValueKind.True) { value = true; return true; }
            if (prop.ValueKind == JsonValueKind.False) { value = false; return true; }
        }
        value = false;
        return false;
    }
}
