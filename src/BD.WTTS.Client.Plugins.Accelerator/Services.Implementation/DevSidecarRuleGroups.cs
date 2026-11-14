using System.Net.Http;
using System.Text.Json;

// ReSharper disable once CheckNamespace
namespace BD.WTTS.Services.Implementation;

/// <summary>
/// 把 DevSidecar 的 <c>remote_config.json5</c> 转换成客户端内置加速组。
/// <para>只实现能在当前反向代理（YARP）里表达的子集：按域名匹配、伪装 SNI、忽略上游证书校验、上游反代、预置 IP。</para>
/// <para>路径级规则（例如只把 release/archive 重定向到镜像站）不会转换：YARP 的域名规则是整域生效，
/// 直接应用会把私有仓库请求也送到镜像站，属于凭据泄露风险。</para>
/// </summary>
public static class DevSidecarRuleGroups
{
    public const string DefaultConfigUrl = "https://ds-official-config.bestar.de5.net/remote_config.json5";

    public const string GroupName = "DevSidecar 规则（远程同步）";

    static readonly HttpClient httpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(20),
    };

    public static string CacheFilePath => Path.Combine(
        BD.WTTS.Plugins.Plugin.Instance.AppDataDirectory,
        "devsidecar_remote_config.json5");

    public static async Task<IReadOnlyList<AccelerateProjectGroupDTO>> LoadAsync(
        string? url,
        bool syncFromRemote,
        CancellationToken cancellationToken = default)
    {
        url = string.IsNullOrWhiteSpace(url) ? DefaultConfigUrl : url.Trim();

        if (syncFromRemote && IsHttps(url))
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.TryAddWithoutValidation("User-Agent", "WattToolkit-DevSidecarCompat/1.0");
                using var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();
                var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(json))
                {
                    await File.WriteAllTextAsync(CacheFilePath, json, cancellationToken).ConfigureAwait(false);
                    return Parse(json);
                }
            }
            catch (Exception ex)
            {
                Log.Warn(nameof(DevSidecarRuleGroups), ex, "同步 DevSidecar 配置失败，回退本地缓存");
            }
        }

        try
        {
            if (File.Exists(CacheFilePath))
            {
                var json = await File.ReadAllTextAsync(CacheFilePath, cancellationToken).ConfigureAwait(false);
                return Parse(json);
            }
        }
        catch (Exception ex)
        {
            Log.Warn(nameof(DevSidecarRuleGroups), ex, "读取 DevSidecar 缓存失败");
        }

        return Array.Empty<AccelerateProjectGroupDTO>();
    }

    /// <summary>
    /// 解析 DevSidecar 配置。解析失败返回空集合，不影响内置规则。
    /// </summary>
    public static IReadOnlyList<AccelerateProjectGroupDTO> Parse(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions
            {
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip,
                MaxDepth = 64,
            });

            var items = new List<AccelerateProjectDTO>();
            if (!TryGetObject(document.RootElement, "server", out var server) ||
                !TryGetObject(server, "intercepts", out var intercepts))
            {
                return Array.Empty<AccelerateProjectGroupDTO>();
            }

            var presetIps = ReadPresetIps(server);
            var order = 0L;

            foreach (var domainItem in intercepts.EnumerateObject())
            {
                var domain = domainItem.Name;
                if (domainItem.Value.ValueKind != JsonValueKind.Object) continue;
                if (!IsSupportedDomain(domain)) continue;

                foreach (var pathItem in domainItem.Value.EnumerateObject())
                {
                    if (pathItem.Value.ValueKind != JsonValueKind.Object) continue;

                    // 路径级规则无法在 YARP 域名配置中安全表达，跳过。
                    if (pathItem.Name != ".*") continue;

                    var action = pathItem.Value;
                    var sni = GetString(action, "sni");
                    var proxy = NormalizeHttps(GetString(action, "proxy"));
                    if (string.IsNullOrEmpty(sni) && string.IsNullOrEmpty(proxy)) continue;

                    order++;
                    var item = new AccelerateProjectDTO
                    {
                        Id = CreateId("DevSidecar." + domain),
                        Name = domain,
                        MatchDomainNames = domain,
                        ListenDomainNames = domain,
                        Port = 443,
                        FakeServerName = sni,
                        IgnoreSSLCertVerification = true,
                        Order = order,
                    };

                    if (!string.IsNullOrEmpty(proxy))
                    {
                        item.ForwardDomainNames = proxy;
                        item.ProxyType = ProxyType.ServerAccelerate;
                    }
                    else if (presetIps.TryGetValue(domain, out var ip))
                    {
                        item.ForwardDomainNames = ip;
                        item.ProxyType = ProxyType.Local;
                    }
                    else
                    {
                        item.ForwardDomainNames = domain;
                        item.ProxyType = ProxyType.Local;
                    }

                    items.Add(item);
                }
            }

            if (items.Count == 0)
            {
                return Array.Empty<AccelerateProjectGroupDTO>();
            }

            return new[]
            {
                new AccelerateProjectGroupDTO
                {
                    Name = GroupName,
                    Order = 950,
                    Items = items,
                },
            };
        }
        catch (Exception ex)
        {
            Log.Warn(nameof(DevSidecarRuleGroups), ex, "解析 DevSidecar 配置失败");
            return Array.Empty<AccelerateProjectGroupDTO>();
        }
    }

    static Dictionary<string, string> ReadPresetIps(JsonElement server)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!TryGetObject(server, "preSetIpList", out var preset)) return result;

        foreach (var item in preset.EnumerateObject())
        {
            if (item.Value.ValueKind != JsonValueKind.Array) continue;
            foreach (var ip in item.Value.EnumerateArray())
            {
                if (ip.ValueKind != JsonValueKind.String) continue;
                var value = ip.GetString();
                if (!string.IsNullOrWhiteSpace(value) &&
                    System.Net.IPAddress.TryParse(value, out _))
                {
                    result[item.Name] = value!;
                    break;
                }
            }
        }

        return result;
    }

    /// <summary>
    /// YARP 的域名匹配支持精确域名和通配符，不支持正则，含正则元字符的规则直接跳过。
    /// </summary>
    static bool IsSupportedDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return false;
        foreach (var c in domain)
        {
            switch (c)
            {
                case '^':
                case '$':
                case '(':
                case ')':
                case '[':
                case ']':
                case '|':
                case '\\':
                    return false;
            }
        }
        return true;
    }

    static bool IsHttps(string url)
        => Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
           string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

    static string? NormalizeHttps(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        value = value.Trim();
        if (value.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) return null;
        if (!value.Contains("://", StringComparison.Ordinal)) value = "https://" + value.Trim('/');
        return IsHttps(value) ? value : null;
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
        => element.ValueKind == JsonValueKind.Object &&
           element.TryGetProperty(name, out var value) &&
           value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    static Guid CreateId(string value)
    {
        using var md5 = System.Security.Cryptography.MD5.Create();
        return new Guid(md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(value)));
    }
}
