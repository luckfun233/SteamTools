using System.Net;
using System.Text.Json;
using NetAccel.Core.Logging;
using NetAccel.Core.Models;

namespace NetAccel.Core.Net;

/// <summary>
/// 最小 DoH（DNS over HTTPS）解析器，使用常见的 RFC 8484 JSON 接口。
/// 请求强制绕过系统代理，避免“系统代理指向本机代理 → DoH 又走本机代理”的递归。
/// </summary>
public sealed class DohResolver : IDisposable
{
    readonly AccelSettings settings;
    readonly IAccelLogger log;
    readonly HttpClient httpClient;

    readonly Dictionary<string, CacheItem> cache = new(StringComparer.OrdinalIgnoreCase);
    readonly object cacheSync = new();

    public DohResolver(AccelSettings settings, IAccelLogger? logger = null)
    {
        this.settings = settings;
        log = logger ?? NullLogger.Instance;

        httpClient = new HttpClient(new SocketsHttpHandler
        {
            UseProxy = false,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        })
        {
            Timeout = TimeSpan.FromSeconds(6),
        };
    }

    public async Task<IReadOnlyList<IPAddress>> ResolveAsync(
        string host,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(host)) return Array.Empty<IPAddress>();
        if (IPAddress.TryParse(host, out var literal)) return new[] { literal };
        if (!settings.EnableDoh) return Array.Empty<IPAddress>();

        lock (cacheSync)
        {
            if (cache.TryGetValue(host, out var cached) && cached.ExpireAt > DateTime.UtcNow)
            {
                return cached.Addresses;
            }
        }

        var endpoint = settings.DohEndpoint?.Trim();
        if (string.IsNullOrEmpty(endpoint) ||
            !Uri.TryCreate(endpoint, UriKind.Absolute, out var endpointUri) ||
            !string.Equals(endpointUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            log.Warn("DoH", $"拒绝非 HTTPS DoH 地址: {endpoint}");
            return Array.Empty<IPAddress>();
        }

        try
        {
            var (addresses, ttl) = await QueryJsonAsync(endpoint, host, cancellationToken).ConfigureAwait(false);
            Store(host, addresses, ttl);
            if (addresses.Count > 0)
            {
                log.Info("DoH", $"{host} -> {string.Join(",", addresses)}");
            }
            return addresses;
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            log.Warn("DoH", $"解析 {host} 失败: {ex.Message}");
            Store(host, Array.Empty<IPAddress>(), TimeSpan.FromSeconds(15));
            return Array.Empty<IPAddress>();
        }
    }

    void Store(string host, IReadOnlyList<IPAddress> addresses, TimeSpan ttl)
    {
        lock (cacheSync)
        {
            // 简单上限，避免大量随机域名把内存吃满。
            if (cache.Count > 4096) cache.Clear();
            cache[host] = new CacheItem(addresses, DateTime.UtcNow.Add(ttl));
        }
    }

    public void ClearCache()
    {
        lock (cacheSync) cache.Clear();
    }

    async Task<(IReadOnlyList<IPAddress> Addresses, TimeSpan Ttl)> QueryJsonAsync(
        string endpoint,
        string host,
        CancellationToken cancellationToken)
    {
        var separator = endpoint.Contains('?', StringComparison.Ordinal) ? "&" : "?";
        var url = endpoint + separator + "name=" + Uri.EscapeDataString(host) + "&type=A";

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("Accept", "application/dns-json");
        using var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ParseJsonResponse(json);
    }

    /// <summary>解析 dns-json 响应，供单元测试直接调用。</summary>
    public static (IReadOnlyList<IPAddress> Addresses, TimeSpan Ttl) ParseJsonResponse(string json)
    {
        var result = new List<IPAddress>();
        var ttl = TimeSpan.FromMinutes(5);

        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("Answer", out var answers) ||
            answers.ValueKind != JsonValueKind.Array)
        {
            return (result, TimeSpan.FromSeconds(30));
        }

        var minTtl = int.MaxValue;
        foreach (var answer in answers.EnumerateArray())
        {
            if (answer.ValueKind != JsonValueKind.Object) continue;
            if (!answer.TryGetProperty("type", out var type) || type.ValueKind != JsonValueKind.Number) continue;
            if (type.GetInt32() != 1) continue;
            if (!answer.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.String) continue;
            if (!IPAddress.TryParse(data.GetString(), out var ip)) continue;
            if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;

            result.Add(ip);

            if (answer.TryGetProperty("TTL", out var ttlElement) &&
                ttlElement.ValueKind == JsonValueKind.Number &&
                ttlElement.TryGetInt32(out var value))
            {
                minTtl = Math.Min(minTtl, value);
            }
        }

        if (minTtl != int.MaxValue)
        {
            ttl = TimeSpan.FromSeconds(Math.Clamp(minTtl, 30, 3600));
        }

        return (result, ttl);
    }

    public void Dispose() => httpClient.Dispose();

    sealed class CacheItem
    {
        public CacheItem(IReadOnlyList<IPAddress> addresses, DateTime expireAt)
        {
            Addresses = addresses;
            ExpireAt = expireAt;
        }

        public IReadOnlyList<IPAddress> Addresses { get; }
        public DateTime ExpireAt { get; }
    }
}
