using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using NetAccel.Core.Logging;
using NetAccel.Core.Models;

namespace NetAccel.Core.Net;

/// <summary>
/// DoH（DNS over HTTPS）解析器。依次尝试主地址与备用地址；
/// 每个地址先走 JSON 接口，失败再走 RFC 8484 二进制接口。
/// 请求强制绕过系统代理，避免“系统代理指向本机代理 → DoH 又走本机代理”的递归。
/// </summary>
public sealed class DohResolver : IDisposable
{
    const ushort TypeA = 1;
    const ushort TypeAaaa = 28;

    readonly AccelSettings settings;
    readonly IAccelLogger log;
    readonly HttpClient httpClient;

    readonly Dictionary<string, CacheItem> cache = new(StringComparer.OrdinalIgnoreCase);
    readonly object cacheSync = new();

    public DohResolver(AccelSettings settings, IAccelLogger? logger = null)
    {
        this.settings = settings;
        log = logger ?? NullLogger.Instance;

        var handler = new SocketsHttpHandler
        {
            ConnectTimeout = TimeSpan.FromSeconds(5),
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            UseProxy = false,
        };

        if (settings.EnableUpstreamRelay && settings.DohViaRelay)
        {
            var scheme = settings.RelayType == RelayType.Http ? "http" : "socks5";
            var proxy = new WebProxy($"{scheme}://{settings.RelayHost}:{settings.RelayPort}");
            if (!string.IsNullOrEmpty(settings.RelayUserName))
            {
                proxy.Credentials = new NetworkCredential(settings.RelayUserName, settings.RelayPassword);
            }
            handler.Proxy = proxy;
            handler.UseProxy = true;
        }

        httpClient = new HttpClient(handler)
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

        var endpoints = EnumerateEndpoints();
        if (endpoints.Count == 0)
        {
            log.Warn("DoH", "没有可用的 HTTPS DoH 地址");
            return Array.Empty<IPAddress>();
        }

        foreach (var endpoint in endpoints)
        {
            try
            {
                var (addresses, ttl) = await QueryEndpointAsync(endpoint, host, cancellationToken)
                    .ConfigureAwait(false);
                if (addresses.Count > 0)
                {
                    Store(host, addresses, ttl);
                    log.Info("DoH", $"{host} -> {string.Join(",", addresses)}（{endpoint}）");
                    return addresses;
                }
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
            {
                log.Warn("DoH", $"{endpoint} 解析 {host} 失败: {ex.Message}");
            }
        }

        Store(host, Array.Empty<IPAddress>(), TimeSpan.FromSeconds(15));
        return Array.Empty<IPAddress>();
    }

    public IReadOnlyList<string> EnumerateEndpoints()
    {
        var result = new List<string>();

        void Add(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return;
            foreach (var item in value.Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var endpoint = item.Trim();
                if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) ||
                    !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!result.Contains(endpoint, StringComparer.OrdinalIgnoreCase)) result.Add(endpoint);
            }
        }

        Add(settings.DohEndpoint);
        Add(settings.DohFallbackEndpoints);
        return result;
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

    async Task<(IReadOnlyList<IPAddress> Addresses, TimeSpan Ttl)> QueryEndpointAsync(
        string endpoint,
        string host,
        CancellationToken cancellationToken)
    {
        try
        {
            var (addresses, ttl) = await QueryJsonAsync(endpoint, host, TypeA, cancellationToken).ConfigureAwait(false);
            if (addresses.Count > 0) return (addresses, ttl);

            // 没有 A 记录时再尝试 AAAA，保证 IPv6-only 网络也能用。
            return await QueryJsonAsync(endpoint, host, TypeAaaa, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            log.Warn("DoH", $"JSON 接口失败，改试二进制接口: {endpoint}: {ex.Message}");
            var (addresses, ttl) = await QueryWireAsync(endpoint, host, TypeA, cancellationToken).ConfigureAwait(false);
            if (addresses.Count > 0) return (addresses, ttl);
            return await QueryWireAsync(endpoint, host, TypeAaaa, cancellationToken).ConfigureAwait(false);
        }
    }

    async Task<(IReadOnlyList<IPAddress> Addresses, TimeSpan Ttl)> QueryJsonAsync(
        string endpoint,
        string host,
        ushort type,
        CancellationToken cancellationToken)
    {
        var separator = endpoint.Contains('?', StringComparison.Ordinal) ? "&" : "?";
        var typeName = type == TypeAaaa ? "AAAA" : "A";
        var url = endpoint + separator + "name=" + Uri.EscapeDataString(host) + "&type=" + typeName;

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("Accept", "application/dns-json");
        using var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ParseJsonResponse(json, type);
    }

    async Task<(IReadOnlyList<IPAddress> Addresses, TimeSpan Ttl)> QueryWireAsync(
        string endpoint,
        string host,
        ushort type,
        CancellationToken cancellationToken)
    {
        var query = BuildWireQuery(host, type);
        using var content = new ByteArrayContent(query);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = content };
        request.Headers.TryAddWithoutValidation("Accept", "application/dns-message");

        using var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        return ParseWireResponse(bytes);
    }

    /// <summary>构造 RFC 8484 的 DNS 查询报文（单问题、RD=1）。</summary>
    public static byte[] BuildWireQuery(string host, ushort type = TypeA)
    {
        var id = (ushort)Random.Shared.Next(0, 65536);
        var buffer = new List<byte>(64)
        {
            (byte)(id >> 8), (byte)(id & 0xFF),
            0x01, 0x00, // flags: standard query, recursion desired
            0x00, 0x01, // qdcount
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };

        foreach (var label in host.TrimEnd('.').Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            if (bytes.Length is 0 or > 63) throw new InvalidDataException("域名标签长度非法");
            buffer.Add((byte)bytes.Length);
            buffer.AddRange(bytes);
        }

        buffer.Add(0); // 根
        buffer.Add((byte)(type >> 8));
        buffer.Add((byte)(type & 0xFF));
        buffer.Add(0x00);
        buffer.Add(0x01); // IN
        return buffer.ToArray();
    }

    /// <summary>解析 DNS 响应报文，返回 A/AAAA 地址与最小 TTL。</summary>
    public static (IReadOnlyList<IPAddress> Addresses, TimeSpan Ttl) ParseWireResponse(byte[] data)
    {
        var result = new List<IPAddress>();
        var ttl = TimeSpan.FromMinutes(5);

        if (data.Length < 12) return (result, TimeSpan.FromSeconds(30));

        int qdCount = (data[4] << 8) | data[5];
        int anCount = (data[6] << 8) | data[7];
        var pos = 12;

        for (var i = 0; i < qdCount && pos < data.Length; i++)
        {
            pos = SkipName(data, pos);
            pos += 4; // type + class
        }

        var minTtl = int.MaxValue;
        for (var i = 0; i < anCount && pos + 10 <= data.Length; i++)
        {
            pos = SkipName(data, pos);
            if (pos + 10 > data.Length) break;

            var type = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            pos += 2; // class
            var recordTtl = (data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
            pos += 4;
            var length = (data[pos] << 8) | data[pos + 1];
            pos += 2;

            if (pos + length > data.Length) break;

            if (type == TypeA && length == 4)
            {
                result.Add(new IPAddress(data.AsSpan(pos, 4)));
                minTtl = Math.Min(minTtl, recordTtl);
            }
            else if (type == TypeAaaa && length == 16)
            {
                result.Add(new IPAddress(data.AsSpan(pos, 16)));
                minTtl = Math.Min(minTtl, recordTtl);
            }

            pos += length;
        }

        if (minTtl != int.MaxValue) ttl = TimeSpan.FromSeconds(Math.Clamp(minTtl, 30, 3600));
        return (result, ttl);
    }

    static int SkipName(byte[] data, int pos)
    {
        while (pos < data.Length)
        {
            var length = data[pos];
            if (length == 0) return pos + 1;
            if ((length & 0xC0) == 0xC0) return pos + 2; // 压缩指针
            pos += 1 + length;
        }
        return pos;
    }

    /// <summary>解析 dns-json 响应，供单元测试直接调用（默认 A 记录）。</summary>
    public static (IReadOnlyList<IPAddress> Addresses, TimeSpan Ttl) ParseJsonResponse(string json)
        => ParseJsonResponse(json, TypeA);

    public static (IReadOnlyList<IPAddress> Addresses, TimeSpan Ttl) ParseJsonResponse(string json, ushort type)
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
            if (!answer.TryGetProperty("type", out var typeElement) || typeElement.ValueKind != JsonValueKind.Number)
                continue;
            if (typeElement.GetInt32() != type) continue;
            if (!answer.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.String) continue;
            if (!IPAddress.TryParse(data.GetString(), out var ip)) continue;
            if (type == TypeA && ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
            if (type == TypeAaaa && ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6) continue;

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
