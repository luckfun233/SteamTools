using System;
using System.Application.Settings;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace System.Application.Services.Implementation
{
    /// <summary>
    /// 最小 DoH（DNS over HTTPS）解析器，使用 RFC 8484 常见的 JSON 接口。
    /// 只负责拿到干净 IP，不解决 IP 黑洞或 SNI 阻断。
    /// </summary>
    public static class DohResolver
    {
        static readonly HttpClient httpClient = new()
        {
            Timeout = TimeSpan.FromSeconds(6),
        };

        static readonly ConcurrentDictionary<string, CacheItem> cache = new(StringComparer.OrdinalIgnoreCase);

        public static async Task<IReadOnlyList<IPAddress>> ResolveAsync(
            string host,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(host)) return Array.Empty<IPAddress>();
            if (IPAddress.TryParse(host, out var literal)) return new[] { literal };
            if (!ProxySettings.EnableDoh.Value) return Array.Empty<IPAddress>();

            if (cache.TryGetValue(host, out var cached) && cached.ExpireAt > DateTime.UtcNow)
            {
                return cached.Addresses;
            }

            var endpoint = ProxySettings.DohEndpoint.Value?.Trim();
            if (string.IsNullOrEmpty(endpoint) ||
                !Uri.TryCreate(endpoint, UriKind.Absolute, out var endpointUri) ||
                !string.Equals(endpointUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                ProxyDiagnostics.Warn("DoH", $"拒绝非 HTTPS DoH 地址: {endpoint}");
                return Array.Empty<IPAddress>();
            }

            try
            {
                var addresses = await QueryAsync(endpoint, host, cancellationToken).ConfigureAwait(false);
                if (addresses.Count > 0)
                {
                    cache[host] = new CacheItem(addresses, DateTime.UtcNow.AddSeconds(300));
                    ProxyDiagnostics.Info("DoH", $"{host} -> {string.Join(",", addresses)}");
                }
                else
                {
                    cache[host] = new CacheItem(Array.Empty<IPAddress>(), DateTime.UtcNow.AddSeconds(30));
                }
                return addresses;
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
            {
                ProxyDiagnostics.Warn("DoH", $"解析 {host} 失败: {ex.Message}");
                cache[host] = new CacheItem(Array.Empty<IPAddress>(), DateTime.UtcNow.AddSeconds(15));
                return Array.Empty<IPAddress>();
            }
        }

        public static void ClearCache() => cache.Clear();

        static async Task<IReadOnlyList<IPAddress>> QueryAsync(
            string endpoint,
            string host,
            CancellationToken cancellationToken)
        {
            var separator = endpoint.Contains("?", StringComparison.Ordinal) ? "&" : "?";
            var url = endpoint + separator + "name=" + Uri.EscapeDataString(host) + "&type=A";

            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.TryAddWithoutValidation("Accept", "application/dns-json");
            using var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);

            var result = new List<IPAddress>();
            if (!doc.RootElement.TryGetProperty("Answer", out var answers) ||
                answers.ValueKind != JsonValueKind.Array)
            {
                return result;
            }

            foreach (var answer in answers.EnumerateArray())
            {
                if (answer.ValueKind != JsonValueKind.Object) continue;
                if (!answer.TryGetProperty("type", out var type) || type.GetInt32() != 1) continue;
                if (!answer.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.String) continue;
                if (IPAddress.TryParse(data.GetString(), out var ip)) result.Add(ip);
            }

            return result;
        }

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
}
