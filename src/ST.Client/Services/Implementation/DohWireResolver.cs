using System;
using System.Application.Settings;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace System.Application.Services.Implementation
{
    /// <summary>
    /// RFC 8484 DNS over HTTPS（wire format）解析器。
    /// 与 <see cref="DohResolver"/> 的 JSON 接口不同，这里直接转发原始 DNS 报文，
    /// 因此可以完整保留 CNAME、AAAA、EDNS 等信息，供本地 DNS 代理和 UDP 中继复用。
    /// </summary>
    public static class DohWireResolver
    {
        const int MaxDnsMessageLength = 65535;

        static readonly HttpClient httpClient = new(new HttpClientHandler
        {
            AutomaticDecompression = System.Net.DecompressionMethods.GZip | System.Net.DecompressionMethods.Deflate,
        })
        {
            Timeout = TimeSpan.FromSeconds(6),
            MaxResponseContentBufferSize = MaxDnsMessageLength,
        };

        public static string GetEndpoint()
        {
            var endpoint = ProxySettings.DohWireEndpoint.Value?.Trim();
            if (string.IsNullOrEmpty(endpoint))
            {
                endpoint = ProxySettings.DefaultDohWireEndpoint;
            }
            return endpoint;
        }

        public static bool IsAcceptableEndpoint(string? endpoint)
            => Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) &&
               string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// 发送原始 DNS 查询。失败时返回 null，由调用方决定是否回退系统 DNS。
        /// </summary>
        public static Task<byte[]?> QueryAsync(byte[] query, CancellationToken cancellationToken = default)
            => QueryAsync(query, null, cancellationToken);

        /// <summary>
        /// 发送原始 DNS 查询，可指定 DevSidecar dns.mapping 选出的 DoH 接口。
        /// </summary>
        public static async Task<byte[]?> QueryAsync(
            byte[] query,
            string? endpointOverride,
            CancellationToken cancellationToken = default)
        {
            if (query == null || query.Length < 12 || query.Length > MaxDnsMessageLength) return null;

            var endpoint = string.IsNullOrWhiteSpace(endpointOverride) ? GetEndpoint() : endpointOverride!.Trim();
            if (!IsAcceptableEndpoint(endpoint))
            {
                ProxyDiagnostics.Warn("DoH", $"拒绝非 HTTPS DoH 地址: {endpoint}");
                return null;
            }

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
                var content = new ByteArrayContent(query);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
                request.Content = content;
                request.Headers.TryAddWithoutValidation("Accept", "application/dns-message");

                using var response = await httpClient
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                    .ConfigureAwait(false);
                response.EnsureSuccessStatusCode();

                var length = response.Content.Headers.ContentLength;
                if (length.HasValue && (length.Value < 12 || length.Value > MaxDnsMessageLength))
                {
                    ProxyDiagnostics.Warn("DoH", $"DoH 响应长度异常: {length.Value}");
                    return null;
                }

                var data = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                if (data.Length < 12 || data.Length > MaxDnsMessageLength)
                {
                    ProxyDiagnostics.Warn("DoH", $"DoH 响应无效: {data.Length} 字节");
                    return null;
                }

                // 少数 DoH 服务会改写 ID；客户端按原查询 ID 匹配，这里强制修正。
                if (data[0] != query[0] || data[1] != query[1])
                {
                    data[0] = query[0];
                    data[1] = query[1];
                }

                DnsProxyServer.OnDohSuccess();
                return data;
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
            {
                ProxyDiagnostics.Warn("DoH", $"DoH wire 查询失败: {ex.Message}");
                return null;
            }
        }
    }
}
