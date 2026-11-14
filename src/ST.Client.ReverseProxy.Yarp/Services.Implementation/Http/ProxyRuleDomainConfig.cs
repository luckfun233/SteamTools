using System.Application.Models;
using System.Application.ProxyRules;
using System.Collections.Concurrent;
using System.Net;
using System.Runtime.CompilerServices;

namespace System.Application.Services.Implementation;

/// <summary>
/// 把 DevSidecar 规则映射为 YARP 可消费的域名配置：
/// <para>- proxy 规则：上游连接切换到第三方反代，Host/路径保持原站点，避免破坏签名链接</para>
/// <para>- sni / verifyHost 规则：改写上游 TLS SNI</para>
/// <para>- 预置 IP：作为连接地址，跳过被污染的 DNS</para>
/// </summary>
sealed class ProxyRuleDomainConfig : IDomainConfig
{
    static readonly ConditionalWeakTable<ProxyRule, ConcurrentDictionary<(IDomainConfig BaseConfig, bool AllowThirdParty), ProxyRuleDomainConfig>> cache = new();

    /// <summary>
    /// 同一条规则复用同一个配置实例，避免 YARP 的连接池按配置对象缓存后每个请求都重建。
    /// </summary>
    public static IDomainConfig Get(ProxyRule rule, IDomainConfig baseConfig, bool allowThirdParty)
    {
        var map = cache.GetOrCreateValue(rule);
        return map.GetOrAdd((baseConfig, allowThirdParty), key => new ProxyRuleDomainConfig(rule, key.BaseConfig, key.AllowThirdParty));
    }

    ProxyRuleDomainConfig(ProxyRule rule, IDomainConfig baseConfig, bool allowThirdParty)
    {
        var thirdParty = allowThirdParty && !string.IsNullOrEmpty(rule.Proxy);
        var proxyHost = thirdParty ? GetHost(rule.Proxy!) : null;
        var sni = rule.Sni;
        var verifyHost = rule.VerifyHost;

        TlsSni = !rule.RemoveSni &&
                 (thirdParty ||
                  !string.IsNullOrEmpty(sni) ||
                  !string.IsNullOrEmpty(verifyHost) ||
                  baseConfig.TlsSni);
        TlsSniPattern = rule.RemoveSni
            ? null
            : sni ?? verifyHost ?? proxyHost ?? baseConfig.TlsSniPattern;
        TlsIgnoreNameMismatch = rule.UnVerifySsl ||
                                thirdParty ||
                                !string.IsNullOrEmpty(sni) ||
                                baseConfig.TlsIgnoreNameMismatch;

        ForwardDestination = proxyHost ?? baseConfig.ForwardDestination;

        IPAddress? presetIp = null;
        foreach (var item in rule.PresetIps)
        {
            if (IPAddress.TryParse(item, out var ip) && !IPAddress.IsLoopback(ip) && !ip.Equals(IPAddress.Any))
            {
                presetIp = ip;
                break;
            }
        }
        IPAddress = presetIp ?? baseConfig.IPAddress;

        Timeout = baseConfig.Timeout;
        Destination = thirdParty ? null : baseConfig.Destination;
        UserAgent = baseConfig.UserAgent;
        Response = baseConfig.Response;
        Items = baseConfig.Items;
    }

    public bool TlsSni { get; }

    public string? TlsSniPattern { get; }

    public bool TlsIgnoreNameMismatch { get; }

    public IPAddress? IPAddress { get; }

    public string? ForwardDestination { get; }

    public TimeSpan? Timeout { get; }

    public Uri? Destination { get; }

    public string? UserAgent { get; }

    public IResponseConfig? Response { get; }

    public IReadOnlyDictionary<DomainPattern, IDomainConfig>? Items { get; }

    static string? GetHost(string target)
    {
        if (string.IsNullOrWhiteSpace(target)) return null;
        if (!target.Contains("://", StringComparison.Ordinal))
        {
            target = "https://" + target.TrimStart('/');
        }
        return Uri.TryCreate(target, UriKind.Absolute, out var uri) ? uri.Host : null;
    }
}
