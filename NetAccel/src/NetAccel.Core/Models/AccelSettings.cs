using NetAccel.Core.Rules;
using NetAccel.Core.Tls;

namespace NetAccel.Core.Models;

/// <summary>
/// 独立加速器的全部可持久化设置。所有数值在使用前都会经过 <see cref="Normalize"/> 修正，
/// 避免手改配置文件导致监听端口非法、分片参数溢出等问题。
/// </summary>
public sealed class AccelSettings
{
    public const string DefaultFragmentDomains =
        "github.com;*.githubusercontent.com;*.githubassets.com;github.dev;huggingface.co;*.huggingface.co;*.hf.co;" +
        "pixiv.net;*.pixiv.net;*.pixiv.org;pximg.net;*.pximg.net;*.fanbox.cc";

    public const string DefaultRewriteDomains =
        "github.com;api.github.com;github.githubassets.com;avatars.githubusercontent.com;camo.githubusercontent.com;" +
        "collector.github.com;raw.githubusercontent.com;gist.githubusercontent.com;objects.githubusercontent.com;" +
        "release-assets.githubusercontent.com;user-images.githubusercontent.com;private-user-images.githubusercontent.com;" +
        "media.githubusercontent.com";

    // ---- 监听 / 启动 ----
    public bool EnableSocks5 { get; set; } = true;
    public int Socks5Port { get; set; } = 8868;
    public bool EnableHttp { get; set; } = true;
    public int HttpPort { get; set; } = 8869;
    public string ListenAddress { get; set; } = "127.0.0.1";
    public bool AutoStartProxy { get; set; } = false;
    public bool SetSystemProxy { get; set; } = false;
    public bool BypassLocalhost { get; set; } = true;

    // ---- 规则 ----
    public bool EnableRemoteRules { get; set; } = true;
    public string RemoteRuleUrl { get; set; } = DevSidecarConfigLoader.DefaultConfigUrl;
    public bool SyncRemoteRulesOnStart { get; set; } = false;
    public string EnabledRuleGroups { get; set; } = ProxyRuleGroups.DefaultEnabled;
    public bool EnableCustomRules { get; set; } = true;

    /// <summary>启用内置的 GitHub / Pixiv 预置 IP，不依赖远程规则。</summary>
    public bool EnableBuiltInRules { get; set; } = true;

    // ---- SNI 分片 ----
    public bool EnableSniFragment { get; set; } = true;
    public TlsFragmentStrategy FragmentStrategy { get; set; } = TlsFragmentStrategy.Auto;
    public int FragmentChunkSize { get; set; } = 64;
    public int SplitPieces { get; set; } = 3;
    public int FragmentDelayMs { get; set; } = 10;
    public int FragmentJitterMs { get; set; } = 0;
    public bool EnableFragmentFallback { get; set; } = true;
    public int FallbackProbeMs { get; set; } = 1200;
    public int FallbackCacheMinutes { get; set; } = 10;
    public int MaxClientHelloBytes { get; set; } = 16384;
    public int FirstPayloadTimeoutMs { get; set; } = 300;
    public string FragmentDomains { get; set; } = DefaultFragmentDomains;
    public bool OnlyFragmentTls { get; set; } = true;

    // ---- SNI 改写 ----
    public bool EnableSniRewrite { get; set; } = false;
    public string SniRewriteHost { get; set; } = "baidu.com";
    public string RewriteDomains { get; set; } = DefaultRewriteDomains;

    // ---- DNS ----
    public bool EnableDoh { get; set; } = true;
    public string DohEndpoint { get; set; } = "https://dns.alidns.com/resolve";

    /// <summary>主 DoH 失败后依次尝试的备用地址，分号分隔。</summary>
    public string DohFallbackEndpoints { get; set; } =
        "https://dns.google/resolve;https://cloudflare-dns.com/dns-query";

    public bool DohFallbackToSystem { get; set; } = true;

    /// <summary>DoH 请求通过上游中继发送，适合直连 DoH 被阻断但中继可用的网络。</summary>
    public bool DohViaRelay { get; set; } = false;

    // ---- 上游中继 ----
    public bool EnableUpstreamRelay { get; set; } = false;
    public RelayType RelayType { get; set; } = RelayType.Socks5;
    public string RelayHost { get; set; } = "127.0.0.1";
    public int RelayPort { get; set; } = 7890;
    public string RelayUserName { get; set; } = string.Empty;
    public string RelayPassword { get; set; } = string.Empty;
    public string RelayDomains { get; set; } = string.Empty;

    // ---- 诊断 ----
    public bool EnableDiagnostics { get; set; } = true;
    public int DiagnosticsMinimumLevel { get; set; } = 0;
    public bool DiagnosticsIncludeHost { get; set; } = true;
    public int DiagnosticsRetentionDays { get; set; } = 7;
    public int DiagnosticsMaxFileSizeKB { get; set; } = 4096;

    public AccelSettings Clone() => (AccelSettings)MemberwiseClone();

    /// <summary>
    /// 用另一份设置覆盖当前实例的所有可写属性。
    /// 这样日志、代理服务持有的引用不会失效，恢复默认值时无需重建整个服务。
    /// </summary>
    public void CopyFrom(AccelSettings other)
    {
        foreach (var property in typeof(AccelSettings).GetProperties())
        {
            if (!property.CanWrite) continue;
            property.SetValue(this, property.GetValue(other));
        }
    }

    /// <summary>
    /// 修正非法值并返回是否有改动。端口冲突不在这里处理，由启动服务时报告。
    /// </summary>
    public bool Normalize()
    {
        var changed = false;

        changed |= ClampProp(Socks5Port, 1, 65535, 8868, v => Socks5Port = v);
        changed |= ClampProp(HttpPort, 1, 65535, 8869, v => HttpPort = v);
        if (EnableSocks5 && EnableHttp && Socks5Port == HttpPort)
        {
            HttpPort = Socks5Port == 65535 ? Socks5Port - 1 : Socks5Port + 1;
            changed = true;
        }

        changed |= FixProp(ListenAddress, "127.0.0.1", v => ListenAddress = v);
        changed |= FixProp(RemoteRuleUrl, DevSidecarConfigLoader.DefaultConfigUrl, v => RemoteRuleUrl = v);
        changed |= FixProp(EnabledRuleGroups, ProxyRuleGroups.DefaultEnabled, v => EnabledRuleGroups = v);
        changed |= FixProp(SniRewriteHost, "baidu.com", v => SniRewriteHost = v);
        changed |= FixProp(DohEndpoint, "https://dns.alidns.com/resolve", v => DohEndpoint = v);
        changed |= FixProp(RelayHost, "127.0.0.1", v => RelayHost = v);

        if (!TryNormalizeListenAddress(ListenAddress, out var listenAddress))
        {
            ListenAddress = "127.0.0.1";
            changed = true;
        }
        else if (!string.Equals(listenAddress, ListenAddress, StringComparison.Ordinal))
        {
            ListenAddress = listenAddress;
            changed = true;
        }

        changed |= ClampProp(FragmentChunkSize, 1, 4096, 64, v => FragmentChunkSize = v);
        changed |= ClampProp(SplitPieces, 2, 8, 3, v => SplitPieces = v);
        changed |= ClampProp(FragmentDelayMs, 0, 5000, 10, v => FragmentDelayMs = v);
        changed |= ClampProp(FragmentJitterMs, 0, 5000, 0, v => FragmentJitterMs = v);
        changed |= ClampProp(FallbackProbeMs, 100, 10000, 1200, v => FallbackProbeMs = v);
        changed |= ClampProp(FallbackCacheMinutes, 1, 1440, 10, v => FallbackCacheMinutes = v);
        changed |= ClampProp(MaxClientHelloBytes, 1024, 65536, 16384, v => MaxClientHelloBytes = v);
        changed |= ClampProp(FirstPayloadTimeoutMs, 50, 5000, 300, v => FirstPayloadTimeoutMs = v);
        changed |= ClampProp(RelayPort, 1, 65535, 7890, v => RelayPort = v);
        changed |= ClampProp(DiagnosticsMinimumLevel, 0, 2, 0, v => DiagnosticsMinimumLevel = v);
        changed |= ClampProp(DiagnosticsRetentionDays, 1, 365, 7, v => DiagnosticsRetentionDays = v);
        changed |= ClampProp(DiagnosticsMaxFileSizeKB, 64, 262144, 4096, v => DiagnosticsMaxFileSizeKB = v);

        if (!Enum.IsDefined(FragmentStrategy))
        {
            FragmentStrategy = TlsFragmentStrategy.SniBoundary;
            changed = true;
        }

        if (!Enum.IsDefined(RelayType))
        {
            RelayType = RelayType.Socks5;
            changed = true;
        }

        if (!TryNormalizeEndpoint(DohEndpoint, out var endpoint))
        {
            DohEndpoint = "https://dns.alidns.com/resolve";
            changed = true;
        }
        else if (!string.Equals(endpoint, DohEndpoint, StringComparison.Ordinal))
        {
            DohEndpoint = endpoint;
            changed = true;
        }

        return changed;
    }

    static bool TryNormalizeListenAddress(string value, out string normalized)
    {
        normalized = value;
        if (string.IsNullOrWhiteSpace(value)) return false;

        value = value.Trim();
        if (value is "*" or "any") { normalized = "0.0.0.0"; return true; }
        if (string.Equals(value, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            normalized = "127.0.0.1";
            return true;
        }

        if (!System.Net.IPAddress.TryParse(value, out var ip)) return false;
        normalized = ip.ToString();
        return true;
    }

    static bool TryNormalizeEndpoint(string value, out string normalized)
    {
        normalized = value;
        if (!Uri.TryCreate(value?.Trim(), UriKind.Absolute, out var uri))
        {
            return false;
        }
        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        normalized = uri.ToString();
        return true;
    }

    static bool FixProp(string value, string fallback, Action<string> set)
    {
        if (!string.IsNullOrWhiteSpace(value)) return false;
        set(fallback);
        return true;
    }

    static bool ClampProp(int value, int min, int max, int fallback, Action<int> set)
    {
        if (value >= min && value <= max) return false;
        set(value <= 0 ? fallback : Math.Clamp(value, min, max));
        return true;
    }

    public static AccelSettings CreateDefault() => new();
}
