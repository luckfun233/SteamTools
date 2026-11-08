using System.Linq;
using System.Application.ProxyRules;
using System.Application.Services;
using System.Application.Services.Implementation;
using System.Application.UI.Resx;
using System.Collections.Generic;
using EProxyMode = System.Application.ProxyMode;
using IPAddress = System.Net.IPAddress;

namespace System.Application.Settings;

public sealed partial class ProxySettings : SettingsHost2<ProxySettings>
{
    /// <summary>
    /// 启用脚本自动检查更新
    /// </summary>
    public static SerializableProperty<bool> IsAutoCheckScriptUpdate { get; }
        = GetProperty(defaultValue: true);

    /// <summary>
    /// 启用代理脚本
    /// </summary>
    public static SerializableProperty<bool> IsEnableScript { get; }
        = GetProperty(defaultValue: false);

    /// <summary>
    /// 代理服务启用状态
    /// </summary>
    public static SerializableProperty<IReadOnlyCollection<string>> SupportProxyServicesStatus { get; }
        = GetProperty(defaultValue: (IReadOnlyCollection<string>)Array.Empty<string>(), autoSave: false);

    /// <summary>
    /// 脚本启用状态
    /// </summary>
    public static SerializableProperty<IReadOnlyCollection<int>> ScriptsStatus { get; }
        = GetProperty(defaultValue: (IReadOnlyCollection<int>)Array.Empty<int>());

    #region 代理设置

    /// <summary>
    /// 程序启动时自动启动代理
    /// </summary>
    public static SerializableProperty<bool> ProgramStartupRunProxy { get; }
        = GetProperty(defaultValue: false);

    /// <summary>
    /// 系统代理模式端口
    /// </summary>
    public static SerializableProperty<int> SystemProxyPortId { get; }
        = GetProperty(defaultValue: 26501, autoSave: false);

    /// <summary>
    /// 系统代理模式IP
    /// </summary>
    public static SerializableProperty<string> SystemProxyIp { get; }
        = GetProperty(defaultValue: IPAddress.Any.ToString(), autoSave: false);

    /// <summary>
    /// 开启加速后仅代理脚本而不加速
    /// </summary>
    public static SerializableProperty<bool> OnlyEnableProxyScript { get; }
        = GetProperty(defaultValue: false, autoSave: false);

    /// <summary>
    /// 代理时使用的解析主DNS
    /// </summary>
    public static SerializableProperty<string?> ProxyMasterDns { get; }
        = GetProperty<string?>(defaultValue: "223.5.5.5", autoSave: false);

    /// <summary>
    /// 启用 Http 链接转发到 Https
    /// </summary>
    public static SerializableProperty<bool> EnableHttpProxyToHttps { get; }
        = GetProperty(defaultValue: true);
    #endregion

    #region 本地代理设置

    /// <summary>
    /// Socks5 Enable
    /// </summary>
    public static SerializableProperty<bool> Socks5ProxyEnable { get; }
        = GetProperty(defaultValue: false, autoSave: false);

    /// <summary>
    /// Socks5 监听端口
    /// </summary>
    public static SerializableProperty<int> Socks5ProxyPortId { get; }
        = GetProperty(defaultValue: DefaultSocks5ProxyPortId, autoSave: false);

    public const int DefaultSocks5ProxyPortId = 8868;

    #endregion

    #region 二级代理设置

    /// <summary>
    /// TwoLevelAgent Enable
    /// </summary>
    public static SerializableProperty<bool> TwoLevelAgentEnable { get; }
        = GetProperty(defaultValue: false, autoSave: false);

    /// <summary>
    /// TwoLevelAgent ProxyType
    /// </summary>
    public static SerializableProperty<short> TwoLevelAgentProxyType { get; }
        = GetProperty(defaultValue: DefaultTwoLevelAgentProxyType, autoSave: false);

    public const short DefaultTwoLevelAgentProxyType =
        (short)IReverseProxyService.DefaultTwoLevelAgentProxyType;

    /// <summary>
    /// 二级代理 IP
    /// </summary>
    public static SerializableProperty<string> TwoLevelAgentIp { get; }
        = GetProperty(defaultValue: IPAddress.Loopback.ToString(), autoSave: false);

    /// <summary>
    /// 二级代理 监听端口
    /// </summary>
    public static SerializableProperty<int> TwoLevelAgentPortId { get; }
        = GetProperty(defaultValue: DefaultTwoLevelAgentPortId, autoSave: false);

    public const int DefaultTwoLevelAgentPortId = 7890;

    /// <summary>
    /// TwoLevelAgent UserName
    /// </summary>
    public static SerializableProperty<string> TwoLevelAgentUserName { get; }
        = GetProperty(defaultValue: string.Empty, autoSave: false);

    /// <summary>
    /// TwoLevelAgent Password
    /// </summary>
    public static SerializableProperty<string> TwoLevelAgentPassword { get; }
        = GetProperty(defaultValue: string.Empty, autoSave: false);

    #endregion

    #region 代理模式设置

    static EProxyMode DefaultProxyMode => ProxyModes.FirstOrDefault();

    static IEnumerable<EProxyMode> GetProxyModes()
    {
        if (OperatingSystem2.IsWindows())
        {
            yield return EProxyMode.Hosts;
            yield return EProxyMode.DNSIntercept;
            yield return EProxyMode.PAC;
            yield return EProxyMode.System;
        }
        else if (OperatingSystem2.IsAndroid())
        {
            yield return EProxyMode.VPN;
            yield return EProxyMode.ProxyOnly;
        }
        else if (OperatingSystem2.IsLinux() || OperatingSystem2.IsMacOS())
        {
            yield return EProxyMode.Hosts;
            yield return EProxyMode.System;
        }
    }

    public static IReadOnlyList<EProxyMode> ProxyModes => mProxyModes.Value;

    static readonly Lazy<IReadOnlyList<EProxyMode>> mProxyModes = new(() => GetProxyModes().ToArray());

    /// <summary>
    /// 当前代理模式
    /// </summary>
    public static SerializableProperty<EProxyMode> ProxyMode { get; }
       = GetProperty(defaultValue: DefaultProxyMode);

    /// <inheritdoc cref="ProxyMode"/>
    public static EProxyMode ProxyModeValue
    {
        get
        {
            var value = ProxyMode.Value;
            if (ProxyModes.Contains(value)) return value;
            return DefaultProxyMode;
        }
        set => ProxyMode.Value = value;
    }

    /// <summary>
    /// 免证书隧道模式。启用后不进行 MITM，镜像改写、SNI 伪装和脚本注入不可用。
    /// 默认关闭；未安装/未信任根证书时会自动退化为隧道模式。
    /// </summary>
    public static SerializableProperty<bool> IsCertificateLessMode { get; }
        = GetProperty(defaultValue: false, autoSave: false);

    #region 实验性加速设置

    /// <summary>
    /// 是否加载 DevSidecar 兼容规则（remote_config.json5）。
    /// </summary>
    public static SerializableProperty<bool> EnableDevSidecarRules { get; }
        = GetProperty(defaultValue: false, autoSave: false);

    /// <summary>
    /// DevSidecar 远程配置地址。
    /// </summary>
    public static SerializableProperty<string> DevSidecarConfigUrl { get; }
        = GetProperty(defaultValue: DefaultDevSidecarConfigUrl, autoSave: false);

    public const string DefaultDevSidecarConfigUrl = "https://ds-official-config.bestar.de5.net/remote_config.json5";

    /// <summary>
    /// 启动加速时是否同步 DevSidecar 配置。
    /// </summary>
    public static SerializableProperty<bool> SyncDevSidecarConfigOnStartup { get; }
        = GetProperty(defaultValue: false, autoSave: false);

    /// <summary>
    /// 启用的 DevSidecar 规则组，分号分隔。未选中的组不会参与匹配。
    /// </summary>
    public static SerializableProperty<string> DevSidecarRuleGroups { get; }
        = GetProperty(defaultValue: ProxyRuleGroups.DefaultEnabled, autoSave: false);

    /// <summary>
    /// 启用免证书 SNI 分片（通过本地 sidecar SOCKS5）。
    /// </summary>
    public static SerializableProperty<bool> EnableSniFragment { get; }
        = GetProperty(defaultValue: false, autoSave: false);

    /// <summary>
    /// SNI 分片策略：0=固定大小，1=按 SNI 边界拆分，2=按 TLS 记录头拆分。
    /// </summary>
    public static SerializableProperty<int> SniFragmentStrategy { get; }
        = GetProperty(defaultValue: SniFragmentStrategySniBoundary, autoSave: false);

    public const int SniFragmentStrategyFixed = 0;
    public const int SniFragmentStrategySniBoundary = 1;
    public const int SniFragmentStrategyRecord = 2;

    /// <summary>
    /// 只对列出的域名做 SNI 分片/改写，分号分隔；为空表示全部域名。
    /// </summary>
    public static SerializableProperty<string> SniFragmentDomains { get; }
        = GetProperty(defaultValue: DefaultSniFragmentDomains, autoSave: false);

    public const string DefaultSniFragmentDomains = "github.com;*.githubusercontent.com;*.githubassets.com;github.dev;huggingface.co;*.huggingface.co;*.hf.co;pixiv.net;*.pixiv.net;*.pixiv.org;pximg.net;*.pximg.net;*.fanbox.cc";

    /// <summary>
    /// 只对 TLS 连接做分片，非 TLS 直接透传。
    /// </summary>
    public static SerializableProperty<bool> SniFragmentOnlyTls { get; }
        = GetProperty(defaultValue: true, autoSave: false);

    /// <summary>
    /// 启用免证书 SNI 改写（实验性，按域名白名单）。
    /// </summary>
    public static SerializableProperty<bool> EnableSniRewrite { get; }
        = GetProperty(defaultValue: false, autoSave: false);

    /// <summary>
    /// SNI 改写目标，默认 baidu.com。
    /// </summary>
    public static SerializableProperty<string> SniRewriteHost { get; }
        = GetProperty(defaultValue: "baidu.com", autoSave: false);

    /// <summary>
    /// 允许做 SNI 改写的域名，分号分隔；默认只包含 GitHub 相关域名。
    /// </summary>
    public static SerializableProperty<string> SniRewriteDomains { get; }
        = GetProperty(defaultValue: DefaultSniRewriteDomains, autoSave: false);

    public const string DefaultSniRewriteDomains = "github.com;api.github.com;github.githubassets.com;avatars.githubusercontent.com;camo.githubusercontent.com;collector.github.com;raw.githubusercontent.com;gist.githubusercontent.com;objects.githubusercontent.com;release-assets.githubusercontent.com;user-images.githubusercontent.com;private-user-images.githubusercontent.com;media.githubusercontent.com";

    /// <summary>
    /// 固定大小分片策略下的分片大小（字节）。
    /// </summary>
    public static SerializableProperty<int> SniFragmentChunkSize { get; }
        = GetProperty(defaultValue: 64, autoSave: false);

    /// <summary>
    /// SNI 分片之间的延迟（毫秒）。
    /// </summary>
    public static SerializableProperty<int> SniFragmentDelayMilliseconds { get; }
        = GetProperty(defaultValue: 10, autoSave: false);

    /// <summary>
    /// 单次 TLS ClientHello 最多缓冲的字节数，防止异常流量占用内存。
    /// </summary>
    public static SerializableProperty<int> SniFragmentMaxBufferBytes { get; }
        = GetProperty(defaultValue: 16384, autoSave: false);

    /// <summary>
    /// 等待剩余 ClientHello 字节的超时时间（毫秒）。
    /// </summary>
    public static SerializableProperty<int> SniFragmentReadTimeoutMilliseconds { get; }
        = GetProperty(defaultValue: 300, autoSave: false);

    /// <summary>
    /// SNI sidecar 的本地 SOCKS5 端口。
    /// </summary>
    public static SerializableProperty<int> SniFragmentPortId { get; }
        = GetProperty(defaultValue: 8869, autoSave: false);

    /// <summary>
    /// 免证书模式下是否通过上游 SOCKS5 中继转发全部流量。
    /// </summary>
    public static SerializableProperty<bool> EnableSniUpstreamRelay { get; }
        = GetProperty(defaultValue: false, autoSave: false);

    public static SerializableProperty<string> SniUpstreamRelayHost { get; }
        = GetProperty(defaultValue: "127.0.0.1", autoSave: false);

    public static SerializableProperty<int> SniUpstreamRelayPort { get; }
        = GetProperty(defaultValue: 7890, autoSave: false);

    public static SerializableProperty<string> SniUpstreamRelayUserName { get; }
        = GetProperty(defaultValue: string.Empty, autoSave: false);

    public static SerializableProperty<string> SniUpstreamRelayPassword { get; }
        = GetProperty(defaultValue: string.Empty, autoSave: false);

    /// <summary>
    /// 是否使用 DoH 解析域名，避免 DNS 污染。
    /// </summary>
    public static SerializableProperty<bool> EnableDoh { get; }
        = GetProperty(defaultValue: false, autoSave: false);

    /// <summary>
    /// DoH JSON 接口地址。
    /// </summary>
    public static SerializableProperty<string> DohEndpoint { get; }
        = GetProperty(defaultValue: DefaultDohEndpoint, autoSave: false);

    public const string DefaultDohEndpoint = "https://dns.alidns.com/resolve";

    /// <summary>
    /// DoH 失败时是否回退到系统 DNS。
    /// </summary>
    public static SerializableProperty<bool> DohFallbackToSystem { get; }
        = GetProperty(defaultValue: true, autoSave: false);

    /// <summary>
    /// 是否写入代理诊断日志。
    /// </summary>
    public static SerializableProperty<bool> EnableProxyDiagnostics { get; }
        = GetProperty(defaultValue: true, autoSave: false);

    /// <summary>
    /// 诊断日志最低级别：0=Info，1=Warn，2=Error。
    /// </summary>
    public static SerializableProperty<int> ProxyDiagnosticsMinimumLevel { get; }
        = GetProperty(defaultValue: 0, autoSave: false);

    /// <summary>
    /// 日志中是否保留完整主机名。关闭后会把形似域名的文本替换为 ***。
    /// </summary>
    public static SerializableProperty<bool> ProxyDiagnosticsIncludeHost { get; }
        = GetProperty(defaultValue: true, autoSave: false);

    /// <summary>
    /// 代理诊断日志保留天数。
    /// </summary>
    public static SerializableProperty<int> ProxyDiagnosticsRetentionDays { get; }
        = GetProperty(defaultValue: 7, autoSave: false);

    /// <summary>
    /// 单个代理诊断日志文件的最大大小（KB），超过后切分。
    /// </summary>
    public static SerializableProperty<int> ProxyDiagnosticsMaxFileSizeKB { get; }
        = GetProperty(defaultValue: 4096, autoSave: false);

    /// <summary>
    /// 增强模式下仅让浏览器走 VPN/MITM，避免其它应用因证书问题断网。
    /// </summary>
    public static SerializableProperty<bool> EnableBrowserOnlyVpn { get; }
        = GetProperty(defaultValue: false, autoSave: false);

    /// <summary>
    /// 恢复实验性设置的默认值。不会修改代理端口、二级代理等基础设置。
    /// </summary>
    public static void RestoreExperimentalDefaults()
    {
        EnableDevSidecarRules.Value = false;
        SyncDevSidecarConfigOnStartup.Value = false;
        DevSidecarConfigUrl.Value = DefaultDevSidecarConfigUrl;
        DevSidecarRuleGroups.Value = ProxyRuleGroups.DefaultEnabled;

        IsCertificateLessMode.Value = false;

        EnableSniFragment.Value = false;
        SniFragmentStrategy.Value = SniFragmentStrategySniBoundary;
        SniFragmentChunkSize.Value = 64;
        SniFragmentDelayMilliseconds.Value = 10;
        SniFragmentMaxBufferBytes.Value = 16384;
        SniFragmentReadTimeoutMilliseconds.Value = 300;
        SniFragmentPortId.Value = 8869;
        SniFragmentDomains.Value = DefaultSniFragmentDomains;
        SniFragmentOnlyTls.Value = true;
        EnableSniRewrite.Value = false;
        SniRewriteHost.Value = "baidu.com";
        SniRewriteDomains.Value = DefaultSniRewriteDomains;

        EnableSniUpstreamRelay.Value = false;
        SniUpstreamRelayHost.Value = "127.0.0.1";
        SniUpstreamRelayPort.Value = 7890;
        SniUpstreamRelayUserName.Value = string.Empty;
        SniUpstreamRelayPassword.Value = string.Empty;

        EnableDoh.Value = false;
        DohEndpoint.Value = DefaultDohEndpoint;
        DohFallbackToSystem.Value = true;

        EnableProxyDiagnostics.Value = true;
        ProxyDiagnosticsMinimumLevel.Value = 0;
        ProxyDiagnosticsIncludeHost.Value = true;
        ProxyDiagnosticsRetentionDays.Value = 7;
        ProxyDiagnosticsMaxFileSizeKB.Value = 4096;

        EnableBrowserOnlyVpn.Value = false;

        DohResolver.ClearCache();
        SettingsHost.Save();
    }

    #endregion

    public static string ToStringByProxyMode(EProxyMode mode) => mode switch
    {
        EProxyMode.DNSIntercept => AppResources.ProxyMode_DNSIntercept,
        EProxyMode.Hosts => AppResources.ProxyMode_Hosts,
        EProxyMode.System => AppResources.ProxyMode_System,
        EProxyMode.VPN => AppResources.ProxyMode_VPN,
        EProxyMode.ProxyOnly => AppResources.ProxyMode_ProxyOnly,
        _ => string.Empty,
    };

    public static string ProxyModeValueString => ToStringByProxyMode(ProxyModeValue);

    #endregion
}
