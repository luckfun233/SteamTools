using NetAccel.Core.Models;

namespace NetAccel.Core.Rules;

/// <summary>
/// 不依赖远程配置的内置加速数据（对应原项目 BuiltInAccelerateProjects）。
/// 免证书模式只能使用其中的预置 IP；SNI 伪装/镜像需要 MITM，这里不启用第三方镜像，
/// 避免把带凭证的请求交给公共节点。
/// </summary>
public static class BuiltInRules
{
    static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> presetIps =
        new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
        {
            // GitHub（DevSidecar 默认配置中的经验 IP）
            ["github.com"] = new[] { "140.82.121.4" },
            ["github.githubassets.com"] = new[] { "185.199.108.154" },
            ["raw.githubusercontent.com"] = new[] { "185.199.108.133" },

            // Pixiv / Fanbox
            ["i.pximg.net"] = new[] { "210.140.139.132" },
            ["s.pximg.net"] = new[] { "210.140.139.132" },
            ["a.pixiv.org"] = new[] { "210.140.139.182" },
            ["www.fanbox.cc"] = new[] { "210.140.139.155" },
            ["api.fanbox.cc"] = new[] { "172.64.146.116" },
        };

    public static ProxyRuleSet Create() => new(
        Array.Empty<ProxyRule>(),
        Array.Empty<string>(),
        presetIps);

    /// <summary>只保留已启用规则组对应的预置 IP。</summary>
    public static ProxyRuleSet CreateFiltered(ISet<string> enabledGroups)
        => Create().FilterGroups(enabledGroups);

    public static IReadOnlyList<string> Describe()
        => presetIps.Select(x => $"{x.Key} → {string.Join(",", x.Value)}").ToArray();
}
