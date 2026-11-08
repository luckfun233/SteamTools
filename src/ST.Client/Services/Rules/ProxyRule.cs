using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace System.Application.ProxyRules
{
    /// <summary>
    /// 一条代理规则，兼容 DevSidecar 的 server.intercepts 子集。
    /// </summary>
    public sealed class ProxyRule
    {
        public string DomainPattern { get; init; } = string.Empty;

        /// <summary>
        /// 路径正则；为空表示匹配该域名下所有路径。
        /// </summary>
        public string? PathPattern { get; init; }

        /// <summary>
        /// 上游 TLS 的 SNI 伪装值。
        /// </summary>
        public string? Sni { get; init; }

        /// <summary>
        /// 上游 TLS 证书校验域名（Titanium 当前默认放行上游证书，保留字段兼容）。
        /// </summary>
        public string? VerifyHost { get; init; }

        /// <summary>
        /// 公开请求的镜像重定向地址，例如 ghp.ci/https://github.com。
        /// </summary>
        public string? Redirect { get; init; }

        /// <summary>
        /// 上游反代目标，例如 huggingface.cn。
        /// </summary>
        public string? Proxy { get; init; }

        public bool Block { get; init; }

        public bool UnVerifySsl { get; init; }

        public string? Description { get; init; }

        public IReadOnlyList<string> PresetIps { get; init; } = Array.Empty<string>();

        /// <summary>
        /// 是否需要解密 TLS 才能执行该规则。
        /// </summary>
        public bool RequiresMitm =>
            !string.IsNullOrEmpty(Sni) ||
            !string.IsNullOrEmpty(VerifyHost) ||
            !string.IsNullOrEmpty(Redirect) ||
            !string.IsNullOrEmpty(Proxy) ||
            Block;

        public bool MatchesPath(string path)
        {
            if (string.IsNullOrEmpty(PathPattern))
            {
                return true;
            }
            try
            {
                return Regex.IsMatch(path, PathPattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// 规则集合。按配置顺序匹配，DevSidecar 的路径规则通常排在 .* 前面。
    /// </summary>
    public sealed class ProxyRuleSet
    {
        public static ProxyRuleSet Empty { get; } = new(
            Array.Empty<ProxyRule>(),
            Array.Empty<string>(),
            new Dictionary<string, IReadOnlyList<string>>());

        public ProxyRuleSet(
            IReadOnlyList<ProxyRule> rules,
            IReadOnlyList<string> excludePatterns,
            IReadOnlyDictionary<string, IReadOnlyList<string>> presetIps)
        {
            Rules = rules;
            ExcludePatterns = excludePatterns;
            PresetIps = presetIps;
        }

        public IReadOnlyList<ProxyRule> Rules { get; }

        public IReadOnlyList<string> ExcludePatterns { get; }

        public IReadOnlyDictionary<string, IReadOnlyList<string>> PresetIps { get; }

        public ProxyRule? Match(string host, string path = "/")
        {
            foreach (var rule in Rules)
            {
                if (!DomainPatternMatcher.IsMatch(host, rule.DomainPattern))
                {
                    continue;
                }
                if (rule.MatchesPath(path))
                {
                    return rule;
                }
            }
            return null;
        }

        public bool DomainRequiresMitm(string host)
        {
            foreach (var rule in Rules)
            {
                if (rule.RequiresMitm && DomainPatternMatcher.IsMatch(host, rule.DomainPattern))
                {
                    return true;
                }
            }
            return false;
        }

        public bool IsExcluded(string host)
        {
            foreach (var pattern in ExcludePatterns)
            {
                if (DomainPatternMatcher.IsMatch(host, pattern))
                {
                    return true;
                }
            }
            return false;
        }

        public IReadOnlyList<string> GetPresetIps(string host)
        {
            var result = new List<string>();
            foreach (var item in PresetIps)
            {
                if (DomainPatternMatcher.IsMatch(host, item.Key))
                {
                    result.AddRange(item.Value);
                }
            }
            return result;
        }
    }

    /// <summary>
    /// 同时支持精确域名、通配符和 DevSidecar 里的正则域名。
    /// </summary>
    public static class DomainPatternMatcher
    {
        public static bool IsMatch(string host, string pattern)
        {
            if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(pattern))
            {
                return false;
            }

            host = host.Trim();
            pattern = pattern.Trim();

            // DevSidecar 中有一部分直接写正则，例如 ^.*(wikipedia|wikimedia).org$
            if (pattern.StartsWith("^", StringComparison.Ordinal) ||
                pattern.Contains("(", StringComparison.Ordinal) ||
                pattern.Contains("[", StringComparison.Ordinal) ||
                pattern.Contains("\\", StringComparison.Ordinal))
            {
                try
                {
                    return Regex.IsMatch(host, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                }
                catch
                {
                    return false;
                }
            }

            var regex = "^" + Regex.Escape(pattern)
                .Replace("\\*", ".*")
                .Replace("\\?", ".") + "$";
            try
            {
                return Regex.IsMatch(host, regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            }
            catch
            {
                return false;
            }
        }
    }
}
