using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
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
        /// 规则组 ID，用于在设置中选择启用哪些组。
        /// </summary>
        public string? Group { get; init; }

        /// <summary>
        /// 路径正则；为空表示匹配该域名下所有路径。
        /// </summary>
        public string? PathPattern { get; init; }

        /// <summary>
        /// 上游 TLS 的 SNI 伪装值；"none" 表示移除 SNI 扩展。
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

        /// <summary>
        /// 主反代不可用时的备用反代。
        /// </summary>
        public IReadOnlyList<string> BackupProxies { get; init; } = Array.Empty<string>();

        /// <summary>
        /// 需要在上游请求中替换或删除的请求头。值为 null 或 "[remove]" 表示删除。
        /// </summary>
        public IReadOnlyDictionary<string, string?> RequestHeaders { get; init; }
            = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// 需要在返回给客户端的响应中替换或删除的响应头。
        /// </summary>
        public IReadOnlyDictionary<string, string?> ResponseHeaders { get; init; }
            = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

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
            RequestHeaders.Count > 0 ||
            ResponseHeaders.Count > 0 ||
            Block;

        /// <summary>
        /// sni 为 "none" 时，DevSidecar 的语义是移除 ClientHello 的 SNI 扩展。
        /// </summary>
        public bool RemoveSni =>
            string.Equals(Sni, "none", StringComparison.OrdinalIgnoreCase);

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

        /// <summary>
        /// 展开 DevSidecar 目标里的正则命名组变量，例如 ${pre}.example.com。
        /// </summary>
        public string ExpandTarget(string host, string target)
        {
            if (string.IsNullOrEmpty(target) || target.IndexOf("${", StringComparison.Ordinal) < 0)
            {
                return target;
            }

            try
            {
                var match = Regex.Match(host, DomainPattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                if (!match.Success) return target;

                return Regex.Replace(target, @"\$\{([A-Za-z0-9_]+)\}", m =>
                {
                    var group = match.Groups[m.Groups[1].Value];
                    return group.Success ? group.Value : m.Value;
                });
            }
            catch
            {
                return target;
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
            List<ProxyRule>? matches = null;
            foreach (var rule in Rules)
            {
                if (!DomainPatternMatcher.IsMatch(host, rule.DomainPattern))
                {
                    continue;
                }
                if (rule.MatchesPath(path))
                {
                    matches ??= new List<ProxyRule>();
                    matches.Add(rule);
                }
            }

            if (matches == null) return null;
            if (matches.Count == 1) return matches[0];
            return Merge(matches);
        }

        /// <summary>
        /// DevSidecar 会合并同一主机名命中的多条配置，例如 *.pximg.net 提供 SNI，
        /// i.pximg.net 再追加 Referer 头。这里用同样的方式合并，避免具体规则被通配规则遮蔽。
        /// </summary>
        static ProxyRule Merge(IReadOnlyList<ProxyRule> rules)
        {
            var first = rules[0];
            var requestHeaders = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
            var responseHeaders = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
            var presetIps = new List<string>();
            var backups = Array.Empty<string>();
            string? sni = null, verifyHost = null, redirect = null, proxy = null, description = null;
            var block = false;
            var unVerifySsl = false;

            foreach (var rule in rules)
            {
                if (string.IsNullOrEmpty(sni)) sni = rule.Sni;
                if (string.IsNullOrEmpty(verifyHost)) verifyHost = rule.VerifyHost;
                if (string.IsNullOrEmpty(redirect)) redirect = rule.Redirect;
                if (string.IsNullOrEmpty(proxy)) proxy = rule.Proxy;
                if (backups.Length == 0 && rule.BackupProxies.Count > 0) backups = rule.BackupProxies.ToArray();
                if (string.IsNullOrEmpty(description)) description = rule.Description;
                block |= rule.Block;
                unVerifySsl |= rule.UnVerifySsl;

                foreach (var header in rule.RequestHeaders) requestHeaders[header.Key] = header.Value;
                foreach (var header in rule.ResponseHeaders) responseHeaders[header.Key] = header.Value;
                foreach (var ip in rule.PresetIps)
                {
                    if (!presetIps.Contains(ip, StringComparer.OrdinalIgnoreCase)) presetIps.Add(ip);
                }
            }

            return new ProxyRule
            {
                DomainPattern = first.DomainPattern,
                Group = first.Group,
                Sni = sni,
                VerifyHost = verifyHost,
                Redirect = redirect,
                Proxy = proxy,
                BackupProxies = backups,
                RequestHeaders = requestHeaders,
                ResponseHeaders = responseHeaders,
                Block = block,
                UnVerifySsl = unVerifySsl,
                Description = description,
                PresetIps = presetIps,
            };
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

        /// <summary>
        /// 只保留指定规则组。未分类的规则始终保留。
        /// </summary>
        public ProxyRuleSet FilterGroups(ISet<string> enabledGroups)
        {
            if (enabledGroups.Count == 0) return Empty;

            var rules = new List<ProxyRule>();
            foreach (var rule in Rules)
            {
                if (string.IsNullOrEmpty(rule.Group) || enabledGroups.Contains(rule.Group))
                {
                    rules.Add(rule);
                }
            }

            var presetIps = new Dictionary<string, IReadOnlyList<string>>();
            foreach (var item in PresetIps)
            {
                var group = ProxyRuleGroups.Classify(item.Key);
                if (string.IsNullOrEmpty(group) || enabledGroups.Contains(group))
                {
                    presetIps[item.Key] = item.Value;
                }
            }

            return new ProxyRuleSet(rules, ExcludePatterns, presetIps);
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

            // IPv6 字面量在 URL 中带方括号，规则里也常带方括号。
            if (pattern.StartsWith("[", StringComparison.Ordinal) && pattern.EndsWith("]", StringComparison.Ordinal))
            {
                return string.Equals(host, pattern, StringComparison.OrdinalIgnoreCase) ||
                       string.Equals(host, pattern.Substring(1, pattern.Length - 2), StringComparison.OrdinalIgnoreCase);
            }

            if (IsPureRegex(pattern))
            {
                if (TryRegex(host, pattern, out var matched)) return matched;
            }
            else
            {
                if (pattern.IndexOf('(') >= 0 || pattern.IndexOf('|') >= 0)
                {
                    // 混合写法，例如 (*account*|scholar).google.com。
                    var hybrid = ConvertHybridToRegex(pattern);
                    if (TryRegex(host, hybrid, out var matched)) return matched;
                }

                var wildcard = "^" + ConvertWildcardsToRegex(pattern) + "$";
                if (TryRegex(host, wildcard, out var wildcardMatched)) return wildcardMatched;
            }

            return false;
        }

        static bool IsPureRegex(string pattern)
        {
            if (pattern.StartsWith("^", StringComparison.Ordinal) ||
                pattern.EndsWith("$", StringComparison.Ordinal) ||
                pattern.Contains("\\", StringComparison.Ordinal))
            {
                return true;
            }

            // 形如 [a-f] 或 IPv6 的字符类也需要按正则处理。
            return pattern.IndexOf('[') >= 0 && pattern.IndexOf(']') >= 0 && pattern.IndexOf('*') < 0;
        }

        static string ConvertWildcardsToRegex(string pattern)
        {
            var escaped = Regex.Escape(pattern);
            return escaped.Replace("\\*", ".*").Replace("\\?", ".");
        }

        /// <summary>
        /// DevSidecar 允许在域名规则里混用通配符和正则分组，例如 (*account*|scholar).google.com。
        /// 这里保留分组语法，把 * ? 按通配符处理，域名中的点按字面量处理。
        /// </summary>
        static string ConvertHybridToRegex(string pattern)
        {
            var sb = new StringBuilder(pattern.Length + 8);
            sb.Append('^');
            foreach (var c in pattern)
            {
                switch (c)
                {
                    case '*':
                        sb.Append(".*");
                        break;
                    case '?':
                        sb.Append('.');
                        break;
                    case '(':
                    case ')':
                    case '|':
                    case '[':
                    case ']':
                        sb.Append(c);
                        break;
                    case '.':
                        sb.Append("\\.");
                        break;
                    case '+':
                    case '{':
                    case '}':
                    case '^':
                    case '$':
                    case '\\':
                        sb.Append('\\').Append(c);
                        break;
                    default:
                        sb.Append(c);
                        break;
                }
            }
            sb.Append('$');
            return sb.ToString();
        }

        static bool TryRegex(string host, string pattern, out bool matched)
        {
            try
            {
                matched = Regex.IsMatch(host, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                return true;
            }
            catch
            {
                matched = false;
                return false;
            }
        }
    }
}
