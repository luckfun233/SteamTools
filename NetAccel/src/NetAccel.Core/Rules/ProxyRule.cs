using System.Collections.Concurrent;
using System.Text;
using System.Text.RegularExpressions;

namespace NetAccel.Core.Rules;

/// <summary>
/// 一条代理规则，兼容 DevSidecar 的 server.intercepts 子集。
/// 无证书模式下只有域匹配、SNI 改写/移除、预置 IP、排除列表、中继会生效；
/// 镜像/请求头类字段保留用于规则兼容与展示。
/// </summary>
public sealed class ProxyRule
{
    public string DomainPattern { get; init; } = string.Empty;
    public string? Group { get; init; }
    public string? PathPattern { get; init; }
    public string? Sni { get; init; }
    public string? VerifyHost { get; init; }
    public string? Redirect { get; init; }
    public string? Proxy { get; init; }
    public IReadOnlyList<string> BackupProxies { get; init; } = Array.Empty<string>();
    public IReadOnlyDictionary<string, string?> RequestHeaders { get; init; }
        = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
    public IReadOnlyDictionary<string, string?> ResponseHeaders { get; init; }
        = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
    public bool Block { get; init; }
    public bool UnVerifySsl { get; init; }
    public string? Description { get; init; }
    public IReadOnlyList<string> PresetIps { get; init; } = Array.Empty<string>();

    /// <summary>需要解密 TLS 才能完整生效；无证书模式下会被忽略。</summary>
    public bool RequiresMitm =>
        !string.IsNullOrEmpty(Sni) ||
        !string.IsNullOrEmpty(VerifyHost) ||
        !string.IsNullOrEmpty(Redirect) ||
        !string.IsNullOrEmpty(Proxy) ||
        RequestHeaders.Count > 0 ||
        ResponseHeaders.Count > 0 ||
        Block;

    /// <summary>DevSidecar 中 sni: "none" 表示移除 ClientHello 的 SNI 扩展。</summary>
    public bool RemoveSni => string.Equals(Sni, "none", StringComparison.OrdinalIgnoreCase);

    public bool MatchesPath(string path)
    {
        if (string.IsNullOrEmpty(PathPattern)) return true;
        var regex = RegexCache.GetPathRegex(PathPattern);
        if (regex == null) return false;
        try
        {
            return regex.IsMatch(path);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    /// <summary>
    /// 展开 DevSidecar 目标里的正则命名组变量，例如 ${pre}.example.com。
    /// </summary>
    public string ExpandTarget(string host, string target)
    {
        if (string.IsNullOrEmpty(target) || target.IndexOf("${", StringComparison.Ordinal) < 0) return target;

        var hostRegex = RegexCache.GetDomainRegex(DomainPattern);
        if (hostRegex == null) return target;

        try
        {
            var match = hostRegex.Match(host);
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
/// 规则集合。按配置顺序匹配；同域名多条规则会合并，避免具体规则被通配规则遮蔽。
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
            if (!DomainPatternMatcher.IsMatch(host, rule.DomainPattern)) continue;
            if (rule.MatchesPath(path))
            {
                matches ??= new List<ProxyRule>();
                matches.Add(rule);
            }
        }

        if (matches == null) return null;
        if (matches.Count == 1) return matches[0];

        // 自定义规则命中时不再合并远程规则，避免远程的 redirect/proxy 覆盖用户意图。
        var customMatches = matches
            .Where(x => string.Equals(x.Group, ProxyRuleGroups.Custom, StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (customMatches.Count > 0)
        {
            return customMatches.Count == 1 ? customMatches[0] : Merge(customMatches);
        }

        return Merge(matches);
    }

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

    public bool IsExcluded(string host)
    {
        foreach (var pattern in ExcludePatterns)
        {
            if (DomainPatternMatcher.IsMatch(host, pattern)) return true;
        }
        return false;
    }

    public IReadOnlyList<string> GetPresetIps(string host)
    {
        var result = new List<string>();
        foreach (var item in PresetIps)
        {
            if (DomainPatternMatcher.IsMatch(host, item.Key)) result.AddRange(item.Value);
        }
        return result;
    }

    /// <summary>合并两个规则集，前者的规则优先匹配。</summary>
    public static ProxyRuleSet Combine(ProxyRuleSet highPriority, ProxyRuleSet lowPriority)
    {
        if (IsEmpty(highPriority)) return lowPriority;
        if (IsEmpty(lowPriority)) return highPriority;

        var rules = new List<ProxyRule>(highPriority.Rules.Count + lowPriority.Rules.Count);
        rules.AddRange(highPriority.Rules);
        rules.AddRange(lowPriority.Rules);

        var excludes = new List<string>(highPriority.ExcludePatterns);
        foreach (var pattern in lowPriority.ExcludePatterns)
        {
            if (!excludes.Contains(pattern, StringComparer.OrdinalIgnoreCase)) excludes.Add(pattern);
        }

        var presetIps = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in lowPriority.PresetIps) presetIps[item.Key] = item.Value;
        foreach (var item in highPriority.PresetIps) presetIps[item.Key] = item.Value;

        return new ProxyRuleSet(rules, excludes, presetIps);
    }

    static bool IsEmpty(ProxyRuleSet set)
        => set.Rules.Count == 0 && set.ExcludePatterns.Count == 0 && set.PresetIps.Count == 0;

    /// <summary>只保留指定规则组。未分类与自定义规则始终保留。</summary>
    public ProxyRuleSet FilterGroups(ISet<string> enabledGroups)
    {
        if (enabledGroups.Count == 0) return Empty;

        var rules = new List<ProxyRule>();
        foreach (var rule in Rules)
        {
            if (string.IsNullOrEmpty(rule.Group) ||
                string.Equals(rule.Group, ProxyRuleGroups.Custom, StringComparison.OrdinalIgnoreCase) ||
                enabledGroups.Contains(rule.Group))
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
/// 正则带 250ms 超时与缓存，防止恶意/错误规则造成 ReDoS 或反复编译。
/// </summary>
public static class DomainPatternMatcher
{
    public static bool IsMatch(string host, string pattern)
    {
        if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(pattern)) return false;

        host = host.Trim();
        pattern = pattern.Trim();

        if (pattern.Length > 1024) return false;

        // IPv6 字面量在 URL 中带方括号，规则里也常带方括号。
        if (pattern.StartsWith("[", StringComparison.Ordinal) && pattern.EndsWith("]", StringComparison.Ordinal))
        {
            return string.Equals(host, pattern, StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(host, pattern[1..^1], StringComparison.OrdinalIgnoreCase);
        }

        if (IsPureRegex(pattern))
        {
            var regex = RegexCache.GetDomainRegex("re:" + pattern, () => pattern);
            return regex != null && SafeIsMatch(regex, host);
        }

        if (pattern.IndexOf('(') >= 0 || pattern.IndexOf('|') >= 0)
        {
            // DevSidecar 允许通配符与正则分组混写，例如 (*account*|scholar).google.com。
            var hybrid = RegexCache.GetDomainRegex("hybrid:" + pattern, () => ConvertHybridToRegex(pattern));
            return hybrid != null && SafeIsMatch(hybrid, host);
        }

        var wildcardRegex = RegexCache.GetDomainRegex("wildcard:" + pattern,
            () => "^" + ConvertWildcardsToRegex(pattern) + "$");
        return wildcardRegex != null && SafeIsMatch(wildcardRegex, host);
    }

    static bool SafeIsMatch(Regex regex, string input)
    {
        try
        {
            return regex.IsMatch(input);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    static bool IsPureRegex(string pattern)
    {
        if (pattern.StartsWith("^", StringComparison.Ordinal) ||
            pattern.EndsWith("$", StringComparison.Ordinal) ||
            pattern.Contains("\\", StringComparison.Ordinal))
        {
            return true;
        }

        return pattern.IndexOf('[') >= 0 && pattern.IndexOf(']') >= 0 && pattern.IndexOf('*') < 0;
    }

    static string ConvertWildcardsToRegex(string pattern)
    {
        var escaped = Regex.Escape(pattern);
        return escaped.Replace("\\*", ".*").Replace("\\?", ".");
    }

    internal static string ConvertHybridToRegex(string pattern)
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
}

/// <summary>
/// 有上限的正则缓存。超过上限直接清空，避免长时间运行后无限增长。
/// </summary>
internal static class RegexCache
{
    const int MaxEntries = 4096;
    static readonly TimeSpan Timeout = TimeSpan.FromMilliseconds(250);

    static readonly ConcurrentDictionary<string, Regex?> domainCache = new(StringComparer.Ordinal);
    static readonly ConcurrentDictionary<string, Regex?> pathCache = new(StringComparer.Ordinal);

    public static Regex? GetDomainRegex(string pattern, Func<string>? factory = null)
        => Get(domainCache, pattern,
            factory ?? (() =>
            {
                if (pattern.IndexOf('(') >= 0 || pattern.IndexOf('|') >= 0)
                {
                    var hasWildcard = pattern.IndexOf('*') >= 0 || pattern.IndexOf('?') >= 0;
                    return hasWildcard ? DomainPatternMatcher.ConvertHybridToRegex(pattern) : pattern;
                }
                return pattern;
            }));

    public static Regex? GetPathRegex(string pattern)
        => Get(pathCache, pattern, () => pattern);

    static Regex? Get(ConcurrentDictionary<string, Regex?> cache, string key, Func<string> factory)
    {
        if (string.IsNullOrWhiteSpace(key)) return null;
        if (cache.TryGetValue(key, out var cached)) return cached;

        Regex? regex = null;
        try
        {
            regex = new Regex(
                factory(),
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
                Timeout);
        }
        catch
        {
            regex = null;
        }

        if (cache.Count > MaxEntries) cache.Clear();
        cache[key] = regex;
        return regex;
    }
}
