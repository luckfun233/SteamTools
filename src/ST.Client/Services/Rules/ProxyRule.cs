using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace System.Application.ProxyRules
{
    /// <summary>
    /// 带超时的正则缓存。远程配置里的正则不可信，必须防止灾难性回溯阻塞请求线程。
    /// </summary>
    internal static class RegexCache
    {
        static readonly TimeSpan Timeout = TimeSpan.FromMilliseconds(100);
        static readonly ConcurrentDictionary<string, Regex> cache = new(StringComparer.Ordinal);
        const int MaxEntries = 2048;

        public static Regex? Get(string pattern, bool ignoreCase = true)
        {
            if (string.IsNullOrEmpty(pattern) || pattern.Length > 512) return null;

            var key = (ignoreCase ? "i:" : "s:") + pattern;
            if (cache.TryGetValue(key, out var cached)) return cached;

            Regex regex;
            try
            {
                var options = RegexOptions.CultureInvariant;
                if (ignoreCase) options |= RegexOptions.IgnoreCase;
                regex = new Regex(pattern, options, Timeout);
            }
            catch
            {
                return null;
            }

            if (cache.Count >= MaxEntries) cache.Clear();
            cache.TryAdd(key, regex);
            return regex;
        }

        public static bool IsMatch(string input, string pattern)
        {
            var regex = Get(pattern);
            if (regex == null) return false;
            try
            {
                return regex.IsMatch(input);
            }
            catch (RegexMatchTimeoutException)
            {
                return false;
            }
            catch
            {
                return false;
            }
        }
    }

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
            return RegexCache.IsMatch(path, PathPattern);
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

            var regex = RegexCache.Get(DomainPattern);
            if (regex == null) return target;

            try
            {
                var match = regex.Match(host);
                if (!match.Success) return target;

                return targetVariableRegex.Replace(target, m =>
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

        static readonly Regex targetVariableRegex = new(
            @"\$\{([A-Za-z0-9_]+)\}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant,
            TimeSpan.FromMilliseconds(100));
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
            IReadOnlyDictionary<string, IReadOnlyList<string>> presetIps,
            IReadOnlyDictionary<string, string>? presetIpGroups = null,
            IReadOnlyList<DnsMapping>? dnsMappings = null,
            IReadOnlyList<ProxyServiceInfo>? services = null)
        {
            Rules = rules;
            ExcludePatterns = excludePatterns;
            PresetIps = presetIps;
            PresetIpGroups = presetIpGroups ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            DnsMappings = dnsMappings ?? Array.Empty<DnsMapping>();
            Services = services ?? Array.Empty<ProxyServiceInfo>();
        }

        public IReadOnlyList<ProxyRule> Rules { get; }

        public IReadOnlyList<string> ExcludePatterns { get; }

        public IReadOnlyDictionary<string, IReadOnlyList<string>> PresetIps { get; }

        /// <summary>
        /// 预置 IP 域名 → 规则组，用于按组过滤。
        /// </summary>
        public IReadOnlyDictionary<string, string> PresetIpGroups { get; }

        /// <summary>
        /// DevSidecar 的 dns.mapping：域名 → HTTPS DoH 接口。只保留能直接使用的 HTTPS provider。
        /// </summary>
        public IReadOnlyList<DnsMapping> DnsMappings { get; }

        /// <summary>
        /// 配置里出现的全部服务（域名），即使没有可执行的 MITM 规则也会保留，
        /// 这样服务分组页面能与桌面端 DevSidecar 一致地展示所有组。
        /// </summary>
        public IReadOnlyList<ProxyServiceInfo> Services { get; }

        /// <summary>
        /// 为指定域名选择 DevSidecar dns.mapping 里的 DoH 接口。
        /// </summary>
        public string? GetDohEndpoint(string host)
        {
            foreach (var item in DnsMappings)
            {
                if (DomainPatternMatcher.IsMatch(host, item.DomainPattern))
                {
                    return item.Endpoint;
                }
            }
            return null;
        }

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

            // 自定义规则命中时不再合并远程规则，避免远程的 redirect/proxy 覆盖用户意图。
            var customMatches = matches.Where(x =>
                string.Equals(x.Group, ProxyRuleGroups.Custom, StringComparison.OrdinalIgnoreCase)).ToList();
            if (customMatches.Count > 0)
            {
                return customMatches.Count == 1 ? customMatches[0] : Merge(customMatches);
            }

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
        /// 合并两个规则集，前者的规则优先匹配。用于把用户自定义规则叠加在远程规则之上。
        /// </summary>
        public static ProxyRuleSet Combine(ProxyRuleSet highPriority, ProxyRuleSet lowPriority)
        {
            if (highPriority.Rules.Count == 0 &&
                highPriority.ExcludePatterns.Count == 0 &&
                highPriority.PresetIps.Count == 0)
            {
                return lowPriority;
            }
            if (lowPriority.Rules.Count == 0 &&
                lowPriority.ExcludePatterns.Count == 0 &&
                lowPriority.PresetIps.Count == 0)
            {
                return highPriority;
            }

            var rules = new List<ProxyRule>(highPriority.Rules.Count + lowPriority.Rules.Count);
            rules.AddRange(highPriority.Rules);
            rules.AddRange(lowPriority.Rules);

            var excludes = new List<string>(highPriority.ExcludePatterns);
            foreach (var pattern in lowPriority.ExcludePatterns)
            {
                if (!excludes.Contains(pattern, StringComparer.OrdinalIgnoreCase))
                {
                    excludes.Add(pattern);
                }
            }

            var presetIps = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
            var presetIpGroups = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in lowPriority.PresetIps)
            {
                presetIps[item.Key] = item.Value;
                if (lowPriority.PresetIpGroups.TryGetValue(item.Key, out var group))
                {
                    presetIpGroups[item.Key] = group;
                }
            }
            foreach (var item in highPriority.PresetIps)
            {
                presetIps[item.Key] = item.Value;
                if (highPriority.PresetIpGroups.TryGetValue(item.Key, out var group))
                {
                    presetIpGroups[item.Key] = group;
                }
            }

            var services = new Dictionary<string, ProxyServiceInfo>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in lowPriority.Services)
            {
                services[item.DomainPattern] = item;
            }
            foreach (var item in highPriority.Services)
            {
                services[item.DomainPattern] = item;
            }

            var dnsMappings = new List<DnsMapping>(highPriority.DnsMappings);
            foreach (var item in lowPriority.DnsMappings)
            {
                if (!dnsMappings.Any(x => string.Equals(x.DomainPattern, item.DomainPattern, StringComparison.OrdinalIgnoreCase)))
                {
                    dnsMappings.Add(item);
                }
            }

            return new ProxyRuleSet(rules, excludes, presetIps, presetIpGroups, dnsMappings, services.Values.ToList());
        }

        /// <summary>
        /// 只保留指定规则组。未分类和自定义规则始终保留。
        /// </summary>
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
            var presetIpGroups = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in PresetIps)
            {
                var group = ProxyRuleGroups.ResolvePresetGroup(item.Key, PresetIpGroups);
                if (string.IsNullOrEmpty(group) || enabledGroups.Contains(group))
                {
                    presetIps[item.Key] = item.Value;
                    if (!string.IsNullOrEmpty(group)) presetIpGroups[item.Key] = group;
                }
            }

            var services = Services.Where(x =>
                string.IsNullOrEmpty(x.Group) ||
                string.Equals(x.Group, ProxyRuleGroups.Custom, StringComparison.OrdinalIgnoreCase) ||
                enabledGroups.Contains(x.Group!)).ToList();

            return new ProxyRuleSet(rules, ExcludePatterns, presetIps, presetIpGroups, DnsMappings, services);
        }

        /// <summary>
        /// 移除已关闭的规则组和服务。默认全部开启，因此空集合表示不过滤。
        /// </summary>
        public ProxyRuleSet FilterDisabled(ISet<string> disabledGroups, ISet<string> disabledServices)
        {
            if (disabledGroups.Count == 0 && disabledServices.Count == 0) return this;

            var rules = new List<ProxyRule>(Rules.Count);
            foreach (var rule in Rules)
            {
                if (!string.IsNullOrEmpty(rule.Group) && disabledGroups.Contains(rule.Group)) continue;
                if (disabledServices.Contains(rule.DomainPattern)) continue;
                rules.Add(rule);
            }

            var presetIps = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
            var presetIpGroups = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in PresetIps)
            {
                var group = ResolveGroup(item.Key);
                if (!string.IsNullOrEmpty(group) && disabledGroups.Contains(group)) continue;
                if (disabledServices.Contains(item.Key)) continue;
                presetIps[item.Key] = item.Value;
                if (!string.IsNullOrEmpty(group)) presetIpGroups[item.Key] = group;
            }

            var dnsMappings = new List<DnsMapping>();
            foreach (var item in DnsMappings)
            {
                if (disabledServices.Contains(item.DomainPattern)) continue;
                if (!string.IsNullOrEmpty(item.Group) && disabledGroups.Contains(item.Group)) continue;
                dnsMappings.Add(item);
            }

            var services = new List<ProxyServiceInfo>(Services.Count);
            foreach (var item in Services)
            {
                if (disabledServices.Contains(item.DomainPattern)) continue;
                if (!string.IsNullOrEmpty(item.Group) && disabledGroups.Contains(item.Group!)) continue;
                services.Add(item);
            }

            return new ProxyRuleSet(rules, ExcludePatterns, presetIps, presetIpGroups, dnsMappings, services);
        }

        string? ResolveGroup(string domain)
        {
            if (PresetIpGroups.TryGetValue(domain, out var group) && !string.IsNullOrEmpty(group))
            {
                return group;
            }
            return ProxyRuleGroups.Classify(domain);
        }

        /// <summary>
        /// 统计规则组。服务 = 域名（或域名通配符），与 DevSidecar 的服务分组概念一致。
        /// </summary>
        public IReadOnlyList<ProxyRuleGroupStat> GetGroups()
        {
            var map = new Dictionary<string, ProxyRuleGroupStat>(StringComparer.OrdinalIgnoreCase);

            if (Services.Count > 0)
            {
                foreach (var service in Services)
                {
                    var group = string.IsNullOrEmpty(service.Group)
                        ? ResolveGroup(service.DomainPattern)
                        : service.Group;
                    Add(group, service.DomainPattern, service.RuleCount);
                }
            }
            else
            {
                // 兼容没有服务目录的旧缓存/自定义规则。
                var seenServices = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                void AddRule(string? group, string service)
                {
                    if (string.Equals(group, ProxyRuleGroups.Custom, StringComparison.OrdinalIgnoreCase)) return;
                    var id = string.IsNullOrEmpty(group) ? ProxyRuleGroups.Unclassified : group!;
                    if (!map.TryGetValue(id, out var stat))
                    {
                        stat = new ProxyRuleGroupStat(id, id);
                        map[id] = stat;
                    }
                    if (seenServices.Add(id + "\u0001" + service))
                    {
                        stat.Services.Add(service);
                    }
                    stat.RuleCount++;
                }

                foreach (var rule in Rules) AddRule(rule.Group, rule.DomainPattern);
                foreach (var item in PresetIps) AddRule(ResolveGroup(item.Key), item.Key);
                foreach (var item in DnsMappings)
                {
                    AddRule(string.IsNullOrEmpty(item.Group) ? ResolveGroup(item.DomainPattern) : item.Group, item.DomainPattern);
                }
            }

            void Add(string? group, string service, int ruleCount)
            {
                if (string.Equals(group, ProxyRuleGroups.Custom, StringComparison.OrdinalIgnoreCase)) return;
                var id = string.IsNullOrEmpty(group) ? ProxyRuleGroups.Unclassified : group!;
                if (!map.TryGetValue(id, out var stat))
                {
                    stat = new ProxyRuleGroupStat(id, id);
                    map[id] = stat;
                }
                if (!stat.Services.Contains(service, StringComparer.OrdinalIgnoreCase))
                {
                    stat.Services.Add(service);
                }
                stat.RuleCount += ruleCount;
            }

            var list = map.Values.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase).ToList();
            foreach (var item in list) item.Services.Sort(StringComparer.OrdinalIgnoreCase);
            return list;
        }

        /// <summary>
        /// 判断某个主机名会被哪些规则/预置 IP 命中，供“匹配域名”搜索使用。
        /// </summary>
        public IReadOnlyList<string> MatchServices(string host)
        {
            var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(host)) return Array.Empty<string>();

            if (Services.Count > 0)
            {
                foreach (var item in Services)
                {
                    if (DomainPatternMatcher.IsMatch(host, item.DomainPattern))
                    {
                        result.Add(item.DomainPattern);
                    }
                }
                return result.ToList();
            }

            foreach (var rule in Rules)
            {
                if (DomainPatternMatcher.IsMatch(host, rule.DomainPattern))
                {
                    result.Add(rule.DomainPattern);
                }
            }
            foreach (var item in PresetIps)
            {
                if (DomainPatternMatcher.IsMatch(host, item.Key))
                {
                    result.Add(item.Key);
                }
            }
            foreach (var item in DnsMappings)
            {
                if (DomainPatternMatcher.IsMatch(host, item.DomainPattern))
                {
                    result.Add(item.DomainPattern);
                }
            }
            return result.ToList();
        }
    }

    public sealed class ProxyRuleGroupStat
    {
        public ProxyRuleGroupStat(string id, string name)
        {
            Id = id;
            Name = name;
        }

        public string Id { get; }

        public string Name { get; }

        public List<string> Services { get; } = new();

        public int RuleCount { get; set; }

        public int ServiceCount => Services.Count;
    }

    /// <summary>
    /// DevSidecar dns.mapping 的一条映射：域名 → HTTPS DoH 接口。
    /// </summary>
    public sealed class DnsMapping
    {
        public DnsMapping(string domainPattern, string endpoint, string? group)
        {
            DomainPattern = domainPattern;
            Endpoint = endpoint;
            Group = group;
        }

        public string DomainPattern { get; }

        public string Endpoint { get; }

        public string? Group { get; }
    }

    /// <summary>
    /// 服务目录中的一项。一个服务 = 配置里出现的一个域名/通配符。
    /// </summary>
    public sealed class ProxyServiceInfo
    {
        public ProxyServiceInfo(string domainPattern, string? group)
        {
            DomainPattern = domainPattern;
            Group = group;
        }

        public string DomainPattern { get; }

        public string? Group { get; set; }

        /// <summary>可执行的 MITM/分片规则数量。</summary>
        public int RuleCount { get; set; }

        /// <summary>预置 IP 数量。</summary>
        public int PresetIpCount { get; set; }

        /// <summary>DevSidecar dns.mapping 里配置的 provider 名称。</summary>
        public string? DnsProvider { get; set; }

        /// <summary>可直接使用的 HTTPS DoH 接口。</summary>
        public string? DnsEndpoint { get; set; }

        public bool InWhiteList { get; set; }

        public bool InEch { get; set; }

        public bool InNat64 { get; set; }

        public ProxyServiceInfo Clone()
            => new(DomainPattern, Group)
            {
                RuleCount = RuleCount,
                PresetIpCount = PresetIpCount,
                DnsProvider = DnsProvider,
                DnsEndpoint = DnsEndpoint,
                InWhiteList = InWhiteList,
                InEch = InEch,
                InNat64 = InNat64,
            };
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
            if (pattern.Length > 512) return false;

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
            var regex = RegexCache.Get(pattern);
            if (regex == null)
            {
                matched = false;
                return false;
            }

            try
            {
                matched = regex.IsMatch(host);
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
