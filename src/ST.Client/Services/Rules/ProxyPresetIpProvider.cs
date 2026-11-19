using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Application.Settings;

namespace System.Application.ProxyRules
{
    /// <summary>
    /// 预置 IP 的统一来源：DevSidecar preSetIpList + Hugging Face 兜底 IP。
    /// 免证书模式下 DNS 可能被系统 Private DNS / 浏览器 DoH 绕过，
    /// 所以 sidecar 在拿到 SNI 后也会直接用这些 IP 重连。
    /// </summary>
    public static class ProxyPresetIpProvider
    {
        public static IReadOnlyList<string> GetCandidates(string host, ProxyRuleSet? rules = null)
        {
            var result = new List<string>();
            if (string.IsNullOrWhiteSpace(host)) return result;

            rules ??= ProxyRuleEngine.Current;
            foreach (var ip in rules.GetPresetIps(host))
            {
                Add(result, ip);
            }

            if (ProxySettings.EnableHuggingFaceFallback.Value && IsHuggingFaceHost(host))
            {
                foreach (var ip in GetHuggingFaceFallbackIps(host))
                {
                    Add(result, ip);
                }
            }

            return result;
        }

        public static IReadOnlyList<IPAddress> GetCandidateAddresses(string host, ProxyRuleSet? rules = null)
            => GetCandidates(host, rules)
                .Select(x => IPAddress.TryParse(x, out var ip) ? ip : null)
                .Where(x => x != null)
                .Select(x => x!)
                .Distinct()
                .ToList();

        public static bool IsHuggingFaceHost(string host)
        {
            if (string.IsNullOrEmpty(host)) return false;
            return host.Equals("hf.co", StringComparison.OrdinalIgnoreCase) ||
                   host.EndsWith(".hf.co", StringComparison.OrdinalIgnoreCase) ||
                   host.EndsWith(".huggingface.co", StringComparison.OrdinalIgnoreCase) ||
                   host.Equals("huggingface.co", StringComparison.OrdinalIgnoreCase);
        }

        public static IReadOnlyList<string> GetHuggingFaceFallbackIps(string host)
        {
            if (host.Equals("hf.co", StringComparison.OrdinalIgnoreCase))
            {
                return ProxySettings.HfCoIpList.Split(';');
            }
            if (host.EndsWith(".hf.co", StringComparison.OrdinalIgnoreCase))
            {
                return ProxySettings.HfCdnIpList.Split(';');
            }
            return ProxySettings.HuggingFaceApexIpList
                .Split(';')
                .Concat(ProxySettings.HuggingFaceIpv6List.Split(';'))
                .ToArray();
        }

        static void Add(List<string> list, string value)
        {
            var ip = value?.Trim();
            if (string.IsNullOrEmpty(ip)) return;
            if (!IPAddress.TryParse(ip, out _)) return;
            if (!list.Contains(ip, StringComparer.OrdinalIgnoreCase)) list.Add(ip);
        }
    }
}
