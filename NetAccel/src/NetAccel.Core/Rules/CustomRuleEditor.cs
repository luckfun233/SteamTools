namespace NetAccel.Core.Rules;

public enum QuickRuleAction
{
    Sni = 0,
    RemoveSni = 1,
    Block = 2,
    PresetIp = 3,
    Exclude = 4,
}

/// <summary>
/// 自定义规则快速编辑：把界面上的“域名 + 动作 + 值”转换成一条规则，
/// 再序列化回编辑器。对应原项目自定义规则页的快速添加能力。
/// </summary>
public static class CustomRuleEditor
{
    public static bool TryApply(
        ProxyRuleSet current,
        QuickRuleAction action,
        string domain,
        string? value,
        out ProxyRuleSet result,
        out string? error)
    {
        result = current;
        error = null;

        domain = domain?.Trim() ?? string.Empty;
        value = value?.Trim();

        if (domain.Length == 0)
        {
            error = "请输入域名，例如 github.com 或 *.githubusercontent.com。";
            return false;
        }

        if (domain.IndexOfAny(new[] { '\r', '\n', ' ', '\t' }) >= 0)
        {
            error = "域名中不能包含空格或换行。";
            return false;
        }

        switch (action)
        {
            case QuickRuleAction.Sni:
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    error = "SNI 伪装需要填写目标域名，例如 baidu.com。";
                    return false;
                }
                result = UpsertRule(current, new ProxyRule
                {
                    DomainPattern = domain,
                    Group = ProxyRuleGroups.Custom,
                    Sni = value,
                    Description = "快速添加：SNI 伪装",
                });
                return true;
            }
            case QuickRuleAction.RemoveSni:
                result = UpsertRule(current, new ProxyRule
                {
                    DomainPattern = domain,
                    Group = ProxyRuleGroups.Custom,
                    Sni = "none",
                    Description = "快速添加：移除 SNI",
                });
                return true;
            case QuickRuleAction.Block:
                result = UpsertRule(current, new ProxyRule
                {
                    DomainPattern = domain,
                    Group = ProxyRuleGroups.Custom,
                    Block = true,
                    Description = "快速添加：阻断",
                });
                return true;
            case QuickRuleAction.PresetIp:
            {
                var ips = (value ?? string.Empty)
                    .Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(x => x.Trim())
                    .Where(x => System.Net.IPAddress.TryParse(x, out _))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();

                if (ips.Length == 0)
                {
                    error = "预置 IP 需要填写至少一个合法 IP，多个 IP 用逗号分隔。";
                    return false;
                }

                var presetIps = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
                foreach (var item in current.PresetIps) presetIps[item.Key] = item.Value;
                presetIps[domain] = ips;

                result = new ProxyRuleSet(current.Rules, current.ExcludePatterns, presetIps);
                return true;
            }
            case QuickRuleAction.Exclude:
            {
                var excludes = current.ExcludePatterns.ToList();
                if (!excludes.Contains(domain, StringComparer.OrdinalIgnoreCase)) excludes.Add(domain);

                var presetIps = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
                foreach (var item in current.PresetIps) presetIps[item.Key] = item.Value;

                result = new ProxyRuleSet(current.Rules.ToList(), excludes, presetIps);
                return true;
            }
            default:
                error = "未知动作。";
                return false;
        }
    }

    static ProxyRuleSet UpsertRule(ProxyRuleSet current, ProxyRule rule)
    {
        var rules = current.Rules.ToList();

        // 同域名、同路径的快速规则直接替换，避免重复添加。
        rules.RemoveAll(x =>
            string.Equals(x.DomainPattern, rule.DomainPattern, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(x.Group, ProxyRuleGroups.Custom, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(x.PathPattern, rule.PathPattern, StringComparison.Ordinal));

        rules.Add(rule);

        var presetIps = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in current.PresetIps) presetIps[item.Key] = item.Value;

        return new ProxyRuleSet(rules, current.ExcludePatterns.ToList(), presetIps);
    }
}
