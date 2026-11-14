using System.Text;
using System.Text.Json;
using NetAccel.Core.Models;

namespace NetAccel.Core.Rules;

/// <summary>
/// 用户自定义规则存储。文件沿用 DevSidecar 的 intercepts 结构，
/// 允许省略 server 包装，也允许 JSON5 注释和尾随逗号。
/// </summary>
public sealed class CustomRuleStore
{
    public const string SampleJson = @"{
  // 自定义规则会和远程 DevSidecar 规则合并，且优先匹配。
  // 目录：{0}
  // 支持字段：sni、verifyHost、redirect、proxy、backup、abort、desc、
  //          requestReplace.headers、responseReplace.headers
  intercepts: {
    // 示例：免证书模式下只改 SNI（不安装根证书）
    ""example.com"": {
      "".*"": {
        sni: ""baidu.com"",
        desc: ""示例：SNI 伪装"",
      },
    },
    // 示例：整个域名直连，不参与加速
    ""intranet.example.com"": {
      "".*"": {
        desc: ""示例：直连"",
      },
    },
  },
  // 可选：预置 IP，sidecar 会并行探测并选择延迟最低的
  preSetIpList: {
    ""example.com"": [""1.2.3.4"", ""5.6.7.8""],
  },
  // 可选：命中后直连，不进入镜像/中继
  excludeIpList: {
    ""*.local"": true,
  },
}";

    readonly string filePath;

    public CustomRuleStore(string? filePath = null)
    {
        this.filePath = filePath ?? AppPaths.CustomRulesFile;
    }

    public string FilePath => filePath;

    public static string BuildSample(string filePath) => string.Format(SampleJson, filePath);

    public string GetText()
    {
        try
        {
            if (File.Exists(filePath)) return File.ReadAllText(filePath);
        }
        catch
        {
            // 读取失败时返回示例，至少让用户能编辑
        }
        return BuildSample(filePath);
    }

    public bool HasFile()
    {
        try
        {
            return File.Exists(filePath);
        }
        catch
        {
            return false;
        }
    }

    public bool TryLoad(out ProxyRuleSet rules, out string? error)
    {
        rules = ProxyRuleSet.Empty;
        error = null;

        try
        {
            if (!File.Exists(filePath)) return true;
            return TryValidate(File.ReadAllText(filePath), out rules, out error);
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    public static bool TryValidate(string text, out ProxyRuleSet rules, out string? error)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            rules = ProxyRuleSet.Empty;
            error = null;
            return true;
        }

        return DevSidecarConfigLoader.TryParse(text, ProxyRuleGroups.Custom, out rules, out error);
    }

    public bool Save(string text, out ProxyRuleSet rules, out string? error)
    {
        if (!TryValidate(text, out rules, out error)) return false;

        try
        {
            var dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            var tmp = filePath + ".tmp";
            File.WriteAllText(tmp, text);
            if (File.Exists(filePath)) File.Delete(filePath);
            File.Move(tmp, filePath);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    public void Delete()
    {
        try
        {
            if (File.Exists(filePath)) File.Delete(filePath);
        }
        catch
        {
            // ignore
        }
    }

    /// <summary>把规则集序列化为可再次编辑的 DevSidecar 风格 JSON。</summary>
    public static string Serialize(ProxyRuleSet rules)
    {
        var sb = new StringBuilder();
        sb.AppendLine("{");

        var domains = new List<string>();
        var byDomain = new Dictionary<string, List<ProxyRule>>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in rules.Rules)
        {
            if (!byDomain.TryGetValue(rule.DomainPattern, out var list))
            {
                list = new List<ProxyRule>();
                byDomain[rule.DomainPattern] = list;
                domains.Add(rule.DomainPattern);
            }
            list.Add(rule);
        }

        sb.AppendLine("  intercepts: {");
        for (var i = 0; i < domains.Count; i++)
        {
            var domain = domains[i];
            sb.Append("    ").Append(Quote(domain)).AppendLine(": {");
            var pathRules = byDomain[domain];
            for (var j = 0; j < pathRules.Count; j++)
            {
                var rule = pathRules[j];
                sb.Append("      ").Append(Quote(rule.PathPattern ?? ".*")).AppendLine(": {");
                AppendRuleFields(sb, rule);
                sb.Append("      }");
                if (j < pathRules.Count - 1) sb.Append(',');
                sb.AppendLine();
            }
            sb.Append("    }");
            if (i < domains.Count - 1) sb.Append(',');
            sb.AppendLine();
        }
        sb.AppendLine("  },");

        sb.AppendLine("  preSetIpList: {");
        var presetIndex = 0;
        foreach (var item in rules.PresetIps)
        {
            sb.Append("    ").Append(Quote(item.Key)).Append(": [");
            for (var i = 0; i < item.Value.Count; i++)
            {
                if (i > 0) sb.Append(", ");
                sb.Append(Quote(item.Value[i]));
            }
            sb.Append(']');
            if (++presetIndex < rules.PresetIps.Count) sb.Append(',');
            sb.AppendLine();
        }
        sb.AppendLine("  },");

        sb.AppendLine("  excludeIpList: {");
        for (var i = 0; i < rules.ExcludePatterns.Count; i++)
        {
            sb.Append("    ").Append(Quote(rules.ExcludePatterns[i])).Append(": true");
            if (i < rules.ExcludePatterns.Count - 1) sb.Append(',');
            sb.AppendLine();
        }
        sb.AppendLine("  },");

        sb.AppendLine("}");
        return sb.ToString();
    }

    static void AppendRuleFields(StringBuilder sb, ProxyRule rule)
    {
        var fields = new List<string>();
        if (rule.Block) fields.Add("abort: true");
        if (!string.IsNullOrEmpty(rule.Sni)) fields.Add("sni: " + Quote(rule.Sni));
        if (!string.IsNullOrEmpty(rule.VerifyHost)) fields.Add("verifyHost: " + Quote(rule.VerifyHost));
        if (!string.IsNullOrEmpty(rule.Redirect)) fields.Add("redirect: " + Quote(rule.Redirect));
        if (!string.IsNullOrEmpty(rule.Proxy)) fields.Add("proxy: " + Quote(rule.Proxy));
        if (rule.BackupProxies.Count > 0)
        {
            fields.Add("backup: [" + string.Join(", ", rule.BackupProxies.Select(Quote)) + "]");
        }
        if (rule.UnVerifySsl) fields.Add("unVerifySsl: true");
        if (rule.RequestHeaders.Count > 0) fields.Add(BuildHeaderBlock("requestReplace", rule.RequestHeaders));
        if (rule.ResponseHeaders.Count > 0) fields.Add(BuildHeaderBlock("responseReplace", rule.ResponseHeaders));
        if (!string.IsNullOrEmpty(rule.Description)) fields.Add("desc: " + Quote(rule.Description));

        for (var i = 0; i < fields.Count; i++)
        {
            AppendIndented(sb, fields[i], 8);
            if (i < fields.Count - 1) sb.Append(',');
            sb.AppendLine();
        }
    }

    static string BuildHeaderBlock(string name, IReadOnlyDictionary<string, string?> headers)
    {
        var sb = new StringBuilder();
        sb.Append(name).AppendLine(": {");
        sb.AppendLine("  headers: {");
        var index = 0;
        foreach (var item in headers)
        {
            sb.Append("    ").Append(Quote(item.Key)).Append(": ").Append(Quote(item.Value ?? "[remove]"));
            if (++index < headers.Count) sb.Append(',');
            sb.AppendLine();
        }
        sb.AppendLine("  },");
        sb.Append('}');
        return sb.ToString();
    }

    static void AppendIndented(StringBuilder target, string text, int spaces)
    {
        var indent = new string(' ', spaces);
        var lines = text.Replace("\r\n", "\n").Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (i > 0) target.AppendLine();
            if (lines[i].Length > 0) target.Append(indent).Append(lines[i]);
        }
    }

    static string Quote(string value) => JsonSerializer.Serialize(value);
}
