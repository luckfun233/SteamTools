namespace NetAccel.Core.Rules;

public sealed class ProxyRuleGroupInfo
{
    public ProxyRuleGroupInfo(string id, string name, string description, bool enabledByDefault)
    {
        Id = id;
        Name = name;
        Description = description;
        EnabledByDefault = enabledByDefault;
    }

    public string Id { get; }
    public string Name { get; }
    public string Description { get; }
    public bool EnabledByDefault { get; }
}

/// <summary>
/// 把 DevSidecar 的声明式规则按站点归类，供界面按组启用。
/// </summary>
public static class ProxyRuleGroups
{
    public const string GitHub = "github";
    public const string HuggingFace = "huggingface";
    public const string Pixiv = "pixiv";
    public const string Google = "google";
    public const string YouTube = "youtube";
    public const string Wikipedia = "wikipedia";
    public const string Docker = "docker";
    public const string Reddit = "reddit";
    public const string Steam = "steam";
    public const string Other = "other";
    public const string Custom = "custom";

    public const string DefaultEnabled = GitHub + ";" + HuggingFace + ";" + Pixiv;

    public static IReadOnlyList<ProxyRuleGroupInfo> All { get; } = new[]
    {
        new ProxyRuleGroupInfo(GitHub, "GitHub", "网页、API、Raw、Gist、头像与 Release 资源", true),
        new ProxyRuleGroupInfo(HuggingFace, "Hugging Face", "模型下载、LFS CDN 与镜像", true),
        new ProxyRuleGroupInfo(Pixiv, "Pixiv / P站", "Pixiv 网页、图片与 Fanbox 资源", true),
        new ProxyRuleGroupInfo(Google, "Google", "搜索、字体、reCAPTCHA 与静态资源", false),
        new ProxyRuleGroupInfo(YouTube, "YouTube", "网页、缩略图与视频 CDN", false),
        new ProxyRuleGroupInfo(Wikipedia, "Wikipedia", "维基百科及姊妹项目", false),
        new ProxyRuleGroupInfo(Docker, "Docker Hub", "镜像仓库与官网", false),
        new ProxyRuleGroupInfo(Reddit, "Reddit", "网页与媒体资源", false),
        new ProxyRuleGroupInfo(Steam, "Steam 社区", "社区、商店与静态资源", false),
        new ProxyRuleGroupInfo(Other, "其它站点", "npm、Maven、Instagram、Archive 等长尾规则", false),
    };

    static readonly (string Id, string[] Keywords)[] keywordMap =
    {
        (HuggingFace, new[] { "huggingface", "hf.co" }),
        (Pixiv, new[] { "pixiv", "pximg", "fanbox" }),
        (GitHub, new[] { "github", "githubusercontent", "githubassets", "gist." }),
        (YouTube, new[] { "youtube", "youtu.be", "ytimg", "ggpht" }),
        (Wikipedia, new[] { "wikipedia", "wikimedia", "wikinews", "wiktionary", "wikiversity", "wikidata", "wikiquote", "wikivoyage", "wikifunctions", "wikibooks", "mediawiki", "w.wiki" }),
        (Docker, new[] { "docker" }),
        (Reddit, new[] { "reddit", "redd.it" }),
        (Steam, new[] { "steam" }),
        (Google, new[] { "google", "gstatic", "googlevideo", "g.cn", "blogger", "goog", "antigravity" }),
    };

    public static string? Classify(string domainPattern)
    {
        if (string.IsNullOrWhiteSpace(domainPattern)) return null;

        var value = domainPattern.Trim().ToLowerInvariant();
        foreach (var (id, keywords) in keywordMap)
        {
            foreach (var keyword in keywords)
            {
                if (value.Contains(keyword, StringComparison.Ordinal)) return id;
            }
        }
        return Other;
    }

    public static ProxyRuleGroupInfo? Get(string id)
        => All.FirstOrDefault(x => string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase));

    public static HashSet<string> ParseEnabled(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return new HashSet<string>(DefaultEnabled.Split(';'), StringComparer.OrdinalIgnoreCase);
        }

        return new HashSet<string>(
            value.Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(x => x.Trim())
                .Where(x => x.Length > 0),
            StringComparer.OrdinalIgnoreCase);
    }

    public static string ToStorage(IEnumerable<string> ids)
        => string.Join(";", ids.Distinct(StringComparer.OrdinalIgnoreCase));

    public static string GetDisplayName(string? id)
        => Get(id ?? string.Empty)?.Name ?? id ?? string.Empty;
}
