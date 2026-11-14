using System.Security.Cryptography;
using System.Text;

// ReSharper disable once CheckNamespace
namespace BD.WTTS.Services.Implementation;

/// <summary>
/// 客户端内置加速组。
/// <para>服务端加速项目接口不可用（自建包、离线环境、接口拒绝非官方客户端）时，仍能在加速页显示并工作的兜底规则。</para>
/// <para>规则思路来自 DevSidecar / FastGithub：本地 MITM 后伪装上游 TLS 的 SNI（<see cref="AccelerateProjectDTO.FakeServerName"/>），
/// 客户端仍然按真实域名校验证书，因此不需要把私有仓库交给镜像。</para>
/// </summary>
public static class BuiltInAccelerateGroups
{
    public const string GitHubGroupName = "GitHub（内置 SNI 加速）";

    public const string HuggingFaceGroupName = "Hugging Face（内置 SNI 加速）";

    /// <summary>
    /// 伪装用的 SNI。GitHub 使用 baidu.com 是 DevSidecar 的默认值，作用只是让 DPI 看不到目标域名。
    /// </summary>
    public const string GitHubFakeServerName = "baidu.com";

    /// <summary>
    /// Hugging Face 使用的伪装 SNI，与 DevSidecar 默认配置保持一致。
    /// </summary>
    public const string HuggingFaceFakeServerName = "huggingface.cn";

    public static IReadOnlyList<AccelerateProjectGroupDTO> CreateAll()
        => new[]
        {
            CreateGitHub(),
            CreateHuggingFace(),
        };

    public static AccelerateProjectGroupDTO CreateGitHub()
    {
        var items = new List<AccelerateProjectDTO>
        {
            Item("GitHub 网页", "github.com", "baidu.com", 1),
            Item("GitHub API", "api.github.com", "baidu.com", 2),
            Item("GitHub Gist", "gist.github.com", "baidu.com", 3),
            Item("GitHub 静态资源", "github.githubassets.com", "baidu.com", 4),
            Item("GitHub 头像", "avatars.githubusercontent.com", "baidu.com", 5),
            Item("GitHub 图片缓存", "camo.githubusercontent.com", "baidu.com", 6),
            Item("GitHub 统计", "collector.github.com", "baidu.com", 7),
            Item("GitHub Raw", "raw.githubusercontent.com", "baidu.com", 8),
            Item("GitHub Gist Raw", "gist.githubusercontent.com", "baidu.com", 9),
            Item("GitHub Objects", "objects.githubusercontent.com", "baidu.com", 10),
            Item("GitHub Release Assets", "release-assets.githubusercontent.com", "baidu.com", 11),
            Item("GitHub 用户图片", "user-images.githubusercontent.com", "baidu.com", 12),
            Item("GitHub 私有用户图片", "private-user-images.githubusercontent.com", "baidu.com", 13),
            Item("GitHub Media/LFS", "media.githubusercontent.com", "baidu.com", 14),
        };

        return Group(GitHubGroupName, 900, items);
    }

    public static AccelerateProjectGroupDTO CreateHuggingFace()
    {
        var items = new List<AccelerateProjectDTO>
        {
            Item("Hugging Face 主站", "huggingface.co", "huggingface.cn", 1),
            Item("Hugging Face 静态资源", "cdn-lfs.huggingface.co", "huggingface.cn", 2),
            Item("Hugging Face Xet", "cas-bridge.xethub.hf.co", "huggingface.cn", 3),
            Item("Hugging Face 传输", "transfer.xethub.hf.co", "huggingface.cn", 4),
            Item("Hugging Face 镜像站", "hf-mirror.com", "huggingface.cn", 5),
        };

        return Group(HuggingFaceGroupName, 1000, items);
    }

    static AccelerateProjectGroupDTO Group(string name, long order, List<AccelerateProjectDTO> items)
        => new()
        {
            Name = name,
            Order = order,
            Items = items,
        };

    /// <summary>
    /// 与目标域名同源的本地加速项：仍然连接原始域名，只在 TLS 握手时伪装 SNI。
    /// </summary>
    static AccelerateProjectDTO Item(string name, string domain, string fakeServerName, long order)
        => new()
        {
            Id = CreateId("BuiltInAccelerate." + domain),
            Name = name,
            MatchDomainNames = domain,
            ListenDomainNames = domain,
            ForwardDomainNames = domain,
            FakeServerName = fakeServerName,
            // 伪装 SNI 后上游返回的证书域名与真实域名不一致，必须忽略上游证书校验；
            // 客户端侧的证书仍然由本地根证书按真实域名签发，安全性不变。
            IgnoreSSLCertVerification = true,
            ProxyType = ProxyType.Local,
            Port = 443,
            Order = order,
        };

    static Guid CreateId(string value)
    {
        using var md5 = MD5.Create();
        return new Guid(md5.ComputeHash(Encoding.UTF8.GetBytes(value)));
    }
}
