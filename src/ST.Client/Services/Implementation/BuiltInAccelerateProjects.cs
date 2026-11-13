using System.Application.Models;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using EProxyType = System.Application.ProxyType;

namespace System.Application.Services.Implementation
{
    /// <summary>
    /// 客户端内置的加速项目，不依赖服务端下发。
    /// </summary>
    public static class BuiltInAccelerateProjects
    {
        /// <summary>
        /// GitHub 的 SNI 伪装规则：连接仍然指向 GitHub，只把上游 TLS 的 SNI 改成 baidu.com，
        /// 用于绕过基于 SNI 的阻断。需要 MITM/根证书；免证书模式下会退化为隧道。
        /// </summary>
        public static AccelerateProjectGroupDTO CreateGitHubGroup()
        {
            var items = new List<AccelerateProjectDTO>();
            void Add(string name, string domain, string? ip = null)
            {
                items.Add(CreateItem(name, domain, domain, "baidu.com", EProxyType.Local, ip, items.Count));
            }

            Add("GitHub 网页", "github.com", "140.82.121.4");
            Add("GitHub API", "api.github.com");
            Add("GitHub Gist", "gist.github.com");
            Add("GitHub 静态资源", "github.githubassets.com", "185.199.108.154");
            Add("GitHub 头像", "avatars.githubusercontent.com");
            Add("GitHub 图片缓存", "camo.githubusercontent.com");
            Add("GitHub 统计", "collector.github.com");
            Add("GitHub Raw", "raw.githubusercontent.com", "185.199.108.133");
            Add("GitHub Gist Raw", "gist.githubusercontent.com");
            Add("GitHub Objects", "objects.githubusercontent.com");
            Add("GitHub Release Assets", "release-assets.githubusercontent.com");
            Add("GitHub 用户图片", "user-images.githubusercontent.com");
            Add("GitHub 私有用户图片", "private-user-images.githubusercontent.com");
            Add("GitHub Media/LFS", "media.githubusercontent.com");

            return new AccelerateProjectGroupDTO
            {
                Name = "GitHub SNI 加速",
                ImageId = Guid.Empty,
                Enable = false,
                Order = 900,
                Items = items,
            };
        }

        /// <summary>
        /// Hugging Face 的 SNI 镜像规则：上游指向 huggingface.cn，SNI 也使用 huggingface.cn。
        /// 私有/gated 请求会携带 Authorization，Titanium 侧会跳过第三方镜像直连。
        /// </summary>
        public static AccelerateProjectGroupDTO CreateHuggingFaceGroup()
        {
            var items = new List<AccelerateProjectDTO>();
            void Add(string name, string domain)
            {
                items.Add(CreateItem(name, domain, "huggingface.cn", "huggingface.cn", EProxyType.ServerAccelerate, null, items.Count));
            }

            Add("Hugging Face 主站", "huggingface.co");
            Add("Hugging Face CDN LFS", "cdn-lfs.huggingface.co");
            Add("Hugging Face CDN LFS US", "cdn-lfs-us-1.hf.co");
            Add("Hugging Face CDN LFS EU", "cdn-lfs-eu-1.hf.co");

            return new AccelerateProjectGroupDTO
            {
                Name = "Hugging Face SNI 镜像",
                ImageId = Guid.Empty,
                Enable = false,
                Order = 1000,
                Items = items,
            };
        }

        /// <summary>
        /// Pixiv（P站）图片 CDN 的 SNI 伪装。Pixiv 图片域名被按 SNI 阻断，
        /// 连接仍然指向 Pixiv 的真实 IP，只把上游 SNI 改成 baidu.com。
        /// </summary>
        public static AccelerateProjectGroupDTO CreatePixivGroup()
        {
            var items = new List<AccelerateProjectDTO>();
            void Add(string name, string domain, string ip, string? requestHeaders = null)
            {
                items.Add(CreateItem(name, domain, domain, "baidu.com", EProxyType.Local, ip, items.Count, requestHeaders));
            }

            Add("Pixiv 图片 i.pximg.net", "i.pximg.net", "210.140.139.132", "referer=https://www.pixiv.net/");
            Add("Pixiv 图片 s.pximg.net", "s.pximg.net", "210.140.139.132", "referer=https://www.pixiv.net/");
            Add("Pixiv 静态 a.pixiv.org", "a.pixiv.org", "210.140.139.182");
            Add("Pixiv Fanbox", "www.fanbox.cc", "210.140.139.155");
            Add("Pixiv API", "api.fanbox.cc", "172.64.146.116");

            return new AccelerateProjectGroupDTO
            {
                Name = "Pixiv / P站 SNI 加速",
                ImageId = Guid.Empty,
                Enable = false,
                Order = 950,
                Items = items,
            };
        }

        static AccelerateProjectDTO CreateItem(
            string name,
            string domain,
            string forwardDomain,
            string serverName,
            EProxyType proxyType,
            string? forwardIp,
            int order,
            string? requestHeaders = null) => new()
            {
                Name = name,
                DomainNames = domain,
                ForwardDomainName = forwardDomain,
                ForwardDomainIP = forwardIp ?? string.Empty,
                ServerName = serverName,
                PortId = 443,
                ProxyType = proxyType,
                Enable = false,
                Id = CreateId(domain),
                Order = order,
                RequestHeaders = requestHeaders,
            };

        static Guid CreateId(string value)
        {
            using var md5 = MD5.Create();
            return new Guid(md5.ComputeHash(Encoding.UTF8.GetBytes("WattToolkit.Accelerate." + value)));
        }
    }
}
