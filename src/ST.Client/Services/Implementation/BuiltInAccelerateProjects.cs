using System.Application.Models;
using System.Collections.Generic;

namespace System.Application.Services.Implementation
{
    /// <summary>
    /// 客户端内置的加速项目，不依赖服务端下发。
    /// </summary>
    public static class BuiltInAccelerateProjects
    {
        public static readonly Guid HuggingFaceItemId = Guid.Parse("1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d");

        /// <summary>
        /// Hugging Face 公开镜像。
        /// 私有/gated 请求会携带 Authorization，Titanium 侧会跳过镜像直连；
        /// 免证书隧道模式下该规则会退化为直连。
        /// </summary>
        public static AccelerateProjectGroupDTO CreateHuggingFaceGroup() => new()
        {
            Name = "Hugging Face",
            ImageId = Guid.Empty,
            Enable = false,
            Order = 1000,
            Items = new List<AccelerateProjectDTO>
            {
                new()
                {
                    Name = "Hugging Face 公开镜像",
                    DomainNames = "huggingface.co;hf.co",
                    ForwardDomainName = "https://hf-mirror.com",
                    PortId = 443,
                    Redirect = true,
                    Enable = false,
                    Id = HuggingFaceItemId,
                    Order = 0,
                },
            },
        };
    }
}
