using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Titanium.Web.Proxy.Network;

namespace System.Application.Services.Implementation;

sealed partial class TitaniumCertificateManagerImpl : CertificateManagerImpl, ICertificateManager
{
    readonly CertificateManager manager;

    public TitaniumCertificateManagerImpl(
        IPlatformService platformService,
        IReverseProxyService reverseProxyService,
        CertificateManager manager) : base(platformService, reverseProxyService)
    {
        // 可选地设置证书引擎
        manager.CertificateEngine = CertificateEngine.BouncyCastle;
        //manager.PfxPassword = $"{CertificateName}";
        manager.PfxFilePath = Interface.PfxFilePath;
        manager.RootCertificateName = IReverseProxyService.RootCertificateName;

        // mac 和 ios 的证书信任时间不能超过300天
        manager.CertificateValidDays = ICertificateManager.CertificateValidDays;
        //manager.SaveFakeCertificates = true;

        manager.RootCertificate = manager.LoadRootCertificate();

        // 免证书隧道模式不会使用 MITM，但 Titanium 启动时需要有一个根证书对象。
        // 这里只生成/加载本地证书，不导入系统信任区。
        if (manager.RootCertificate == null)
        {
            try
            {
                manager.CreateRootCertificate(true);
            }
            catch (Exception ex)
            {
                Log.Warn("TitaniumCertificateManager", ex, "创建本地根证书失败，免证书隧道模式可能无法启动。");
            }
        }

        this.manager = manager;
    }

    public override X509Certificate2? RootCertificate
    {
        get => manager.RootCertificate;
        set => manager.RootCertificate = value;
    }

    protected override X509Certificate2? LoadRootCertificate()
    {
        try
        {
            return manager.LoadRootCertificate();
        }
        catch (PlatformNotSupportedException)
        {
            // https://github.com/dotnet/runtime/issues/71603
            return null;
        }
        catch (CryptographicException e)
        {
            if (e.InnerException is PlatformNotSupportedException) return null;
            throw;
        }
    }

    protected override bool SharedCreateRootCertificate()
        => manager.CreateRootCertificate(true);

    protected override void SharedRemoveTrustedRootCertificate()
        => manager.RemoveTrustedRootCertificate(true);

    protected override void SharedTrustRootCertificate()
        => manager.TrustRootCertificate(true);
}
