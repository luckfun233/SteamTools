using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Application.UI.Resx;
using System.Application.UI.ViewModels;

namespace System.Application.Services.Implementation;

abstract partial class CertificateManagerImpl
{
    protected const string TAG = "CertificateManager";

    protected readonly IPlatformService platformService;
    protected readonly IReverseProxyService reverseProxyService;

    protected ICertificateManager Interface => (ICertificateManager)this;

    public CertificateManagerImpl(
        IPlatformService platformService,
        IReverseProxyService reverseProxyService)
    {
        this.platformService = platformService;
        this.reverseProxyService = reverseProxyService;
    }

    /// <inheritdoc cref="ICertificateManager.RootCertificate"/>
    public abstract X509Certificate2? RootCertificate { get; set; }

    /// <inheritdoc cref="ICertificateManager.PfxPassword"/>
    public virtual string? PfxPassword { get; set; }

    protected abstract X509Certificate2? LoadRootCertificate();

    protected abstract void SharedTrustRootCertificate();

    protected abstract bool SharedCreateRootCertificate();

    protected abstract void SharedRemoveTrustedRootCertificate();

    static readonly object lockGenerateCertificate = new();

    /// <inheritdoc cref="ICertificateManager.GetCerFilePathGeneratedWhenNoFileExists"/>
    public string? GetCerFilePathGeneratedWhenNoFileExists()
    {
        var filePath = Interface.CerFilePath;
        lock (lockGenerateCertificate)
        {
            if (!File.Exists(filePath))
            {
                if (!GenerateCertificateUnlock(filePath)) return null;
            }
            return filePath;
        }
    }

    /// <summary>
    /// (❌🔒)生成 Root 证书
    /// </summary>
    /// <param name="filePath"></param>
    /// <returns></returns>
    bool GenerateCertificateUnlock(string filePath)
    {
        var result = SharedCreateRootCertificate();
        if (!result || RootCertificate == null)
        {
            Log.Error(TAG, AppResources.CreateCertificateFaild);
            Toast.Show(AppResources.CreateCertificateFaild);
            return false;
        }

        RootCertificate.SaveCerCertificateFile(filePath);

        return true;
    }

    /// <summary>
    /// (✔️🔒)生成 Root 证书
    /// </summary>
    /// <param name="filePath"></param>
    /// <returns></returns>
    protected bool GenerateCertificate(string? filePath = null)
    {
        filePath ??= Interface.CerFilePath;
        lock (lockGenerateCertificate)
        {
            return GenerateCertificateUnlock(filePath);
        }
    }

    async ValueTask TrustRootCertificate()
    {
        try
        {
            SharedTrustRootCertificate();
        }
#if DEBUG
        catch (Exception e)
        {
            e.LogAndShowT(TAG, msg: "TrustRootCertificate Error");
        }
#else
        catch { }
#endif

        await PlatformTrustRootCertificateGuide();
    }

    /// <inheritdoc cref="ICertificateManager.PlatformTrustRootCertificateGuide"/>
    public async ValueTask PlatformTrustRootCertificateGuide()
    {
        try
        {
            if (OperatingSystem2.IsMacOS())
            {
                await TrustRootCertificateMacOS();
            }
            else if (OperatingSystem2.IsAndroid())
            {
                // Android 无法由应用直接写入系统信任区，只能导出 .cer 后交给系统安装器。
                // 未安装根证书时，VPN 会自动退回免证书 sidecar。
                var filePath = GetCerFilePathGeneratedWhenNoFileExists();
                if (filePath != null)
                {
                    var state = await platformService.TrustRootCertificate(filePath);
                    if (state == true)
                    {
                        Log.Info(TAG, "已打开 Android 证书安装器，需要用户在系统设置中确认。");
                    }
                }
            }
            else if (OperatingSystem2.IsLinux())
            {
                TrustRootCertificateLinux();
            }
        }
#if DEBUG
        catch (Exception e)
        {
            e.LogAndShowT(TAG, msg: "PlatformTrustRootCertificateGuide Error");
        }
#else
        catch { }
#endif
    }

    [SupportedOSPlatform("macOS")]
    async ValueTask TrustRootCertificateMacOS()
    {
        var filePath = GetCerFilePathGeneratedWhenNoFileExists();
        if (filePath == null) return;
        var state = await platformService.TrustRootCertificate(filePath);
        //await platformService.RunShellAsync($"security add-trusted-cert -d -r trustRoot -k /Users/{Environment.UserName}/Library/Keychains/login.keychain-db \\\"{filePath}\\\"", true);
        if (state != null && !IsRootCertificateInstalled)
            await TrustRootCertificateMacOS();
    }

    [SupportedOSPlatform("Linux")]
    void TrustRootCertificateLinux()
    {
        var filePath = GetCerFilePathGeneratedWhenNoFileExists();
        if (filePath == null) return;
        //全部屏蔽 Linux 浏览器全部不信任系统证书 只能手动导入 如需导入请手动操作
        //var crtFile = $"{Path.Combine(IOPath.AppDataDirectory, $@"{IReverseProxyService.CertificateName}.Certificate.crt")}";
        ////复制一份Crt导入系统用 ca-certificates 只识别Crt后缀 
        //platformService.RunShell($"cp -f \"{filePath}\" \"{crtFile}\"", false);
        //platformService.RunShell($"cp -f \"{crtFile}\" \"/usr/local/share/ca-certificates\" && sudo update-ca-certificates", true);
        //浏览器不信任系统证书列表
        Browser2.Open(UrlConstants.OfficialWebsite_LiunxSetupCer);
    }

    /// <inheritdoc cref="ICertificateManager.SetupRootCertificate"/>
    public async ValueTask<bool> SetupRootCertificate()
    {
        if (!GenerateCertificate()) return false;
        if (!IsRootCertificateInstalled)
        {
            await TrustRootCertificate();
            return IsRootCertificateInstalled;
        }
        return true;
    }

    /// <inheritdoc cref="ICertificateManager.DeleteRootCertificate"/>
    public bool DeleteRootCertificate()
    {
        if (reverseProxyService.ProxyRunning)
            return false;
        if (RootCertificate == null)
            return true;
        try
        {
            if (OperatingSystem2.IsMacOS())
            {
                DeleteRootCertificateMacOS();
            }
            else if (OperatingSystem2.IsLinux())
            {
                DeleteRootCertificateLinux();
            }
            else
            {
                SharedRemoveTrustedRootCertificate();
            }
            if (!IsRootCertificateInstalled)
            {
                RootCertificate = null;
                var pfxFilePath = Interface.PfxFilePath;
                if (File.Exists(pfxFilePath)) File.Delete(pfxFilePath);
            }
        }
        catch (CryptographicException)
        {
            // 取消删除证书
            return false;
        }
        catch (Exception e)
        {
            e.LogAndShowT(TAG, msg: "DeleteRootCertificate Error");
            return false;
        }
        return true;
    }

    [SupportedOSPlatform("Linux")]
    void DeleteRootCertificateLinux()
    {
        using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        var collection = store.Certificates.Find(X509FindType.FindByIssuerName, IReverseProxyService.RootCertificateName, false);
        foreach (var item in collection)
        {
            if (item != null)
            {
                try
                {
                    store.Open(OpenFlags.ReadWrite);
                    store.Remove(item);
                }
                catch
                {
                    platformService.RunShell($"rm -f \"/usr/local/share/ca-certificates/{IReverseProxyService.CertificateName}.Certificate.pem\" && sudo update-ca-certificates", true);
                }
            }
        }
    }

    [SupportedOSPlatform("macOS")]
    async void DeleteRootCertificateMacOS()
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        var collection = store.Certificates.Find(X509FindType.FindByIssuerName, IReverseProxyService.RootCertificateName, false);
        foreach (var item in collection)
        {
            if (item != null)
            {
                try
                {
                    store.Open(OpenFlags.ReadWrite);
                    store.Remove(item);
                }
                catch
                {
                    await platformService.RunShellAsync($"security delete-certificate -Z \\\"{item.GetCertHashString()}\\\"", true);
                }
            }
        }
    }

    /// <inheritdoc cref="ICertificateManager.IsRootCertificateInstalled"/>
    public bool IsRootCertificateInstalled
    {
        get
        {
            if (RootCertificate == null)
                if (GetCerFilePathGeneratedWhenNoFileExists() == null) return false;
            return IsCertificateInstalled(RootCertificate);
        }
    }

    /// <summary>
    /// 检查证书是否已安装并信任
    /// </summary>
    /// <param name="certificate2"></param>
    /// <returns></returns>
    bool IsCertificateInstalled(X509Certificate2? certificate2)
    {
        if (certificate2 == null)
            return false;
        if (certificate2.NotAfter <= DateTime.Now)
            return false;

        if (!OperatingSystem2.IsAndroid() && OperatingSystem2.IsLinux())
        {
            // Linux 目前没有实现检测
            return true;
        }
        else if (OperatingSystem2.IsAndroid() || OperatingSystem2.IsMacOS())
        {
            return platformService.IsCertificateInstalled(certificate2);
        }
        else
        {
            using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            return store.Certificates.Contains(certificate2);
        }
    }
}