#if SHADOWSOCKS
using Android.App;
using Android.Content;
using Android.Runtime;
using System.Application.Services.Implementation;
using System.Application.Settings;
using static System.Application.Services.Native.IServiceBase;
using AndroidX.Core.App;
using static System.Properties.ThisAssembly;
using System.Collections.Generic;
using System.Net;

namespace System.Application.Services.Native
{
    partial class ProxyForegroundService
    {
        partial class VpnService : Shadowsocks.VpnService
        {
            bool isStart;
            int notifyId;
            NotificationCompat.Builder? builder;
            NotificationManagerCompat? mNotificationManager;

            NotificationManagerCompat NotificationManager
            {
                get
                {
                    if (mNotificationManager == null)
                    {
                        mNotificationManager = NotificationManagerCompat.From(this);
                    }
                    return mNotificationManager;
                }
            }

            public override void OnStart()
            {
                if (isStart) return;
                isStart = true;

                // 先显示通知 UI
                IForegroundService f = this;
                (builder, mNotificationManager, notifyId) = AndroidNotificationServiceImpl.Instance.StartForeground(this, f.NotificationType, f.NotificationText, f.NotificationEntranceAction);

                // 免证书模式要在 tun2socks 计算 SOCKS 出口前就绪。
                SniSidecarService.Start();

                // 启动本地代理服务
                ProxyService.Current.ProxyStatus = true;

                // 启动 VPN tun2socks
                base.OnStart();
            }

            public override void OnStop()
            {
                if (!isStart) return;
                isStart = false;

                // 停止通知栏 UI
                StopForeground(true);

                // 停止 VPN tun2socks
                base.OnStop();

                // 停止本地代理服务
                ProxyService.Current.ProxyStatus = false;
            }

            public override void OnRevoke()
            {
                OnStop();
                base.OnRevoke();
            }

            [return: GeneratedEnum]
            public override StartCommandResult OnStartCommand(Intent? intent, [GeneratedEnum] StartCommandFlags flags, int startId)
            {
                if (intent != null)
                {
                    var action = intent.Action;
                    switch (action)
                    {
                        case START:
                            OnStart();
                            return StartCommandResult.RedeliverIntent;
                        case STOP:
                        default:
                            OnStop();
                            StopSelf();
                            break;
                    }
                }
                return StartCommandResult.NotSticky;
            }

            public override string SocksServerAddress
            {
                get
                {
                    var s = ProxyService.Current;
                    var ip = IPAddress.Any.Equals(s.ProxyIp) || IPAddress.IPv6Any.Equals(s.ProxyIp)
                        ? IPAddress.Loopback
                        : s.ProxyIp;

                    // 只有免证书模式（或根本未安装根证书）才把 VPN 出口交给 SNI sidecar。
                    // 有证书时仍然走 Titanium 的 SOCKS5，否则 DevSidecar 的 SNI 伪装、镜像和请求头规则不会生效。
                    var certificateLess = ProxySettings.IsCertificateLessMode.Value ||
                        !IReverseProxyService.Instance.CertificateManager.IsRootCertificateInstalled;
                    var port = certificateLess && SniSidecarService.IsRunning
                        ? SniSidecarService.ActivePort
                        : s.Socks5ProxyPortId;
                    return $"{ip}:{port}";
                }
            }

            const int VPN_MTU = 1500;
            const string VPN_MTU_STR = "1500";

            public override void OnConfigure(Builder builder)
            {
                builder.SetSession(AssemblyTrademark);
                //builder.AddDnsServer(IDnsAnalysisService.PrimaryDNS_Ali);
                // https://github.com/2dust/v2rayNG/blob/master/AndroidLibV2rayLite/CoreI/Status.go#L56
                builder.SetMtu(VPN_MTU);
                builder.AddAddress("26.26.26.1", 30);
                AddRouteByPassPrivateIPAddress(builder);
                builder.AddAddress("da26:2626::1", 126);
                builder.AddRoute("2000::", 3);
                builder.AddDisallowedApplication(PackageName!);

                if (!ProxySettings.IsCertificateLessMode.Value && ProxySettings.EnableBrowserOnlyVpn.Value)
                {
                    var added = 0;
                    foreach (var package in BrowserPackageNames)
                    {
                        try
                        {
                            builder.AddAllowedApplication(package);
                            added++;
                        }
                        catch
                        {
                            // 未安装的浏览器直接跳过
                        }
                    }
                    if (added > 0)
                    {
                        ProxyDiagnostics.Info("Vpn", $"增强模式仅代理浏览器，已加入 {added} 个包");
                    }
                }
            }

            static readonly string[] BrowserPackageNames =
            {
                "com.android.chrome",
                "org.mozilla.firefox",
                "com.microsoft.emmx",
                "com.brave.browser",
                "com.opera.browser",
                "com.sec.android.app.sbrowser",
                "com.quark.browser",
                "com.UCMobile",
                "com.tencent.mtt",
                "com.android.browser",
            };

            public override IList<string> Tun2socksArgs
            {
                get
                {
                    // https://github.com/2dust/v2rayNG/blob/master/AndroidLibV2rayLite/CoreI/Status.go#L28
                    return new JavaList<string>
                    {
                        Tun2socksExecutablePath,
                        "--netif-ipaddr",
                        "26.26.26.2",
                        "--netif-netmask",
                        "255.255.255.252",
                        "--socks-server-addr",
                        SocksServerAddress,
                        "--tunmtu",
                        VPN_MTU_STR,
                        "--loglevel",
                        "notice",
                        "--enable-udprelay",
                        "--sock-path",
                        "sock_path",
                        "--netif-ip6addr",
                        "da26:2626::2"
                    };
                }
            }

#if DEBUG
            public override void OnError(string msg, Java.Lang.Throwable tr)
            {
                base.OnError(msg, tr);
            }

            public override string SockPath
            {
                get
                {
                    var value = base.SockPath;
                    Log.Info(nameof(VpnService), $"SockPath: {value}");
                    return value;
                }
            }
#endif
        }
    }
}
#endif
