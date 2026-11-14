using System.Net;
using System.Net.Sockets;
using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using NetAccel.Core.Logging;
using NetAccel.Core.Models;
using NetAccel.Core.Proxy;
using NetAccel.Core.Tls;

namespace NetAccel.Android;

/// <summary>
/// 前台服务：在 127.0.0.1 上运行 SOCKS5 + HTTP 代理。
/// Android 不允许普通应用静默修改全局代理，因此用户在 WiFi 设置里手动填写代理地址；
/// 服务放到前台可以避免 Activity 退到后台后被系统回收。
/// </summary>
[Service(Exported = false, ForegroundServiceType = ForegroundService.TypeDataSync)]
public sealed class ProxyForegroundService : Service
{
    public const string ActionStop = "com.netaccel.android.STOP";

    const string ChannelId = "netaccel_proxy";
    const int NotificationId = 1001;

    FileLogger? logger;
    AccelProxyService? service;

    public static bool IsRunning { get; private set; }
    public static bool Starting { get; private set; }
    public static string LastMessage { get; private set; } = "未启动";
    public static int SocksPort { get; private set; } = 8868;
    public static int HttpPort { get; private set; } = 8869;
    public static AccelProxyService? Current { get; private set; }

    public override IBinder? OnBind(Intent? intent) => null;

    public override void OnCreate()
    {
        base.OnCreate();
        AppPaths.Home = FilesDir!.AbsolutePath;
        AppPaths.EnsureDirectories();
        CreateChannel();
    }

    public override StartCommandResult OnStartCommand(Intent? intent, StartCommandFlags flags, int startId)
    {
        if (string.Equals(intent?.Action, ActionStop, StringComparison.Ordinal))
        {
            StopProxy();
            StopForeground(StopForegroundFlags.Remove);
            StopSelf();
            return StartCommandResult.NotSticky;
        }

        Starting = true;
        LastMessage = "正在启动代理…";
        StartForeground(NotificationId, BuildNotification(LastMessage));
        _ = Task.Run(StartProxyAsync);
        return StartCommandResult.Sticky;
    }

    async Task StartProxyAsync()
    {
        try
        {
            var store = new SettingsStore();
            var settings = store.Load();

            settings.SetSystemProxy = false;
            settings.AutoStartProxy = false;
            settings.ListenAddress = "127.0.0.1";
            settings.EnableSocks5 = true;
            settings.EnableHttp = true;
            settings.Socks5Port = FindFreePort(8868);
            settings.HttpPort = FindFreePort(settings.Socks5Port + 1);
            settings.EnableDoh = true;
            settings.EnableBuiltInRules = true;
            settings.EnableSniFragment = true;
            settings.FragmentStrategy = TlsFragmentStrategy.Auto;
            settings.EnableDiagnostics = true;
            settings.Normalize();

            SocksPort = settings.Socks5Port;
            HttpPort = settings.HttpPort;

            logger = new FileLogger(
                AppPaths.LogDirectory,
                enabled: () => true,
                minimumLevel: () => settings.DiagnosticsMinimumLevel,
                includeHost: () => settings.DiagnosticsIncludeHost,
                retentionDays: () => settings.DiagnosticsRetentionDays,
                maxFileSizeKB: () => settings.DiagnosticsMaxFileSizeKB);

            var proxy = new AccelProxyService(settings, logger);
            var result = await proxy.StartAsync().ConfigureAwait(false);

            if (!result.Success)
            {
                Starting = false;
                IsRunning = false;
                LastMessage = result.Message;
                UpdateNotification(LastMessage);
                return;
            }

            service = proxy;
            Current = proxy;
            IsRunning = true;
            Starting = false;
            LastMessage = $"运行中：SOCKS5 {SocksPort} / HTTP {HttpPort}";
            UpdateNotification(LastMessage);
        }
        catch (Exception ex)
        {
            Starting = false;
            IsRunning = false;
            LastMessage = "启动失败：" + ex.Message;
            UpdateNotification(LastMessage);
        }
    }

    void StopProxy()
    {
        IsRunning = false;
        Starting = false;
        Current = null;

        try
        {
            service?.StopAsync().Wait(TimeSpan.FromSeconds(4));
        }
        catch
        {
            // 停止失败不影响退出
        }

        service = null;
        logger?.Dispose();
        logger = null;
        LastMessage = "已停止";
    }

    public override void OnDestroy()
    {
        StopProxy();
        base.OnDestroy();
    }

    static int FindFreePort(int start)
    {
        for (var port = start; port < start + 50 && port <= 65535; port++)
        {
            try
            {
                using var listener = new TcpListener(IPAddress.Loopback, port);
                listener.Start();
                listener.Stop();
                return port;
            }
            catch
            {
                // 端口被占用，继续尝试下一个
            }
        }
        return start;
    }

    void CreateChannel()
    {
        if (Build.VERSION.SdkInt < BuildVersionCodes.O) return;

        var manager = (NotificationManager?)GetSystemService(NotificationService);
        if (manager == null) return;

        var channel = new NotificationChannel(ChannelId, "代理服务", NotificationImportance.Low)
        {
            Description = "NetAccel 本地代理运行状态",
        };
        manager.CreateNotificationChannel(channel);
    }

    Notification BuildNotification(string text)
    {
        var builder = new Notification.Builder(this, ChannelId);
        builder.SetContentTitle("NetAccel 网络加速")
            .SetContentText(text)
            .SetSmallIcon(global::Android.Resource.Drawable.IcDialogInfo)
            .SetOngoing(true);

        var pending = PendingIntent.GetActivity(
            this,
            0,
            new Intent(this, typeof(MainActivity)),
            PendingIntentFlags.Immutable);
        builder.SetContentIntent(pending);

        return builder.Build()!;
    }

    void UpdateNotification(string text)
    {
        try
        {
            var manager = (NotificationManager?)GetSystemService(NotificationService);
            manager?.Notify(NotificationId, BuildNotification(text));
        }
        catch
        {
            // 通知失败不影响代理
        }
    }
}
