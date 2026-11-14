using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Graphics;
using Android.Graphics.Drawables;
using Android.OS;
using Android.Provider;
using Android.Views;
using Android.Widget;
using NetAccel.Core.Models;
using NetAccel.Core.Proxy;

namespace NetAccel.Android;

[Activity(
    Label = "NetAccel",
    MainLauncher = true,
    Exported = true,
    Theme = "@android:style/Theme.Material.NoActionBar")]
public sealed class MainActivity : Activity
{
    readonly Handler handler = new(Looper.MainLooper!);

    TextView statusText = null!;
    TextView addressText = null!;
    TextView statsText = null!;
    TextView messageText = null!;
    Button toggleButton = null!;
    Action? pollAction;

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);

        AppPaths.Home = FilesDir!.AbsolutePath;
        AppPaths.EnsureDirectories();

        BuildUi();
        RequestNotificationPermission();
    }

    protected override void OnResume()
    {
        base.OnResume();
        pollAction = RefreshUi;
        handler.Post(pollAction);
    }

    protected override void OnPause()
    {
        base.OnPause();
        if (pollAction != null) handler.RemoveCallbacks(pollAction);
        pollAction = null;
    }

    void BuildUi()
    {
        var scroll = new ScrollView(this);
        scroll.SetBackgroundColor(Color.ParseColor("#0B0E1A"));

        var root = new LinearLayout(this) { Orientation = Orientation.Vertical };
        root.SetPadding(Dp(24), Dp(36), Dp(24), Dp(36));

        root.AddView(Text("NetAccel", 28, "#E8ECF8", bold: true));
        root.AddView(Text("免证书 SNI 加速 · DevSidecar 规则兼容", 13, "#8A94B0"), MarginTop(4));

        var card = new LinearLayout(this) { Orientation = Orientation.Vertical };
        card.SetPadding(Dp(20), Dp(20), Dp(20), Dp(20));
        card.Background = CardBackground("#141829", 16);

        statusText = Text("加速未启动", 20, "#E8ECF8", bold: true);
        card.AddView(statusText);

        messageText = Text("点击下方按钮启动本地代理。", 13, "#8A94B0");
        messageText.SetPadding(0, Dp(6), 0, Dp(12));
        card.AddView(messageText);

        addressText = Text("SOCKS5 127.0.0.1:8868\nHTTP 127.0.0.1:8869", 13, "#C6D2F2");
        addressText.Typeface = Typeface.Monospace;
        card.AddView(addressText);

        statsText = Text("连接 0 · 分片 0 · 上行 0 B · 下行 0 B", 12, "#8A94B0");
        statsText.SetPadding(0, Dp(10), 0, 0);
        card.AddView(statsText);

        root.AddView(card, MarginTop(20));

        toggleButton = new Button(this) { Text = "启动加速" };
        toggleButton.SetTextColor(Color.White);
        toggleButton.BackgroundTintList = global::Android.Content.Res.ColorStateList.ValueOf(Color.ParseColor("#5B8CFF"));
        toggleButton.Click += (_, _) => ToggleService();
        root.AddView(toggleButton, MarginTop(18, matchWidth: true));

        var row = new LinearLayout(this) { Orientation = Orientation.Horizontal };
        row.SetPadding(0, Dp(10), 0, 0);

        var copyButton = SecondaryButton("复制代理地址");
        copyButton.Click += (_, _) => CopyAddress();
        row.AddView(copyButton, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WrapContent, 1f));

        var wifiButton = SecondaryButton("打开 WiFi 设置");
        wifiButton.Click += (_, _) => OpenWifiSettings();
        var wifiParams = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WrapContent, 1f);
        wifiParams.SetMargins(Dp(10), 0, 0, 0);
        row.AddView(wifiButton, wifiParams);

        root.AddView(row);

        root.AddView(Text("使用方式", 15, "#E8ECF8", bold: true), MarginTop(26));
        root.AddView(Text(
            "1. 点击“启动加速”，应用会在本机启动 SOCKS5 与 HTTP 代理。\n" +
            "2. 打开系统 WiFi 设置 → 当前网络 → 代理 → 手动，填写 127.0.0.1 与 HTTP 端口。\n" +
            "3. Firefox 等浏览器也可以直接在浏览器内填写 SOCKS5/HTTP 代理。",
            13, "#8A94B0"), MarginTop(8));

        root.AddView(Text("说明", 15, "#E8ECF8", bold: true), MarginTop(22));
        root.AddView(Text(
            "• 本版本不创建 VPN，未配置代理的应用不会自动走加速。\n" +
            "• 不安装根证书、不终止 TLS，只做 SNI 分片/预置 IP/DoH/中继。\n" +
            "• 不代理 UDP/QUIC；部分视频应用可能仍走直连。\n" +
            "• 代理默认只监听 127.0.0.1，不会暴露给局域网。",
            13, "#8A94B0"), MarginTop(8));

        root.AddView(Text("数据目录：" + AppPaths.Home, 11, "#5E6880"), MarginTop(22));

        scroll.AddView(root);
        SetContentView(scroll);
    }

    void ToggleService()
    {
        if (ProxyForegroundService.IsRunning || ProxyForegroundService.Starting)
        {
            var stop = new Intent(this, typeof(ProxyForegroundService));
            stop.SetAction(ProxyForegroundService.ActionStop);
            StartService(stop);
        }
        else
        {
            var start = new Intent(this, typeof(ProxyForegroundService));
            if (Build.VERSION.SdkInt >= BuildVersionCodes.O) StartForegroundService(start);
            else StartService(start);
        }
    }

    void RefreshUi()
    {
        var running = ProxyForegroundService.IsRunning;
        var starting = ProxyForegroundService.Starting;

        statusText.Text = running ? "加速运行中" : starting ? "正在启动…" : "加速未启动";
        toggleButton.Text = running || starting ? "停止加速" : "启动加速";
        messageText.Text = ProxyForegroundService.LastMessage;

        addressText.Text =
            $"SOCKS5 127.0.0.1:{ProxyForegroundService.SocksPort}\n" +
            $"HTTP 127.0.0.1:{ProxyForegroundService.HttpPort}";

        var snapshot = ProxyForegroundService.Current?.Stats.GetSnapshot();
        statsText.Text = snapshot == null
            ? "连接 0 · 分片 0 · 上行 0 B · 下行 0 B"
            : $"连接 {snapshot.Connections} · 分片 {snapshot.Fragmented} · " +
              $"上行 {FormatBytes(snapshot.BytesUp)} · 下行 {FormatBytes(snapshot.BytesDown)}";

        if (pollAction != null) handler.PostDelayed(pollAction, 1000);
    }

    void CopyAddress()
    {
        var clipboard = (ClipboardManager?)GetSystemService(ClipboardService);
        var text = $"SOCKS5 127.0.0.1:{ProxyForegroundService.SocksPort}\n" +
                   $"HTTP 127.0.0.1:{ProxyForegroundService.HttpPort}";
        if (clipboard != null) clipboard.PrimaryClip = ClipData.NewPlainText("NetAccel 代理地址", text);
        Toast.MakeText(this, "代理地址已复制", ToastLength.Short)?.Show();
    }

    void OpenWifiSettings()
    {
        try
        {
            StartActivity(new Intent(Settings.ActionWifiSettings));
        }
        catch (Exception ex)
        {
            Toast.MakeText(this, "无法打开 WiFi 设置：" + ex.Message, ToastLength.Short)?.Show();
        }
    }

    void RequestNotificationPermission()
    {
        if (OperatingSystem.IsAndroidVersionAtLeast(33) &&
            CheckSelfPermission(global::Android.Manifest.Permission.PostNotifications) != Permission.Granted)
        {
            RequestPermissions(new[] { global::Android.Manifest.Permission.PostNotifications }, 1);
        }
    }

    TextView Text(string text, float size, string color, bool bold = false)
    {
        var view = new TextView(this) { Text = text };
        view.SetTextSize(global::Android.Util.ComplexUnitType.Sp, size);
        view.SetTextColor(Color.ParseColor(color));
        if (bold) view.SetTypeface(null, TypefaceStyle.Bold);
        return view;
    }

    Button SecondaryButton(string text)
    {
        var button = new Button(this) { Text = text };
        button.SetTextColor(Color.ParseColor("#E8ECF8"));
        button.BackgroundTintList = global::Android.Content.Res.ColorStateList.ValueOf(Color.ParseColor("#1B2136"));
        return button;
    }

    GradientDrawable CardBackground(string color, float radius)
    {
        var drawable = new GradientDrawable();
        drawable.SetColor(Color.ParseColor(color));
        drawable.SetCornerRadius(Dp(radius));
        return drawable;
    }

    LinearLayout.LayoutParams MarginTop(int top, bool matchWidth = false)
        => new(matchWidth ? ViewGroup.LayoutParams.MatchParent : ViewGroup.LayoutParams.WrapContent,
            ViewGroup.LayoutParams.WrapContent)
        {
            TopMargin = Dp(top),
        };

    int Dp(float value) => (int)(value * Resources!.DisplayMetrics!.Density + 0.5f);

    static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return (bytes / 1024d).ToString("0.0") + " KB";
        return (bytes / 1024d / 1024).ToString("0.0") + " MB";
    }
}
