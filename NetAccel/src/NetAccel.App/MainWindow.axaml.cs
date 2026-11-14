using System.Diagnostics;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input.Platform;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using NetAccel.Core.Lab;
using NetAccel.Core.Logging;
using NetAccel.Core.Models;
using NetAccel.Core.Proxy;
using NetAccel.Core.Rules;
using NetAccel.Core.Stats;
using NetAccel.Core.Tls;

namespace NetAccel.App;

public partial class MainWindow : Window
{
    readonly SettingsStore store = new();
    readonly MemoryLogger memoryLog = new(600);
    readonly DispatcherTimer timer;

    AccelSettings settings;
    FileLogger fileLogger;
    IAccelLogger logger;
    AccelProxyService service;

    // 控件缓存，避免在事件里反复 FindControl。
    readonly TextBlock statusTitle;
    readonly TextBlock statusSubtitle;
    readonly TextBlock statusDetail;
    readonly Border statusDot;
    readonly TextBlock headerStatusText;
    readonly Button startStopButton;

    readonly TextBlock activeConnText;
    readonly TextBlock fragmentedText;
    readonly TextBlock bytesUpText;
    readonly TextBlock bytesDownText;
    readonly SelectableTextBlock socksAddressText;
    readonly SelectableTextBlock httpAddressText;
    readonly WrapPanel groupPanel;

    readonly CheckBox remoteRulesCheck;
    readonly TextBox remoteRuleUrlBox;
    readonly Button syncRulesButton;
    readonly TextBlock remoteRuleStatus;
    readonly CheckBox syncOnStartCheck;

    readonly TextBox customRulesBox;
    readonly TextBlock customRuleStatus;

    readonly TextBox labHostBox;
    readonly Button labRunButton;
    readonly ProgressBar labProgress;
    readonly TextBlock labStatus;
    readonly StackPanel labResultsPanel;
    readonly TextBox labReportBox;

    readonly CheckBox socksEnableCheck;
    readonly NumericUpDown socksPortBox;
    readonly CheckBox httpEnableCheck;
    readonly NumericUpDown httpPortBox;
    readonly TextBox listenAddressBox;
    readonly CheckBox setSystemProxyCheck;
    readonly CheckBox autoStartCheck;
    readonly CheckBox bypassLocalCheck;

    readonly CheckBox fragmentEnableCheck;
    readonly ComboBox strategyCombo;
    readonly NumericUpDown chunkBox;
    readonly NumericUpDown piecesBox;
    readonly NumericUpDown delayBox;
    readonly NumericUpDown jitterBox;
    readonly TextBox fragmentDomainsBox;
    readonly CheckBox onlyTlsCheck;
    readonly NumericUpDown probeBox;
    readonly NumericUpDown fallbackCacheBox;
    readonly NumericUpDown maxHelloBox;
    readonly NumericUpDown firstTimeoutBox;
    readonly CheckBox fallbackCheck;

    readonly CheckBox rewriteEnableCheck;
    readonly TextBox rewriteHostBox;
    readonly TextBox rewriteDomainsBox;
    readonly CheckBox dohEnableCheck;
    readonly TextBox dohEndpointBox;
    readonly CheckBox dohFallbackCheck;

    readonly CheckBox relayEnableCheck;
    readonly TextBox relayHostBox;
    readonly NumericUpDown relayPortBox;
    readonly TextBox relayUserBox;
    readonly TextBox relayPassBox;
    readonly TextBox relayDomainsBox;

    readonly CheckBox diagEnableCheck;
    readonly ComboBox diagLevelCombo;
    readonly CheckBox diagHostCheck;
    readonly NumericUpDown diagRetentionBox;
    readonly NumericUpDown diagSizeBox;

    readonly TextBox logBox;

    readonly List<CheckBox> groupChecks = new();
    string lastReport = string.Empty;
    bool loading = true;
    bool busy;
    bool labBusy;
    bool shuttingDown;
    bool logDirty;

    public MainWindow()
    {
        InitializeComponent();

        statusTitle = C<TextBlock>("StatusTitle");
        statusSubtitle = C<TextBlock>("StatusSubtitle");
        statusDetail = C<TextBlock>("StatusDetail");
        statusDot = C<Border>("StatusDot");
        headerStatusText = C<TextBlock>("HeaderStatusText");
        startStopButton = C<Button>("StartStopButton");

        activeConnText = C<TextBlock>("ActiveConnText");
        fragmentedText = C<TextBlock>("FragmentedText");
        bytesUpText = C<TextBlock>("BytesUpText");
        bytesDownText = C<TextBlock>("BytesDownText");
        socksAddressText = C<SelectableTextBlock>("SocksAddressText");
        httpAddressText = C<SelectableTextBlock>("HttpAddressText");
        groupPanel = C<WrapPanel>("GroupPanel");

        remoteRulesCheck = C<CheckBox>("RemoteRulesCheck");
        remoteRuleUrlBox = C<TextBox>("RemoteRuleUrlBox");
        syncRulesButton = C<Button>("SyncRulesButton");
        remoteRuleStatus = C<TextBlock>("RemoteRuleStatus");
        syncOnStartCheck = C<CheckBox>("SyncOnStartCheck");

        customRulesBox = C<TextBox>("CustomRulesBox");
        customRuleStatus = C<TextBlock>("CustomRuleStatus");

        labHostBox = C<TextBox>("LabHostBox");
        labRunButton = C<Button>("LabRunButton");
        labProgress = C<ProgressBar>("LabProgress");
        labStatus = C<TextBlock>("LabStatus");
        labResultsPanel = C<StackPanel>("LabResultsPanel");
        labReportBox = C<TextBox>("LabReportBox");

        socksEnableCheck = C<CheckBox>("SocksEnableCheck");
        socksPortBox = C<NumericUpDown>("SocksPortBox");
        httpEnableCheck = C<CheckBox>("HttpEnableCheck");
        httpPortBox = C<NumericUpDown>("HttpPortBox");
        listenAddressBox = C<TextBox>("ListenAddressBox");
        setSystemProxyCheck = C<CheckBox>("SetSystemProxyCheck");
        autoStartCheck = C<CheckBox>("AutoStartCheck");
        bypassLocalCheck = C<CheckBox>("BypassLocalCheck");

        fragmentEnableCheck = C<CheckBox>("FragmentEnableCheck");
        strategyCombo = C<ComboBox>("StrategyCombo");
        chunkBox = C<NumericUpDown>("ChunkBox");
        piecesBox = C<NumericUpDown>("PiecesBox");
        delayBox = C<NumericUpDown>("DelayBox");
        jitterBox = C<NumericUpDown>("JitterBox");
        fragmentDomainsBox = C<TextBox>("FragmentDomainsBox");
        onlyTlsCheck = C<CheckBox>("OnlyTlsCheck");
        probeBox = C<NumericUpDown>("ProbeBox");
        fallbackCacheBox = C<NumericUpDown>("FallbackCacheBox");
        maxHelloBox = C<NumericUpDown>("MaxHelloBox");
        firstTimeoutBox = C<NumericUpDown>("FirstTimeoutBox");
        fallbackCheck = C<CheckBox>("FallbackCheck");

        rewriteEnableCheck = C<CheckBox>("RewriteEnableCheck");
        rewriteHostBox = C<TextBox>("RewriteHostBox");
        rewriteDomainsBox = C<TextBox>("RewriteDomainsBox");
        dohEnableCheck = C<CheckBox>("DohEnableCheck");
        dohEndpointBox = C<TextBox>("DohEndpointBox");
        dohFallbackCheck = C<CheckBox>("DohFallbackCheck");

        relayEnableCheck = C<CheckBox>("RelayEnableCheck");
        relayHostBox = C<TextBox>("RelayHostBox");
        relayPortBox = C<NumericUpDown>("RelayPortBox");
        relayUserBox = C<TextBox>("RelayUserBox");
        relayPassBox = C<TextBox>("RelayPassBox");
        relayDomainsBox = C<TextBox>("RelayDomainsBox");

        diagEnableCheck = C<CheckBox>("DiagEnableCheck");
        diagLevelCombo = C<ComboBox>("DiagLevelCombo");
        diagHostCheck = C<CheckBox>("DiagHostCheck");
        diagRetentionBox = C<NumericUpDown>("DiagRetentionBox");
        diagSizeBox = C<NumericUpDown>("DiagSizeBox");

        logBox = C<TextBox>("LogBox");

        try
        {
            AppPaths.EnsureDirectories();
        }
        catch
        {
            // 目录创建失败不阻止界面启动，后续保存时会再次尝试
        }

        settings = store.Load();
        fileLogger = CreateFileLogger(settings);
        logger = new CompositeLogger(fileLogger, memoryLog);
        service = new AccelProxyService(settings, logger);
        service.StateChanged += () => Dispatcher.UIThread.Post(RefreshStatus);

        memoryLog.Changed += () => logDirty = true;

        BuildGroupChecks();
        LoadSettingsIntoUi();
        RefreshStatus();
        RefreshAddress();
        RefreshLog(force: true);

        timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        timer.Tick += (_, _) => OnTick();
        timer.Start();

        Opened += OnOpened;
        Closing += OnClosing;
        loading = false;
    }

    FileLogger CreateFileLogger(AccelSettings target)
        => new(
            AppPaths.LogDirectory,
            enabled: () => target.EnableDiagnostics,
            minimumLevel: () => target.DiagnosticsMinimumLevel,
            includeHost: () => target.DiagnosticsIncludeHost,
            retentionDays: () => target.DiagnosticsRetentionDays,
            maxFileSizeKB: () => target.DiagnosticsMaxFileSizeKB);

    T C<T>(string name) where T : Control
        => this.FindControl<T>(name) ?? throw new InvalidOperationException($"缺少控件: {name}");

    async void OnOpened(object? sender, EventArgs e)
    {
        if (!settings.AutoStartProxy) return;

        try
        {
            await StartProxyAsync();
        }
        catch (Exception ex)
        {
            CrashReporter.Write(ex, "AutoStart");
            statusSubtitle.Text = "自动启动失败：" + ex.Message;
        }
    }

    void BuildGroupChecks()
    {
        groupPanel.Children.Clear();
        groupChecks.Clear();

        foreach (var group in ProxyRuleGroups.All)
        {
            var check = new CheckBox
            {
                Content = group.Name,
                Margin = new Thickness(0, 0, 22, 10),
                Tag = group.Id,
            };
            ToolTip.SetTip(check, group.Description);
            check.IsCheckedChanged += (_, _) =>
            {
                if (loading || busy) return;
                ApplyGroupSelection();
            };
            groupChecks.Add(check);
            groupPanel.Children.Add(check);
        }
    }

    void ApplyGroupSelection()
    {
        var selected = groupChecks
            .Where(x => x.IsChecked == true)
            .Select(x => (string)x.Tag!)
            .ToArray();

        settings.EnabledRuleGroups = ProxyRuleGroups.ToStorage(selected);
        store.Save(settings);
        service.ReloadRules();
        UpdateRemoteStatus();
    }

    void LoadSettingsIntoUi()
    {
        loading = true;
        try
        {
            socksEnableCheck.IsChecked = settings.EnableSocks5;
            socksPortBox.Value = settings.Socks5Port;
            httpEnableCheck.IsChecked = settings.EnableHttp;
            httpPortBox.Value = settings.HttpPort;
            listenAddressBox.Text = settings.ListenAddress;
            setSystemProxyCheck.IsChecked = settings.SetSystemProxy;
            autoStartCheck.IsChecked = settings.AutoStartProxy;
            bypassLocalCheck.IsChecked = settings.BypassLocalhost;

            fragmentEnableCheck.IsChecked = settings.EnableSniFragment;
            strategyCombo.SelectedIndex = (int)settings.FragmentStrategy;
            chunkBox.Value = settings.FragmentChunkSize;
            piecesBox.Value = settings.SplitPieces;
            delayBox.Value = settings.FragmentDelayMs;
            jitterBox.Value = settings.FragmentJitterMs;
            fragmentDomainsBox.Text = settings.FragmentDomains;
            onlyTlsCheck.IsChecked = settings.OnlyFragmentTls;
            probeBox.Value = settings.FallbackProbeMs;
            fallbackCacheBox.Value = settings.FallbackCacheMinutes;
            maxHelloBox.Value = settings.MaxClientHelloBytes;
            firstTimeoutBox.Value = settings.FirstPayloadTimeoutMs;
            fallbackCheck.IsChecked = settings.EnableFragmentFallback;

            rewriteEnableCheck.IsChecked = settings.EnableSniRewrite;
            rewriteHostBox.Text = settings.SniRewriteHost;
            rewriteDomainsBox.Text = settings.RewriteDomains;
            dohEnableCheck.IsChecked = settings.EnableDoh;
            dohEndpointBox.Text = settings.DohEndpoint;
            dohFallbackCheck.IsChecked = settings.DohFallbackToSystem;

            relayEnableCheck.IsChecked = settings.EnableUpstreamRelay;
            relayHostBox.Text = settings.RelayHost;
            relayPortBox.Value = settings.RelayPort;
            relayUserBox.Text = settings.RelayUserName;
            relayPassBox.Text = settings.RelayPassword;
            relayDomainsBox.Text = settings.RelayDomains;

            diagEnableCheck.IsChecked = settings.EnableDiagnostics;
            diagLevelCombo.SelectedIndex = Math.Clamp(settings.DiagnosticsMinimumLevel, 0, 2);
            diagHostCheck.IsChecked = settings.DiagnosticsIncludeHost;
            diagRetentionBox.Value = settings.DiagnosticsRetentionDays;
            diagSizeBox.Value = settings.DiagnosticsMaxFileSizeKB;

            remoteRulesCheck.IsChecked = settings.EnableRemoteRules;
            remoteRuleUrlBox.Text = settings.RemoteRuleUrl;
            syncOnStartCheck.IsChecked = settings.SyncRemoteRulesOnStart;

            var enabled = ProxyRuleGroups.ParseEnabled(settings.EnabledRuleGroups);
            foreach (var check in groupChecks)
            {
                check.IsChecked = enabled.Contains((string)check.Tag!);
            }

            customRulesBox.Text = service.Rules.CustomStore.GetText();
            UpdateRemoteStatus();
        }
        finally
        {
            loading = false;
        }
    }

    void CollectSettingsFromUi()
    {
        settings.EnableSocks5 = socksEnableCheck.IsChecked == true;
        settings.Socks5Port = ToInt(socksPortBox, settings.Socks5Port);
        settings.EnableHttp = httpEnableCheck.IsChecked == true;
        settings.HttpPort = ToInt(httpPortBox, settings.HttpPort);
        settings.ListenAddress = listenAddressBox.Text?.Trim() ?? "127.0.0.1";
        settings.SetSystemProxy = setSystemProxyCheck.IsChecked == true;
        settings.AutoStartProxy = autoStartCheck.IsChecked == true;
        settings.BypassLocalhost = bypassLocalCheck.IsChecked == true;

        settings.EnableSniFragment = fragmentEnableCheck.IsChecked == true;
        settings.FragmentStrategy = (TlsFragmentStrategy)Math.Clamp(strategyCombo.SelectedIndex, 0, 5);
        settings.FragmentChunkSize = ToInt(chunkBox, settings.FragmentChunkSize);
        settings.SplitPieces = ToInt(piecesBox, settings.SplitPieces);
        settings.FragmentDelayMs = ToInt(delayBox, settings.FragmentDelayMs);
        settings.FragmentJitterMs = ToInt(jitterBox, settings.FragmentJitterMs);
        settings.FragmentDomains = fragmentDomainsBox.Text?.Trim() ?? string.Empty;
        settings.OnlyFragmentTls = onlyTlsCheck.IsChecked == true;
        settings.FallbackProbeMs = ToInt(probeBox, settings.FallbackProbeMs);
        settings.FallbackCacheMinutes = ToInt(fallbackCacheBox, settings.FallbackCacheMinutes);
        settings.MaxClientHelloBytes = ToInt(maxHelloBox, settings.MaxClientHelloBytes);
        settings.FirstPayloadTimeoutMs = ToInt(firstTimeoutBox, settings.FirstPayloadTimeoutMs);
        settings.EnableFragmentFallback = fallbackCheck.IsChecked == true;

        settings.EnableSniRewrite = rewriteEnableCheck.IsChecked == true;
        settings.SniRewriteHost = rewriteHostBox.Text?.Trim() ?? "baidu.com";
        settings.RewriteDomains = rewriteDomainsBox.Text?.Trim() ?? string.Empty;
        settings.EnableDoh = dohEnableCheck.IsChecked == true;
        settings.DohEndpoint = dohEndpointBox.Text?.Trim() ?? string.Empty;
        settings.DohFallbackToSystem = dohFallbackCheck.IsChecked == true;

        settings.EnableUpstreamRelay = relayEnableCheck.IsChecked == true;
        settings.RelayHost = relayHostBox.Text?.Trim() ?? "127.0.0.1";
        settings.RelayPort = ToInt(relayPortBox, settings.RelayPort);
        settings.RelayUserName = relayUserBox.Text ?? string.Empty;
        settings.RelayPassword = relayPassBox.Text ?? string.Empty;
        settings.RelayDomains = relayDomainsBox.Text?.Trim() ?? string.Empty;

        settings.EnableDiagnostics = diagEnableCheck.IsChecked == true;
        settings.DiagnosticsMinimumLevel = Math.Clamp(diagLevelCombo.SelectedIndex, 0, 2);
        settings.DiagnosticsIncludeHost = diagHostCheck.IsChecked == true;
        settings.DiagnosticsRetentionDays = ToInt(diagRetentionBox, settings.DiagnosticsRetentionDays);
        settings.DiagnosticsMaxFileSizeKB = ToInt(diagSizeBox, settings.DiagnosticsMaxFileSizeKB);

        settings.EnableRemoteRules = remoteRulesCheck.IsChecked == true;
        settings.RemoteRuleUrl = remoteRuleUrlBox.Text?.Trim() ?? settings.RemoteRuleUrl;
        settings.SyncRemoteRulesOnStart = syncOnStartCheck.IsChecked == true;

        settings.EnabledRuleGroups = ProxyRuleGroups.ToStorage(
            groupChecks.Where(x => x.IsChecked == true).Select(x => (string)x.Tag!));

        settings.Normalize();
    }

    static int ToInt(NumericUpDown box, int fallback)
        => box.Value is { } value ? (int)value : fallback;

    // ---------------- 启停 ----------------

    async void OnStartStopClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (busy) return;

        busy = true;
        startStopButton.IsEnabled = false;
        try
        {
            if (service.IsRunning)
            {
                await StopProxyAsync();
            }
            else
            {
                await StartProxyAsync();
            }
        }
        finally
        {
            busy = false;
            startStopButton.IsEnabled = true;
            RefreshStatus();
            RefreshAddress();
        }
    }

    async Task StartProxyAsync()
    {
        CollectSettingsFromUi();
        store.Save(settings);

        statusSubtitle.Text = "正在启动代理…";
        var result = await service.StartAsync();
        if (result.Success)
        {
            statusSubtitle.Text = settings.SetSystemProxy
                ? "系统代理已按设置开启；关闭加速或退出应用会自动恢复。"
                : "把应用或系统代理指向下面的地址即可开始使用。";
        }
        else
        {
            statusSubtitle.Text = result.Message;
            await ShowMessageAsync("启动失败", result.Message);
        }

        RefreshStatus();
        RefreshAddress();
    }

    async Task StopProxyAsync()
    {
        statusSubtitle.Text = "正在停止代理…";
        await service.StopAsync();
        statusSubtitle.Text = "代理已停止。";
        RefreshStatus();
        RefreshAddress();
    }

    // ---------------- 状态刷新 ----------------

    void OnTick()
    {
        var snapshot = service.Stats.GetSnapshot();
        activeConnText.Text = snapshot.ActiveConnections.ToString();
        fragmentedText.Text = snapshot.Fragmented.ToString();
        bytesUpText.Text = AccelerationLab.FormatBytes(snapshot.BytesUp);
        bytesDownText.Text = AccelerationLab.FormatBytes(snapshot.BytesDown);

        if (logDirty) RefreshLog(force: false);

        if (!busy) RefreshStatus();
    }

    void RefreshStatus()
    {
        var running = service.IsRunning;

        statusDot.Background = Brush(running ? "#2ED573" : "#8A94B0");
        headerStatusText.Text = running ? "运行中" : "未启动";
        statusTitle.Text = running ? "加速运行中" : "加速未启动";

        if (running)
        {
            var modes = new List<string>();
            if (settings.EnableSocks5) modes.Add("SOCKS5");
            if (settings.EnableHttp) modes.Add("HTTP");
            statusDetail.Text = $"{string.Join(" + ", modes)} 已监听 · " +
                                $"分片 {(settings.EnableSniFragment ? settings.FragmentStrategy.ToString() : "关")} · " +
                                $"DoH {(settings.EnableDoh ? "开" : "关")}";
        }
        else
        {
            statusDetail.Text = $"SOCKS5 127.0.0.1:{settings.Socks5Port} · HTTP 127.0.0.1:{settings.HttpPort}";
        }

        startStopButton.Content = running ? "停止加速" : "启动加速";
        startStopButton.Classes.Set("danger", running);
        startStopButton.Classes.Set("primary", !running);

        if (!running && statusSubtitle.Text is null or "" or "正在停止代理…")
        {
            statusSubtitle.Text = "启动本地代理后，把应用或系统代理指向下面的地址即可。";
        }
        else if (running && statusSubtitle.Text is null or "" or "正在启动代理…")
        {
            statusSubtitle.Text = "代理已就绪。";
        }
    }

    void RefreshAddress()
    {
        var socksPort = service.IsRunning && service.Socks5Running ? service.Socks5Port : settings.Socks5Port;
        var httpPort = service.IsRunning && service.HttpRunning ? service.HttpPort : settings.HttpPort;
        socksAddressText.Text = $"127.0.0.1:{socksPort}";
        httpAddressText.Text = $"127.0.0.1:{httpPort}";
    }

    void RefreshLog(bool force)
    {
        if (!logDirty && !force) return;
        logDirty = false;
        logBox.Text = string.Join(Environment.NewLine, memoryLog.Lines);
        logBox.CaretIndex = logBox.Text?.Length ?? 0;
    }

    // ---------------- 规则 ----------------

    void UpdateRemoteStatus()
    {
        var rules = service.Rules;
        var parts = new List<string>
        {
            $"当前生效 {rules.Current.Rules.Count} 条",
            $"自定义 {rules.CustomRuleCount} 条",
        };

        if (rules.LastSyncTime is { } time)
        {
            parts.Add($"上次同步 {time:HH:mm:ss}");
        }
        if (!string.IsNullOrEmpty(rules.LastError))
        {
            parts.Add("远程错误: " + rules.LastError);
        }
        if (!string.IsNullOrEmpty(rules.LastCustomError))
        {
            parts.Add("自定义错误: " + rules.LastCustomError);
        }

        remoteRuleStatus.Text = string.Join(" · ", parts);
    }

    async void OnSyncRulesClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        syncRulesButton.IsEnabled = false;
        remoteRuleStatus.Text = "正在同步远程规则…";
        try
        {
            CollectSettingsFromUi();
            store.Save(settings);
            service.ReloadRules();
            await service.SyncRulesAsync();
            UpdateRemoteStatus();
        }
        catch (Exception ex)
        {
            remoteRuleStatus.Text = "同步失败：" + ex.Message;
        }
        finally
        {
            syncRulesButton.IsEnabled = true;
        }
    }

    void OnValidateRulesClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (CustomRuleStore.TryValidate(customRulesBox.Text ?? string.Empty, out var rules, out var error))
        {
            customRuleStatus.Text = rules.Rules.Count == 0 && rules.PresetIps.Count == 0
                ? "语法正确，但没有解析到任何规则。"
                : $"校验通过：{rules.Rules.Count} 条规则，{rules.PresetIps.Count} 组预置 IP，{rules.ExcludePatterns.Count} 条排除。";
            customRuleStatus.Foreground = Brush("#2ED573");
        }
        else
        {
            customRuleStatus.Text = "校验失败：" + error;
            customRuleStatus.Foreground = Brush("#FF5D6C");
        }
    }

    void OnSaveRulesClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (!service.Rules.CustomStore.Save(customRulesBox.Text ?? string.Empty, out var rules, out var error))
        {
            customRuleStatus.Text = "保存失败：" + error;
            customRuleStatus.Foreground = Brush("#FF5D6C");
            return;
        }

        service.Rules.SetCustom(rules, error);
        customRuleStatus.Text = $"已保存并应用：{rules.Rules.Count} 条自定义规则。";
        customRuleStatus.Foreground = Brush("#2ED573");
        UpdateRemoteStatus();
    }

    void OnResetRulesClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        customRulesBox.Text = CustomRuleStore.BuildSample(service.Rules.CustomStore.FilePath);
        customRuleStatus.Text = "已填入示例规则，点击“保存并应用”后生效。";
        customRuleStatus.Foreground = Brush("#8A94B0");
    }

    // ---------------- 实验室 ----------------

    async void OnRunLabClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (labBusy) return;

        labBusy = true;
        labRunButton.IsEnabled = false;
        labProgress.IsVisible = true;
        labResultsPanel.Children.Clear();
        labStatus.Text = "正在检测，请稍候…";

        try
        {
            CollectSettingsFromUi();
            var lab = new AccelerationLab(settings, service, logger, fileLogger);
            var report = await lab.RunAsync(labHostBox.Text ?? "github.com");

            lastReport = report.Text;
            labReportBox.Text = report.Text;

            foreach (var result in report.Results)
            {
                labResultsPanel.Children.Add(BuildLabRow(result));
            }

            var required = report.Results.Count(x => !x.Informational);
            var passed = report.Results.Count(x => !x.Informational && x.Success);
            labStatus.Text = $"检测完成：{passed}/{required} 项通过" +
                             (report.AllRequiredPassed ? "。" : "，请查看失败项和报告。");
        }
        catch (Exception ex)
        {
            labStatus.Text = "检测失败：" + ex.Message;
            logger.Warn("Lab", "实验室异常: " + ex.Message);
        }
        finally
        {
            labProgress.IsVisible = false;
            labRunButton.IsEnabled = true;
            labBusy = false;
        }
    }

    static Control BuildLabRow(LabTestResult result)
    {
        var color = result.Informational ? "#8A94B0" : result.Success ? "#2ED573" : "#FF5D6C";
        var status = result.Informational ? "INFO" : result.Success ? "PASS" : "FAIL";

        var grid = new Grid
        {
            ColumnDefinitions = new ColumnDefinitions("58,180,*,Auto"),
            Margin = new Thickness(0, 2),
        };

        var badge = new Border
        {
            Background = Brush(color + "22"),
            BorderBrush = Brush(color + "66"),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(8, 3),
            HorizontalAlignment = HorizontalAlignment.Left,
            Child = new TextBlock
            {
                Text = status,
                FontSize = 11,
                FontWeight = FontWeight.SemiBold,
                Foreground = Brush(color),
            },
        };

        var name = new TextBlock
        {
            Text = result.Name,
            VerticalAlignment = VerticalAlignment.Center,
            Foreground = Brush("#E8ECF8"),
        };

        var detail = new TextBlock
        {
            Text = result.Detail,
            VerticalAlignment = VerticalAlignment.Center,
            Foreground = Brush("#8A94B0"),
            FontSize = 12,
            TextTrimming = TextTrimming.CharacterEllipsis,
        };

        var elapsed = new TextBlock
        {
            Text = result.ElapsedMs > 0 ? result.ElapsedMs + "ms" : string.Empty,
            VerticalAlignment = VerticalAlignment.Center,
            Foreground = Brush("#8A94B0"),
            FontSize = 11,
        };

        Grid.SetColumn(name, 1);
        Grid.SetColumn(detail, 2);
        Grid.SetColumn(elapsed, 3);
        grid.Children.Add(badge);
        grid.Children.Add(name);
        grid.Children.Add(detail);
        grid.Children.Add(elapsed);
        return grid;
    }

    async void OnCopyReportClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(lastReport)) return;
        await CopyTextAsync(lastReport);
        labStatus.Text = "报告已复制到剪贴板。";
    }

    async void OnExportReportClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(lastReport)) return;

        try
        {
            var storage = GetTopLevel(this)?.StorageProvider;
            if (storage == null) return;

            var file = await storage.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "导出加速实验室报告",
                SuggestedFileName = $"netaccel-report-{DateTime.Now:yyyyMMdd-HHmmss}.txt",
                DefaultExtension = "txt",
                FileTypeChoices = new[]
                {
                    new FilePickerFileType("文本文件") { Patterns = new[] { "*.txt" } },
                },
            });

            if (file == null) return;
            await using var stream = await file.OpenWriteAsync();
            await using var writer = new StreamWriter(stream, Encoding.UTF8);
            await writer.WriteAsync(lastReport);
            labStatus.Text = "报告已导出：" + file.Path.LocalPath;
        }
        catch (Exception ex)
        {
            labStatus.Text = "导出失败：" + ex.Message;
        }
    }

    // ---------------- 设置 ----------------

    async void OnSaveSettingsClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        var wasRunning = service.IsRunning;
        var oldSocks = settings.Socks5Port;
        var oldHttp = settings.HttpPort;
        var oldSocksEnabled = settings.EnableSocks5;
        var oldHttpEnabled = settings.EnableHttp;

        CollectSettingsFromUi();

        if (!store.Save(settings))
        {
            await ShowMessageAsync("保存失败", "无法写入设置文件：" + store.FilePath);
            return;
        }

        var needsRestart = wasRunning &&
                           (oldSocks != settings.Socks5Port ||
                            oldHttp != settings.HttpPort ||
                            oldSocksEnabled != settings.EnableSocks5 ||
                            oldHttpEnabled != settings.EnableHttp);

        if (needsRestart)
        {
            var result = await service.RestartAsync();
            await ShowMessageAsync(result.Success ? "已应用" : "重启失败", result.Message);
        }
        else
        {
            service.ReloadRules();
            await ShowMessageAsync("已保存", "设置已保存，规则已重新加载。");
        }

        RefreshStatus();
        RefreshAddress();
        UpdateRemoteStatus();
    }

    async void OnResetSettingsClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (service.IsRunning) await service.StopAsync();

        var defaults = AccelSettings.CreateDefault();
        defaults.Normalize();
        settings.CopyFrom(defaults);
        service.ReloadRules();
        store.Save(settings);
        service.Stats.Reset();

        LoadSettingsIntoUi();
        RefreshStatus();
        RefreshAddress();
        UpdateRemoteStatus();
        statusSubtitle.Text = "已恢复默认设置。";
    }

    // ---------------- 通用操作 ----------------

    async void OnCopySocksClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        => await CopyTextAsync(socksAddressText.Text ?? string.Empty);

    async void OnCopyHttpClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        => await CopyTextAsync(httpAddressText.Text ?? string.Empty);

    void OnOpenDataDirClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        => OpenDirectory(AppPaths.Home);

    void OnOpenLogDirClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        => OpenDirectory(AppPaths.LogDirectory);

    void OnClearLogClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        memoryLog.Clear();
        RefreshLog(force: true);
    }

    async Task CopyTextAsync(string text)
    {
        var clipboard = GetTopLevel(this)?.Clipboard;
        if (clipboard != null) await clipboard.SetTextAsync(text);
    }

    void OpenDirectory(string path)
    {
        try
        {
            Directory.CreateDirectory(path);
            var psi = OperatingSystem.IsWindows()
                ? new ProcessStartInfo("explorer.exe", path)
                : OperatingSystem.IsMacOS()
                    ? new ProcessStartInfo("open", path)
                    : new ProcessStartInfo("xdg-open", path);

            psi.UseShellExecute = false;
            Process.Start(psi);
        }
        catch (Exception ex)
        {
            statusSubtitle.Text = "无法打开目录：" + ex.Message;
            logger.Warn("UI", "打开目录失败: " + ex.Message);
        }
    }

    async Task ShowMessageAsync(string title, string message)
    {
        // 不引入额外弹窗依赖：状态区和日志同时给出结果，避免启动/保存时被模态框打断。
        statusSubtitle.Text = $"{title}：{message}";
        logger.Info("UI", $"{title}: {message}");
        await Task.CompletedTask;
    }

    async void OnClosing(object? sender, WindowClosingEventArgs e)
    {
        if (shuttingDown) return;

        e.Cancel = true;
        shuttingDown = true;

        try
        {
            CollectSettingsFromUi();
            store.Save(settings);
            await service.StopAsync();
        }
        catch (Exception ex)
        {
            CrashReporter.Write(ex, "Closing");
        }
        finally
        {
            timer.Stop();
            Close();
        }
    }

    static IBrush Brush(string color) => new SolidColorBrush(Color.Parse(color));
}
