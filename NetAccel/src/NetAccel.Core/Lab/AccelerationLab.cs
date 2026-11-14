using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using NetAccel.Core.Logging;
using NetAccel.Core.Models;
using NetAccel.Core.Proxy;
using NetAccel.Core.Rules;
using NetAccel.Core.Stats;
using NetAccel.Core.Tls;

namespace NetAccel.Core.Lab;

public sealed record LabTestResult(
    string Name,
    bool Success,
    long ElapsedMs,
    string Detail,
    bool Informational = false)
{
    public string ToLine()
    {
        var status = Informational ? "INFO" : Success ? "PASS" : "FAIL";
        return $"[{status}] {Name} ({ElapsedMs}ms) {Detail}";
    }
}

public sealed class LabReport
{
    public LabReport(string host, DateTimeOffset startedAt, IReadOnlyList<LabTestResult> results, string text)
    {
        Host = host;
        StartedAt = startedAt;
        Results = results;
        Text = text;
    }

    public string Host { get; }
    public DateTimeOffset StartedAt { get; }
    public IReadOnlyList<LabTestResult> Results { get; }
    public string Text { get; }
    public bool AllRequiredPassed => Results.Where(x => !x.Informational).All(x => x.Success);
}

public sealed record StrategyMatrixRow(string Strategy, int Success, int Runs, long MedianMs, string? LastError);

public sealed class StrategyMatrixReport
{
    public StrategyMatrixReport(string host, IReadOnlyList<StrategyMatrixRow> rows, string text)
    {
        Host = host;
        Rows = rows;
        Text = text;
    }

    public string Host { get; }
    public IReadOnlyList<StrategyMatrixRow> Rows { get; }
    public string Text { get; }
}

/// <summary>
/// 加速实验室：把规则、DNS、DoH、TCP、TLS、代理链路、UDP 等检查集中跑一次，
/// 输出可复制/导出的报告。只做只读检查，不修改代理状态。
/// </summary>
public sealed class AccelerationLab
{
    readonly AccelSettings settings;
    readonly AccelProxyService service;
    readonly IAccelLogger log;
    readonly FileLogger? fileLogger;

    public AccelerationLab(AccelSettings settings, AccelProxyService service, IAccelLogger? logger = null,
        FileLogger? fileLogger = null)
    {
        this.settings = settings;
        this.service = service;
        log = logger ?? NullLogger.Instance;
        this.fileLogger = fileLogger;
    }

    public async Task<LabReport> RunAsync(string host, CancellationToken cancellationToken = default)
    {
        host = string.IsNullOrWhiteSpace(host) ? "github.com" : host.Trim();
        var startedAt = DateTimeOffset.Now;
        var results = new List<LabTestResult>();

        results.Add(CheckRules());
        results.Add(CheckSettings());
        results.Add(CheckPorts());
        results.Add(await CheckSystemDnsAsync(host, cancellationToken).ConfigureAwait(false));
        results.Add(await CheckDohAsync(host, cancellationToken).ConfigureAwait(false));
        results.Add(await CheckTcpAsync(host, 443, cancellationToken).ConfigureAwait(false));

        var direct = await SniConnectivityTester.ProbeDirectAsync(host, 443, 8, cancellationToken)
            .ConfigureAwait(false);
        results.Add(new LabTestResult(
            "直连 TLS 握手",
            direct.Success,
            direct.ElapsedMs,
            direct.Success ? $"成功 {direct.TlsVersion}" : direct.Error ?? "失败"));

        if (service.Socks5Running)
        {
            var viaProxy = await SniConnectivityTester.ProbeViaSocks5Async(
                host, 443, service.Socks5Port, 8, cancellationToken).ConfigureAwait(false);
            results.Add(new LabTestResult(
                "SOCKS5 代理 TLS",
                viaProxy.Success,
                viaProxy.ElapsedMs,
                viaProxy.Success
                    ? $"成功 {viaProxy.TlsVersion}（策略 {settings.FragmentStrategy}）"
                    : viaProxy.Error ?? "失败"));
        }
        else
        {
            results.Add(new LabTestResult(
                "SOCKS5 代理 TLS", false, 0, "SOCKS5 服务未运行", Informational: true));
        }

        if (service.HttpRunning)
        {
            results.Add(await CheckHttpProxyAsync(host, cancellationToken).ConfigureAwait(false));
        }
        else
        {
            results.Add(new LabTestResult("HTTP 代理请求", false, 0, "HTTP 服务未运行", Informational: true));
        }

        results.Add(await CheckUdpAsync(host, cancellationToken).ConfigureAwait(false));
        results.Add(new LabTestResult(
            "免证书模式",
            true,
            0,
            "当前实现只做 TCP 隧道与 SNI 处理，不需要安装根证书",
            Informational: true));
        results.Add(CheckPlatform());

        var text = BuildReport(host, startedAt, results);
        log.Info("Lab", $"实验室完成：{results.Count(x => !x.Informational && x.Success)}/{results.Count(x => !x.Informational)} 项通过");
        return new LabReport(host, startedAt, results, text);
    }

    /// <summary>
    /// 分片策略矩阵：在正在运行的代理上依次切换策略，每种重复若干次，
    /// 输出成功次数与中位延迟。对应原项目实验设置页的策略矩阵。
    /// </summary>
    public async Task<StrategyMatrixReport> RunStrategyMatrixAsync(
        string host,
        int runs,
        CancellationToken cancellationToken = default)
    {
        host = string.IsNullOrWhiteSpace(host) ? "github.com" : host.Trim();
        runs = Math.Clamp(runs, 1, 10);

        var sb = new StringBuilder();
        var rows = new List<StrategyMatrixRow>();
        sb.AppendLine("NetAccel 分片策略矩阵");
        sb.AppendLine($"时间: {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
        sb.AppendLine($"目标: {host}:443，每种策略 {runs} 次");
        sb.AppendLine();

        if (!service.Socks5Running)
        {
            sb.AppendLine("SOCKS5 服务未运行，请先启动加速后再运行策略矩阵。");
            return new StrategyMatrixReport(host, rows, sb.ToString());
        }

        var originalStrategy = settings.FragmentStrategy;
        var originalEnabled = settings.EnableSniFragment;

        try
        {
            settings.EnableSniFragment = false;
            service.ClearFallbackCache();
            var baseline = await SniConnectivityTester.ProbeViaSocks5Async(
                host, 443, service.Socks5Port, 8, cancellationToken).ConfigureAwait(false);
            sb.AppendLine($"不分片基准: {baseline}");
            sb.AppendLine();

            settings.EnableSniFragment = true;

            var strategies = new[]
            {
                TlsFragmentStrategy.SniBoundary,
                TlsFragmentStrategy.SniPieces,
                TlsFragmentStrategy.TlsRecordSplit,
                TlsFragmentStrategy.Fixed,
                TlsFragmentStrategy.Record,
                TlsFragmentStrategy.Random,
            };

            foreach (var strategy in strategies)
            {
                cancellationToken.ThrowIfCancellationRequested();

                settings.FragmentStrategy = strategy;
                // 清空失败缓存，避免上一次策略的失败记录让后面直接跳过。
                service.ClearFallbackCache();

                var successes = 0;
                var times = new List<long>();
                string? lastError = null;

                for (var i = 0; i < runs; i++)
                {
                    var result = await SniConnectivityTester.ProbeViaSocks5Async(
                        host, 443, service.Socks5Port, 8, cancellationToken).ConfigureAwait(false);
                    if (result.Success)
                    {
                        successes++;
                        times.Add(result.ElapsedMs);
                    }
                    else
                    {
                        lastError = result.Error;
                    }
                }

                times.Sort();
                var median = times.Count == 0 ? 0 : times[times.Count / 2];
                rows.Add(new StrategyMatrixRow(strategy.ToString(), successes, runs, median, lastError));
                sb.AppendLine(
                    $"{GetStrategyName(strategy),-14} 成功 {successes}/{runs} 中位 {median}ms" +
                    (lastError == null ? string.Empty : $"，最后错误: {lastError}"));
            }

            sb.AppendLine();
            sb.AppendLine("判读：");
            sb.AppendLine("- 全部成功通常说明当前网络没有阻断该目标，无法据此判断分片是否有效。");
            sb.AppendLine("- 部分成功说明策略不稳定；记录型 DPI 只能被 TLS record 拆分或上游中继绕过。");
            sb.AppendLine("- 若直连/QoS 抖动明显，优先比较中位耗时，而不是单次结果。");
        }
        finally
        {
            settings.FragmentStrategy = originalStrategy;
            settings.EnableSniFragment = originalEnabled;
            service.ClearFallbackCache();
        }

        return new StrategyMatrixReport(host, rows, sb.ToString());
    }

    public static string GetStrategyName(TlsFragmentStrategy strategy) => strategy switch
    {
        TlsFragmentStrategy.Fixed => "固定大小",
        TlsFragmentStrategy.Record => "TLS 记录头",
        TlsFragmentStrategy.SniPieces => "SNI 多段",
        TlsFragmentStrategy.TlsRecordSplit => "TLS record 拆分",
        TlsFragmentStrategy.Random => "随机分片",
        _ => "SNI 边界",
    };

    LabTestResult CheckRules()
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var current = service.Rules.Current;
            var customActive = settings.EnableCustomRules ? service.Rules.CustomRuleCount : 0;
            var remoteActive = Math.Max(0, current.Rules.Count - customActive);
            var detail = $"自定义 {customActive} 条，远程启用 {remoteActive} 条，" +
                         $"排除 {current.ExcludePatterns.Count} 条，预置 IP {current.PresetIps.Count} 组";
            if (!string.IsNullOrEmpty(service.Rules.LastCustomError))
            {
                detail += $"；自定义规则错误: {service.Rules.LastCustomError}";
            }

            return new LabTestResult(
                "规则集",
                current.Rules.Count > 0 || current.PresetIps.Count > 0,
                sw.ElapsedMilliseconds,
                detail,
                Informational: current.Rules.Count == 0);
        }
        catch (Exception ex)
        {
            return new LabTestResult("规则集", false, sw.ElapsedMilliseconds, ex.Message);
        }
    }

    LabTestResult CheckSettings()
    {
        var detail =
            $"SOCKS5={(settings.EnableSocks5 ? settings.Socks5Port.ToString() : "关")}，" +
            $"HTTP={(settings.EnableHttp ? settings.HttpPort.ToString() : "关")}，" +
            $"分片={(settings.EnableSniFragment ? settings.FragmentStrategy.ToString() : "关")}，" +
            $"DoH={(settings.EnableDoh ? "开" : "关")}，" +
            $"中继={(settings.EnableUpstreamRelay ? $"{settings.RelayHost}:{settings.RelayPort}" : "关")}";
        return new LabTestResult("当前设置", true, 0, detail, Informational: true);
    }

    LabTestResult CheckPorts()
    {
        var sw = Stopwatch.StartNew();
        var running = service.IsRunning;
        var detail = running
            ? $"SOCKS5 {(service.Socks5Running ? "监听 " + service.Socks5Port : "未启动")}，" +
              $"HTTP {(service.HttpRunning ? "监听 " + service.HttpPort : "未启动")}"
            : "代理未启动";
        return new LabTestResult("监听端口", running, sw.ElapsedMilliseconds, detail, Informational: !running);
    }

    async Task<LabTestResult> CheckSystemDnsAsync(string host, CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(6));
            var addresses = await Dns.GetHostAddressesAsync(host, cts.Token).ConfigureAwait(false);
            var ipv4 = addresses.Where(x => x.AddressFamily == AddressFamily.InterNetwork).Take(4).ToList();
            var text = string.Join(", ", ipv4.Select(x => x.ToString()));
            return new LabTestResult("系统 DNS", addresses.Length > 0, sw.ElapsedMilliseconds,
                string.IsNullOrEmpty(text) ? "仅有 IPv6 结果" : text);
        }
        catch (Exception ex)
        {
            return new LabTestResult("系统 DNS", false, sw.ElapsedMilliseconds, Describe(ex));
        }
    }

    async Task<LabTestResult> CheckDohAsync(string host, CancellationToken cancellationToken)
    {
        if (!settings.EnableDoh)
        {
            return new LabTestResult("DoH 解析", true, 0, "未启用", Informational: true);
        }

        var sw = Stopwatch.StartNew();
        try
        {
            using var resolver = new Net.DohResolver(settings, log);
            var addresses = await resolver.ResolveAsync(host, cancellationToken).ConfigureAwait(false);
            var text = addresses.Count == 0 ? "无结果" : string.Join(", ", addresses.Take(4));
            return new LabTestResult("DoH 解析", addresses.Count > 0, sw.ElapsedMilliseconds, text);
        }
        catch (Exception ex)
        {
            return new LabTestResult("DoH 解析", false, sw.ElapsedMilliseconds, ex.Message);
        }
    }

    async Task<LabTestResult> CheckTcpAsync(string host, int port, CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        using var client = new TcpClient();
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(6));
            await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            return new LabTestResult($"TCP {port}", true, sw.ElapsedMilliseconds,
                client.Client.RemoteEndPoint?.ToString() ?? "已连接");
        }
        catch (Exception ex)
        {
            return new LabTestResult($"TCP {port}", false, sw.ElapsedMilliseconds, Describe(ex));
        }
    }

    async Task<LabTestResult> CheckHttpProxyAsync(string host, CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var handler = new SocketsHttpHandler
            {
                Proxy = new WebProxy($"http://127.0.0.1:{service.HttpPort}"),
                UseProxy = true,
                ConnectTimeout = TimeSpan.FromSeconds(8),
                AllowAutoRedirect = false,
            };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(12) };

            using var request = new HttpRequestMessage(HttpMethod.Get, $"https://{host}/");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);
            var code = (int)response.StatusCode;
            return new LabTestResult("HTTP 代理请求", code is >= 200 and < 500, sw.ElapsedMilliseconds,
                $"https://{host}/ -> {code}");
        }
        catch (Exception ex)
        {
            return new LabTestResult("HTTP 代理请求", false, sw.ElapsedMilliseconds, Describe(ex));
        }
    }

    async Task<LabTestResult> CheckUdpAsync(string host, CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            var addresses = await Dns.GetHostAddressesAsync(host, cts.Token).ConfigureAwait(false);
            var address = addresses.FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork);
            if (address == null)
            {
                return new LabTestResult("UDP 443 探测", true, sw.ElapsedMilliseconds, "没有 IPv4 地址，跳过",
                    Informational: true);
            }

            using var udp = new UdpClient(address.AddressFamily);
            await udp.SendAsync(new byte[] { 0x00 }, 1, new IPEndPoint(address, 443)).ConfigureAwait(false);
            return new LabTestResult("UDP 443 探测", true, sw.ElapsedMilliseconds,
                "已发出探测包；UDP 无连接，无法据此判断是否被阻断", Informational: true);
        }
        catch (Exception ex)
        {
            return new LabTestResult("UDP 443 探测", false, sw.ElapsedMilliseconds, ex.Message,
                Informational: true);
        }
    }

    LabTestResult CheckPlatform()
    {
        var detail = $"{Environment.OSVersion.VersionString} / .NET {Environment.Version} / {(Environment.Is64BitProcess ? "x64" : "x86")}";
        return new LabTestResult("运行环境", true, 0, detail, Informational: true);
    }

    string BuildReport(string host, DateTimeOffset startedAt, IReadOnlyList<LabTestResult> results)
    {
        var sb = new StringBuilder();
        sb.AppendLine("NetAccel 加速实验室报告");
        sb.AppendLine($"时间: {startedAt:yyyy-MM-dd HH:mm:ss zzz}");
        sb.AppendLine($"目标: {host}");
        sb.AppendLine($"数据目录: {AppPaths.Home}");
        sb.AppendLine();

        sb.AppendLine("== 设置快照 ==");
        AppendSettingsSnapshot(sb);
        sb.AppendLine();

        sb.AppendLine("== 测试结果 ==");
        foreach (var result in results) sb.AppendLine(result.ToLine());

        sb.AppendLine();
        sb.AppendLine("== 运行统计 ==");
        sb.AppendLine(FormatStats(service.Stats.GetSnapshot()));

        if (fileLogger != null)
        {
            var tail = fileLogger.ReadRecent(120);
            if (!string.IsNullOrWhiteSpace(tail))
            {
                sb.AppendLine();
                sb.AppendLine("== 最近日志 ==");
                sb.AppendLine(tail);
            }
        }

        return sb.ToString();
    }

    void AppendSettingsSnapshot(StringBuilder sb)
    {
        sb.AppendLine($"监听: SOCKS5 {settings.Socks5Port} / HTTP {settings.HttpPort}，地址 {settings.ListenAddress}");
        sb.AppendLine($"规则: 远程={settings.EnableRemoteRules}，组={settings.EnabledRuleGroups}，自定义={settings.EnableCustomRules}");
        sb.AppendLine($"分片: {settings.EnableSniFragment}，策略={settings.FragmentStrategy}，大小={settings.FragmentChunkSize}B，" +
                      $"段数={settings.SplitPieces}，延迟={settings.FragmentDelayMs}ms，抖动={settings.FragmentJitterMs}ms");
        sb.AppendLine($"分片域名: {settings.FragmentDomains}");
        sb.AppendLine($"回退: {settings.EnableFragmentFallback}，探测={settings.FallbackProbeMs}ms，缓存={settings.FallbackCacheMinutes} 分钟");
        sb.AppendLine($"SNI 改写: {settings.EnableSniRewrite}，目标={settings.SniRewriteHost}");
        sb.AppendLine($"DoH: {settings.EnableDoh}，{settings.DohEndpoint}，回退系统 DNS={settings.DohFallbackToSystem}");
        sb.AppendLine($"上游中继: {settings.EnableUpstreamRelay}，{settings.RelayHost}:{settings.RelayPort}，" +
                      $"域名={(string.IsNullOrWhiteSpace(settings.RelayDomains) ? "全部" : settings.RelayDomains)}");
    }

    public static string FormatStats(ProxyStats.Snapshot snapshot)
        => $"连接 {snapshot.Connections} / 活动 {snapshot.ActiveConnections} / 分片 {snapshot.Fragmented} / " +
           $"改写 {snapshot.Rewritten} / 预置IP {snapshot.PresetIp} / 中继 {snapshot.Relayed} / " +
           $"回退 {snapshot.Fallbacks} / 重连 {snapshot.Reconnects} / 失败 {snapshot.Failures} / " +
           $"上行 {FormatBytes(snapshot.BytesUp)} / 下行 {FormatBytes(snapshot.BytesDown)}";

    public static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return (bytes / 1024d).ToString("0.0") + " KB";
        if (bytes < 1024L * 1024 * 1024) return (bytes / 1024d / 1024).ToString("0.0") + " MB";
        return (bytes / 1024d / 1024 / 1024).ToString("0.00") + " GB";
    }

    static string Describe(Exception ex)
    {
        if (ex is OperationCanceledException) return "超时/已取消";
        if (ex is SocketException socket) return $"网络错误 {socket.SocketErrorCode}";
        if (ex.InnerException is SocketException inner) return $"网络错误 {inner.SocketErrorCode}";
        return ex.Message;
    }
}
