using System.Net;
using System.Net.Sockets;
using System.Text;
using NetAccel.Core.Lab;
using NetAccel.Core.Logging;
using NetAccel.Core.Models;
using NetAccel.Core.Proxy;
using NetAccel.Core.Tls;

namespace NetAccel.Cli;

internal static class Program
{
    static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        var options = CliOptions.Parse(args);

        if (options.ShowHelp)
        {
            PrintHelp();
            return 0;
        }

        try
        {
            if (!string.IsNullOrWhiteSpace(options.DataDirectory))
            {
                AppPaths.Home = Path.GetFullPath(options.DataDirectory);
            }

            AppPaths.EnsureDirectories();
            var store = new SettingsStore();
            var settings = store.Load();
            options.ApplyTo(settings);

            if (options.Verbose)
            {
                Console.WriteLine($"数据目录: {AppPaths.Home}");
                Console.WriteLine($"设置文件: {store.FilePath}");
            }

            var logger = new ConsoleLogger(settings.EnableDiagnostics ? new FileLogger(
                AppPaths.LogDirectory,
                enabled: () => true,
                minimumLevel: () => settings.DiagnosticsMinimumLevel,
                includeHost: () => settings.DiagnosticsIncludeHost,
                retentionDays: () => settings.DiagnosticsRetentionDays,
                maxFileSizeKB: () => settings.DiagnosticsMaxFileSizeKB) : NullLogger.Instance);

            switch (options.Command)
            {
                case "run":
                    return await RunAsync(settings, logger);
                case "check":
                    return await CheckAsync(settings, logger, options.Host);
                case "sync":
                    return await SyncAsync(settings, logger);
                case "info":
                    PrintInfo(settings, store);
                    return 0;
                case "selftest":
                    return await SelfTestAsync(settings, logger);
                case "help":
                    PrintHelp();
                    return 0;
                default:
                    Console.Error.WriteLine($"未知命令: {options.Command}");
                    PrintHelp();
                    return 2;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("运行失败: " + ex.Message);
            if (options.Verbose) Console.Error.WriteLine(ex);
            return 1;
        }
    }

    static async Task<int> RunAsync(AccelSettings settings, IAccelLogger logger)
    {
        await using var service = new AccelProxyService(settings, logger);
        var result = await service.StartAsync();
        Console.WriteLine(result.Message);
        if (!result.Success) return 1;

        Console.WriteLine($"SOCKS5: {(settings.EnableSocks5 ? $"socks5://127.0.0.1:{service.Socks5Port}" : "已关闭")}");
        Console.WriteLine($"HTTP:   {(settings.EnableHttp ? $"http://127.0.0.1:{service.HttpPort}" : "已关闭")}");
        Console.WriteLine($"PAC:    {(settings.EnableHttp ? $"http://127.0.0.1:{service.HttpPort}/pac" : "已关闭")}");
        Console.WriteLine("按 Ctrl+C 停止代理。");

        var stopped = new TaskCompletionSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            stopped.TrySetResult();
        };

        var statsTimer = new Timer(_ =>
        {
            var snapshot = service.Stats.GetSnapshot();
            Console.WriteLine(AccelerationLab.FormatStats(snapshot));
        }, null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));

        await stopped.Task;
        statsTimer.Dispose();
        await service.StopAsync();
        Console.WriteLine("代理已停止。");
        return 0;
    }

    static async Task<int> CheckAsync(AccelSettings settings, IAccelLogger logger, string host)
    {
        // 实验室只做检查，绝不修改系统代理。
        settings.SetSystemProxy = false;

        await using var service = new AccelProxyService(settings, logger);
        var start = await service.StartAsync();
        if (!start.Success)
        {
            Console.Error.WriteLine(start.Message);
            return 1;
        }

        Console.WriteLine("正在运行加速实验室，请稍候…");
        var lab = new AccelerationLab(settings, service, logger);
        var report = await lab.RunAsync(host);
        Console.WriteLine();
        Console.WriteLine(report.Text);

        await service.StopAsync();
        return report.AllRequiredPassed ? 0 : 1;
    }

    static async Task<int> SyncAsync(AccelSettings settings, IAccelLogger logger)
    {
        var rules = new Core.Rules.RuleEngine(settings, logger);
        rules.Initialize();
        Console.WriteLine($"同步远程规则: {settings.RemoteRuleUrl}");
        await rules.SyncRemoteAsync();

        Console.WriteLine($"远程规则: {rules.Remote.Rules.Count} 条，预置 IP: {rules.Remote.PresetIps.Count} 组");
        Console.WriteLine($"当前生效: {rules.Current.Rules.Count} 条");
        if (!string.IsNullOrEmpty(rules.LastError)) Console.Error.WriteLine("错误: " + rules.LastError);
        return rules.Remote.Rules.Count > 0 ? 0 : 1;
    }

    static void PrintInfo(AccelSettings settings, SettingsStore store)
    {
        Console.WriteLine("NetAccel 网络加速器");
        Console.WriteLine($"数据目录: {AppPaths.Home}");
        Console.WriteLine($"设置文件: {store.FilePath}");
        Console.WriteLine($"自定义规则: {AppPaths.CustomRulesFile}");
        Console.WriteLine($"远程规则缓存: {AppPaths.RemoteRulesCacheFile}");
        Console.WriteLine($"日志目录: {AppPaths.LogDirectory}");
        Console.WriteLine();
        Console.WriteLine($"SOCKS5: {settings.Socks5Port} ({settings.EnableSocks5})");
        Console.WriteLine($"HTTP:   {settings.HttpPort} ({settings.EnableHttp})");
        Console.WriteLine($"分片:   {settings.EnableSniFragment} / {settings.FragmentStrategy}");
        Console.WriteLine($"DoH:    {settings.EnableDoh} / {settings.DohEndpoint}");
        Console.WriteLine($"中继:   {settings.EnableUpstreamRelay} / {settings.RelayHost}:{settings.RelayPort}");
        Console.WriteLine($"规则:   远程={settings.EnableRemoteRules} 组={settings.EnabledRuleGroups} 自定义={settings.EnableCustomRules}");
    }

    /// <summary>
    /// 端到端自检：本地起一个 echo 服务，经 SOCKS5 与 HTTP CONNECT 各走一遍，
    /// 不依赖外网，适合 CI 和打包后冒烟测试。
    /// </summary>
    static async Task<int> SelfTestAsync(AccelSettings settings, IAccelLogger logger)
    {
        settings.EnableRemoteRules = false;
        settings.EnableCustomRules = false;
        settings.EnableDoh = false;
        settings.EnableSniFragment = false;
        settings.EnableHttp = true;
        settings.EnableSocks5 = true;
        settings.SetSystemProxy = false;
        settings.Socks5Port = GetFreePort();
        settings.HttpPort = GetFreePort();

        using var echo = new EchoServer();
        Console.WriteLine($"Echo 服务: 127.0.0.1:{echo.Port}");

        await using var service = new AccelProxyService(settings, logger);
        var start = await service.StartAsync();
        if (!start.Success)
        {
            Console.Error.WriteLine(start.Message);
            return 1;
        }

        try
        {
            var socksOk = await TestSocksAsync(echo.Port, service.Socks5Port);
            var httpOk = await TestHttpConnectAsync(echo.Port, service.HttpPort);

            Console.WriteLine($"[{(socksOk ? "PASS" : "FAIL")}] SOCKS5 隧道回显");
            Console.WriteLine($"[{(httpOk ? "PASS" : "FAIL")}] HTTP CONNECT 隧道回显");

            return socksOk && httpOk ? 0 : 1;
        }
        finally
        {
            await service.StopAsync();
        }
    }

    static int GetFreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    static async Task<bool> TestSocksAsync(int echoPort, int socksPort)
    {
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, socksPort);
            var stream = client.GetStream();

            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 });
            var greeting = new byte[2];
            if (!await ReadExactAsync(stream, greeting)) return false;
            if (greeting[0] != 0x05 || greeting[1] != 0x00) return false;

            var host = IPAddress.Loopback.GetAddressBytes();
            var request = new byte[10];
            request[0] = 0x05;
            request[1] = 0x01;
            request[2] = 0x00;
            request[3] = 0x01;
            host.CopyTo(request, 4);
            request[8] = (byte)(echoPort >> 8);
            request[9] = (byte)(echoPort & 0xFF);
            await stream.WriteAsync(request);

            var reply = new byte[10];
            if (!await ReadExactAsync(stream, reply)) return false;
            if (reply[1] != 0x00) return false;

            return await EchoThroughAsync(stream);
        }
        catch
        {
            return false;
        }
    }

    static async Task<bool> TestHttpConnectAsync(int echoPort, int httpPort)
    {
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, httpPort);
            var stream = client.GetStream();

            var connect = Encoding.ASCII.GetBytes(
                $"CONNECT 127.0.0.1:{echoPort} HTTP/1.1\r\nHost: 127.0.0.1:{echoPort}\r\n\r\n");
            await stream.WriteAsync(connect);

            var header = new List<byte>();
            var one = new byte[1];
            while (header.Count < 8192)
            {
                if (!await ReadExactAsync(stream, one)) return false;
                header.Add(one[0]);
                if (header.Count >= 4 &&
                    header[^4] == '\r' && header[^3] == '\n' && header[^2] == '\r' && header[^1] == '\n')
                {
                    break;
                }
            }

            var headerText = Encoding.ASCII.GetString(header.ToArray());
            if (!headerText.StartsWith("HTTP/1.1 200", StringComparison.Ordinal)) return false;

            return await EchoThroughAsync(stream);
        }
        catch
        {
            return false;
        }
    }

    static async Task<bool> EchoThroughAsync(Stream stream)
    {
        var payload = Encoding.UTF8.GetBytes("netaccel-selftest-" + Guid.NewGuid().ToString("N"));
        await stream.WriteAsync(payload);

        var response = new byte[payload.Length];
        if (!await ReadExactAsync(stream, response)) return false;
        return response.SequenceEqual(payload);
    }

    static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total));
            if (read <= 0) return false;
            total += read;
        }
        return true;
    }

    static void PrintHelp()
    {
        Console.WriteLine("""
NetAccel 网络加速器 (命令行)

用法:
  netaccel run        [选项]   启动本地代理并保持运行
  netaccel check      [选项]   运行加速实验室并打印报告
  netaccel sync       [选项]   同步远程 DevSidecar 规则
  netaccel selftest   [选项]   本地端到端自检（不需要外网）
  netaccel info       [选项]   显示数据目录与当前设置
  netaccel help                显示帮助

选项:
  --data-dir <path>       覆盖数据目录（默认 ~/.config/NetAccel）
  --socks-port <port>     覆盖 SOCKS5 端口
  --http-port <port>      覆盖 HTTP 端口
  --host <host>           实验室测试目标（默认 github.com）
  --strategy <name>       sni|fixed|record|pieces|record-split|random
  --no-fragment           关闭 SNI 分片
  --no-doh                关闭 DoH
  --system-proxy          启动时设置系统代理
  --relay <host:port>     启用上游 SOCKS5 中继
  --verbose               输出详细信息
""");
    }

    sealed class EchoServer : IDisposable
    {
        readonly TcpListener listener = new(IPAddress.Loopback, 0);
        readonly CancellationTokenSource cts = new();
        readonly Task acceptTask;

        public EchoServer()
        {
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
            acceptTask = Task.Run(() => AcceptLoopAsync(cts.Token));
        }

        public int Port { get; }

        async Task AcceptLoopAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    var client = await listener.AcceptTcpClientAsync(cancellationToken);
                    _ = Task.Run(async () =>
                    {
                        using (client)
                        {
                            try
                            {
                                var stream = client.GetStream();
                                var buffer = new byte[16 * 1024];
                                while (true)
                                {
                                    var read = await stream.ReadAsync(buffer, cancellationToken);
                                    if (read <= 0) break;
                                    await stream.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                                }
                            }
                            catch
                            {
                                // ignore
                            }
                        }
                    }, CancellationToken.None);
                }
                catch
                {
                    return;
                }
            }
        }

        public void Dispose()
        {
            cts.Cancel();
            listener.Stop();
            try
            {
                acceptTask.Wait(1000);
            }
            catch
            {
                // ignore
            }
        }
    }
}

internal sealed class CliOptions
{
    public string Command { get; private set; } = "run";
    public bool ShowHelp { get; private set; }
    public bool Verbose { get; private set; }
    public string? DataDirectory { get; private set; }
    public string Host { get; private set; } = "github.com";
    public int? SocksPort { get; private set; }
    public int? HttpPort { get; private set; }
    public string? Strategy { get; private set; }
    public bool DisableFragment { get; private set; }
    public bool DisableDoh { get; private set; }
    public bool SystemProxy { get; private set; }
    public string? Relay { get; private set; }

    public static CliOptions Parse(string[] args)
    {
        var options = new CliOptions();
        var commandSet = false;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            switch (arg)
            {
                case "-h":
                case "--help":
                    options.ShowHelp = true;
                    break;
                case "--verbose":
                    options.Verbose = true;
                    break;
                case "--data-dir":
                    options.DataDirectory = Next(args, ref i);
                    break;
                case "--host":
                    options.Host = Next(args, ref i) ?? "github.com";
                    break;
                case "--socks-port":
                    options.SocksPort = ParseInt(Next(args, ref i));
                    break;
                case "--http-port":
                    options.HttpPort = ParseInt(Next(args, ref i));
                    break;
                case "--strategy":
                    options.Strategy = Next(args, ref i);
                    break;
                case "--no-fragment":
                    options.DisableFragment = true;
                    break;
                case "--no-doh":
                    options.DisableDoh = true;
                    break;
                case "--system-proxy":
                    options.SystemProxy = true;
                    break;
                case "--relay":
                    options.Relay = Next(args, ref i);
                    break;
                default:
                    if (!arg.StartsWith('-') && !commandSet)
                    {
                        options.Command = arg.ToLowerInvariant();
                        commandSet = true;
                    }
                    break;
            }
        }

        return options;
    }

    static string? Next(string[] args, ref int index)
        => index + 1 < args.Length ? args[++index] : null;

    static int? ParseInt(string? value)
        => int.TryParse(value, out var result) ? result : null;

    public void ApplyTo(AccelSettings settings)
    {
        if (SocksPort is > 0 and <= 65535) settings.Socks5Port = SocksPort.Value;
        if (HttpPort is > 0 and <= 65535) settings.HttpPort = HttpPort.Value;
        if (DisableFragment) settings.EnableSniFragment = false;
        if (DisableDoh) settings.EnableDoh = false;
        if (SystemProxy) settings.SetSystemProxy = true;

        if (!string.IsNullOrWhiteSpace(Strategy))
        {
            settings.FragmentStrategy = Strategy.ToLowerInvariant() switch
            {
                "fixed" => TlsFragmentStrategy.Fixed,
                "record" => TlsFragmentStrategy.Record,
                "pieces" or "sni-pieces" => TlsFragmentStrategy.SniPieces,
                "record-split" or "tls-record" => TlsFragmentStrategy.TlsRecordSplit,
                "random" => TlsFragmentStrategy.Random,
                _ => TlsFragmentStrategy.SniBoundary,
            };
        }

        if (!string.IsNullOrWhiteSpace(Relay))
        {
            var parts = Relay.Split(':');
            if (parts.Length == 2 && int.TryParse(parts[1], out var relayPort))
            {
                settings.EnableUpstreamRelay = true;
                settings.RelayHost = parts[0];
                settings.RelayPort = relayPort;
            }
        }

        settings.Normalize();
    }
}

internal sealed class ConsoleLogger : IAccelLogger
{
    readonly IAccelLogger inner;
    readonly object sync = new();

    public ConsoleLogger(IAccelLogger inner) => this.inner = inner;

    public void Info(string tag, string message)
    {
        inner.Info(tag, message);
        Write("INFO", tag, message);
    }

    public void Warn(string tag, string message)
    {
        inner.Warn(tag, message);
        Write("WARN", tag, message);
    }

    public void Error(string tag, string message, Exception? exception = null)
    {
        inner.Error(tag, message, exception);
        Write("ERROR", tag, message + (exception == null ? string.Empty : " | " + exception.Message));
    }

    static void Write(string level, string tag, string message)
    {
        Console.WriteLine($"{DateTime.Now:HH:mm:ss} [{level}] [{tag}] {message}");
    }
}
