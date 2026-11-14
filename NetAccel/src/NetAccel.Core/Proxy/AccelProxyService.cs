using NetAccel.Core.Logging;
using NetAccel.Core.Models;
using NetAccel.Core.Net;
using NetAccel.Core.Rules;
using NetAccel.Core.Stats;
using NetAccel.Core.SystemProxy;

namespace NetAccel.Core.Proxy;

public sealed record StartResult(bool Success, string Message);

/// <summary>
/// 加速器门面：持有规则、统计、DNS 与两个本地代理服务，负责启动/停止/重启。
/// UI、CLI 都只依赖这个类，避免把网络细节散落到界面代码里。
/// </summary>
public sealed class AccelProxyService : IAsyncDisposable
{
    readonly SemaphoreSlim lifecycle = new(1, 1);
    readonly IAccelLogger log;
    readonly SystemProxyManager systemProxy;

    RuleEngine? rules;
    DohResolver? doh;
    PresetIpSelector? presetSelector;
    FragmentFallbackCache? fallbackCache;
    UpstreamConnector? connector;
    TunnelSession? tunnel;
    Socks5Server? socksServer;
    HttpProxyServer? httpServer;

    bool running;
    bool systemProxyEnabledByUs;

    public AccelProxyService(AccelSettings settings, IAccelLogger? logger = null, SystemProxyManager? systemProxy = null)
    {
        Settings = settings;
        log = logger ?? NullLogger.Instance;
        this.systemProxy = systemProxy ?? new SystemProxyManager();
        Stats = new ProxyStats();
    }

    public AccelSettings Settings { get; }

    public ProxyStats Stats { get; }

    public bool IsRunning => running;

    public int Socks5Port => socksServer?.Port ?? Settings.Socks5Port;

    public int HttpPort => httpServer?.Port ?? Settings.HttpPort;

    public bool Socks5Running => socksServer?.IsRunning == true;

    public bool HttpRunning => httpServer?.IsRunning == true;

    public RuleEngine Rules => rules ??= CreateRuleEngine();

    public event Action? StateChanged;

    RuleEngine CreateRuleEngine() => new(Settings, log);

    public async Task<StartResult> StartAsync(CancellationToken cancellationToken = default)
    {
        await lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (running) return new StartResult(true, "代理已在运行");

            Settings.Normalize();
            AppPaths.EnsureDirectories();

            if (!Settings.EnableSocks5 && !Settings.EnableHttp)
            {
                return new StartResult(false, "至少需要启用 SOCKS5 或 HTTP 其中一个协议。");
            }

            rules ??= CreateRuleEngine();
            rules.Initialize();

            if (Settings.EnableRemoteRules && Settings.SyncRemoteRulesOnStart)
            {
                TryObserveSync();
            }

            doh = new DohResolver(Settings, log);
            presetSelector = new PresetIpSelector(log);
            fallbackCache = new FragmentFallbackCache
            {
                Duration = TimeSpan.FromMinutes(Settings.FallbackCacheMinutes),
            };
            connector = new UpstreamConnector(Settings, rules, doh, presetSelector, log, Stats);
            tunnel = new TunnelSession(Settings, rules, connector, Stats, fallbackCache, log);

            if (Settings.EnableSocks5)
            {
                try
                {
                    socksServer = new Socks5Server(Settings, rules, tunnel, Stats, log);
                    socksServer.Start();
                }
                catch (Exception ex)
                {
                    DisposeServers();
                    return new StartResult(false, DescribeBindError("SOCKS5", Settings.Socks5Port, ex));
                }
            }

            if (Settings.EnableHttp)
            {
                try
                {
                    httpServer = new HttpProxyServer(Settings, rules, tunnel, Stats, log);
                    httpServer.Start();
                }
                catch (Exception ex)
                {
                    DisposeServers();
                    return new StartResult(false, DescribeBindError("HTTP", Settings.HttpPort, ex));
                }
            }

            running = true;

            var message = "代理已启动";
            if (Settings.SetSystemProxy)
            {
                if (!Settings.EnableHttp)
                {
                    message += "；系统代理未开启：需要同时启用 HTTP 端口";
                    log.Warn("SystemProxy", "系统代理需要 HTTP 端口，当前已关闭");
                }
                else if (systemProxy.Enable(Settings.HttpPort, Settings.Socks5Port, out var proxyMessage))
                {
                    systemProxyEnabledByUs = true;
                    message += "；" + proxyMessage;
                }
                else
                {
                    message += "；系统代理未开启：" + proxyMessage;
                    log.Warn("SystemProxy", proxyMessage);
                }
            }

            StateChanged?.Invoke();
            return new StartResult(true, message);
        }
        finally
        {
            lifecycle.Release();
        }
    }

    void TryObserveSync()
    {
        _ = Task.Run(async () =>
        {
            try
            {
                await Rules.SyncRemoteAsync().ConfigureAwait(false);
            }
            catch
            {
                // 同步失败不影响代理启动
            }
        });
    }

    static string DescribeBindError(string name, int port, Exception ex)
    {
        if (ex is System.Net.Sockets.SocketException socket &&
            socket.SocketErrorCode == System.Net.Sockets.SocketError.AddressAlreadyInUse)
        {
            return $"{name} 端口 {port} 已被占用，请换一个端口或在设置中关闭该协议。";
        }

        if (ex is ArgumentException)
        {
            return $"{name} 监听地址或端口无效：{ex.Message}";
        }

        return $"{name} 启动失败：{ex.Message}";
    }

    public async Task StopAsync()
    {
        await lifecycle.WaitAsync().ConfigureAwait(false);
        try
        {
            running = false;
            DisposeServers();

            // 即使上次运行异常退出（running 已为 false），也要根据状态文件恢复系统代理。
            if (systemProxyEnabledByUs || systemProxy.IsEnabledByUs)
            {
                if (!systemProxy.Disable(out var message))
                {
                    log.Warn("SystemProxy", message);
                }
                systemProxyEnabledByUs = false;
            }

            StateChanged?.Invoke();
        }
        finally
        {
            lifecycle.Release();
        }
    }

    public async Task<StartResult> RestartAsync(CancellationToken cancellationToken = default)
    {
        await StopAsync().ConfigureAwait(false);
        return await StartAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>规则变更后调用：重新加载自定义规则并重建合并规则集。</summary>
    public void ReloadRules()
    {
        Rules.ReloadCustom();
        Rules.Rebuild();
    }

    /// <summary>清空“分片失败域名”缓存，实验室策略矩阵会用到。</summary>
    public void ClearFallbackCache() => fallbackCache?.Clear();

    public Task SyncRulesAsync(CancellationToken cancellationToken = default) => Rules.SyncRemoteAsync(cancellationToken);

    void DisposeServers()
    {
        try
        {
            socksServer?.Dispose();
        }
        catch
        {
            // ignore
        }
        socksServer = null;

        try
        {
            httpServer?.Dispose();
        }
        catch
        {
            // ignore
        }
        httpServer = null;

        doh?.Dispose();
        doh = null;
        presetSelector?.Clear();
        presetSelector = null;
        fallbackCache?.Clear();
        fallbackCache = null;
        connector = null;
        tunnel = null;
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        lifecycle.Dispose();
    }
}
