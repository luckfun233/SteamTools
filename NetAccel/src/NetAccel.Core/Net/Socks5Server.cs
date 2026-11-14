using System.Net;
using System.Net.Sockets;
using NetAccel.Core.Logging;
using NetAccel.Core.Models;
using NetAccel.Core.Rules;
using NetAccel.Core.Stats;

namespace NetAccel.Core.Net;

/// <summary>
/// 本地 SOCKS5 服务，只支持 CONNECT（TCP）。每条连接都会经过规则匹配、
/// SNI 改写/分片、预置 IP / DoH / 上游中继，然后双向转发。
/// </summary>
public sealed class Socks5Server : IDisposable
{
    const int MaxConcurrentConnections = 512;

    readonly AccelSettings settings;
    readonly RuleEngine rules;
    readonly TunnelSession tunnel;
    readonly ProxyStats stats;
    readonly IAccelLogger log;

    readonly CancellationTokenSource cts = new();
    readonly SemaphoreSlim concurrency = new(MaxConcurrentConnections);
    TcpListener? listener;
    Task? acceptTask;

    public Socks5Server(
        AccelSettings settings,
        RuleEngine rules,
        TunnelSession tunnel,
        ProxyStats stats,
        IAccelLogger logger)
    {
        this.settings = settings;
        this.rules = rules;
        this.tunnel = tunnel;
        this.stats = stats;
        log = logger;
    }

    public int Port { get; private set; }

    public bool IsRunning => listener != null;

    public void Start()
    {
        var address = ParseListenAddress(settings.ListenAddress);
        listener = new TcpListener(address, settings.Socks5Port);
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        acceptTask = Task.Run(() => AcceptLoopAsync(cts.Token));
        log.Info("SOCKS5", $"已监听 {address}:{Port}");
        if (!IPAddress.IsLoopback(address))
        {
            log.Warn("SOCKS5", "SOCKS5 未监听回环地址，局域网内其它设备可以使用该代理，请确认网络环境可信。");
        }
    }

    async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener!.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException)
            {
                return;
            }
            catch (Exception ex)
            {
                log.Warn("SOCKS5", "accept 失败: " + ex.Message);
                continue;
            }

            if (!concurrency.Wait(0))
            {
                client.Dispose();
                stats.OnFailure();
                continue;
            }

            _ = Task.Run(async () =>
            {
                try
                {
                    await HandleClientAsync(client, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    concurrency.Release();
                }
            }, CancellationToken.None);
        }
    }

    async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        stats.OnConnection();
        stats.OnActive();
        using (client)
        {
            try
            {
                client.NoDelay = true;
                using var stream = client.GetStream();

                if (!await NegotiateAsync(stream, cancellationToken).ConfigureAwait(false)) return;

                var request = await ReadRequestAsync(stream, cancellationToken).ConfigureAwait(false);
                if (request == null) return;
                var req = request.Value;

                if (req.Command != 0x01)
                {
                    await NetUtil.WriteSocks5ReplyAsync(stream, 0x07, cancellationToken).ConfigureAwait(false);
                    stats.OnFailure();
                    log.Warn("SOCKS5", $"不支持的命令: {req.Command}");
                    return;
                }

                var host = req.HostName ?? req.Address?.ToString() ?? string.Empty;
                if (string.IsNullOrEmpty(host))
                {
                    await NetUtil.WriteSocks5ReplyAsync(stream, 0x01, cancellationToken).ConfigureAwait(false);
                    stats.OnFailure();
                    return;
                }

                if (tunnel.IsBlocked(host))
                {
                    await NetUtil.WriteSocks5ReplyAsync(stream, 0x02, cancellationToken).ConfigureAwait(false);
                    stats.OnFailure();
                    log.Info("SOCKS5", $"规则阻断: {host}");
                    return;
                }

                var excluded = rules.Current.IsExcluded(host);
                var upstream = await tunnel.ConnectAsync(host, req.Port, excluded, cancellationToken)
                    .ConfigureAwait(false);

                await NetUtil.WriteSocks5ReplyAsync(stream, 0x00, cancellationToken).ConfigureAwait(false);
                await tunnel.RunAsync(stream, upstream, host, req.Port, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // 停止服务
            }
            catch (Exception ex)
            {
                stats.OnFailure();
                log.Warn("SOCKS5", $"连接处理失败: {ex.Message}");
            }
            finally
            {
                stats.OnActiveClosed();
            }
        }
    }

    async Task<bool> NegotiateAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var header = new byte[2];
        if (!await NetUtil.ReadExactAsync(stream, header, 0, 2, cancellationToken).ConfigureAwait(false)) return false;
        if (header[0] != 0x05) return false;

        var methods = new byte[header[1]];
        if (!await NetUtil.ReadExactAsync(stream, methods, 0, methods.Length, cancellationToken).ConfigureAwait(false))
            return false;

        if (!methods.Contains((byte)0x00))
        {
            await stream.WriteAsync(new byte[] { 0x05, 0xFF }, cancellationToken).ConfigureAwait(false);
            return false;
        }

        await stream.WriteAsync(new byte[] { 0x05, 0x00 }, cancellationToken).ConfigureAwait(false);
        return true;
    }

    async Task<SocksRequest?> ReadRequestAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        if (!await NetUtil.ReadExactAsync(stream, header, 0, 4, cancellationToken).ConfigureAwait(false)) return null;
        if (header[0] != 0x05) return null;

        var (host, address) = await NetUtil.ReadSocks5AddressAsync(stream, header[3], cancellationToken)
            .ConfigureAwait(false);
        if (host == null && address == null) return null;

        var portBuffer = new byte[2];
        if (!await NetUtil.ReadExactAsync(stream, portBuffer, 0, 2, cancellationToken).ConfigureAwait(false)) return null;
        var port = (portBuffer[0] << 8) | portBuffer[1];

        return new SocksRequest(header[1], host, address, port);
    }

    public static IPAddress ParseListenAddress(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return IPAddress.Loopback;
        if (value is "*" or "any" or "0.0.0.0") return IPAddress.Any;
        return IPAddress.TryParse(value, out var ip) ? ip : IPAddress.Loopback;
    }

    public void Stop()
    {
        try
        {
            cts.Cancel();
            listener?.Stop();
        }
        catch
        {
            // ignore
        }
        listener = null;

        try
        {
            // 给活动连接一点时间收尾，避免退出时直接抛异常。
            acceptTask?.Wait(TimeSpan.FromSeconds(2));
        }
        catch
        {
            // ignore
        }
        acceptTask = null;
    }

    public void Dispose()
    {
        Stop();
        cts.Dispose();
        concurrency.Dispose();
    }

    readonly record struct SocksRequest(byte Command, string? HostName, IPAddress? Address, int Port);
}
