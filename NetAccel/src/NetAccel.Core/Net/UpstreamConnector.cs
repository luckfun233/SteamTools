using System.Net;
using System.Net.Sockets;
using NetAccel.Core.Logging;
using NetAccel.Core.Models;
using NetAccel.Core.Rules;
using NetAccel.Core.Stats;
using NetAccel.Core.Tls;

namespace NetAccel.Core.Net;

public sealed record UpstreamConnection(TcpClient Client, bool Relayed, string? ResolvedIp)
{
    public NetworkStream Stream => Client.GetStream();
}

/// <summary>
/// 负责把目标域名变成一条可用的上游 TCP 连接：
/// 预置 IP → DoH → 系统 DNS，或按域名走上游 SOCKS5 中继。
/// </summary>
public sealed class UpstreamConnector
{
    readonly AccelSettings settings;
    readonly RuleEngine rules;
    readonly DohResolver doh;
    readonly PresetIpSelector presetSelector;
    readonly IAccelLogger log;
    readonly ProxyStats stats;

    static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(10);
    static readonly TimeSpan ProbeTimeout = TimeSpan.FromMilliseconds(800);

    public UpstreamConnector(
        AccelSettings settings,
        RuleEngine rules,
        DohResolver doh,
        PresetIpSelector presetSelector,
        IAccelLogger logger,
        ProxyStats stats)
    {
        this.settings = settings;
        this.rules = rules;
        this.doh = doh;
        this.presetSelector = presetSelector;
        log = logger;
        this.stats = stats;
    }

    public async Task<UpstreamConnection> ConnectAsync(
        string host,
        int port,
        bool excluded,
        CancellationToken cancellationToken)
    {
        // 本机/内网默认直连；关闭 BypassLocalhost 时也允许本机流量走分片/中继，便于自测。
        if (excluded || (settings.BypassLocalhost && NetUtil.IsLocalHost(host)))
        {
            var direct = await ConnectTcpAsync(host, port, cancellationToken).ConfigureAwait(false);
            return new UpstreamConnection(direct, false, null);
        }

        if (settings.EnableUpstreamRelay && !excluded &&
            NetUtil.IsDomainAllowed(host, settings.RelayDomains))
        {
            var relay = await ConnectViaRelayAsync(host, port, cancellationToken).ConfigureAwait(false);
            stats.OnRelay();
            log.Info("Relay", $"经中继 {settings.RelayHost}:{settings.RelayPort} -> {host}:{port}");
            return new UpstreamConnection(relay, true, null);
        }

        var presetIps = rules.Current.GetPresetIps(host);
        if (!excluded && presetIps.Count > 0)
        {
            var selected = await presetSelector.PickAsync(presetIps, port, ProbeTimeout, cancellationToken)
                .ConfigureAwait(false);
            if (selected != null)
            {
                try
                {
                    var client = await ConnectTcpAsync(selected.ToString(), port, cancellationToken).ConfigureAwait(false);
                    stats.OnPresetIp();
                    log.Info("Upstream", $"预置 IP: {host} -> {selected}:{port}");
                    return new UpstreamConnection(client, false, selected.ToString());
                }
                catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
                {
                    log.Warn("Upstream", $"预置 IP 连接失败 {selected}: {ex.Message}");
                }
            }
        }

        if (settings.EnableDoh && !excluded)
        {
            var addresses = await doh.ResolveAsync(host, cancellationToken).ConfigureAwait(false);
            if (addresses.Count > 0)
            {
                IPAddress? best = addresses[0];
                if (addresses.Count > 1)
                {
                    var candidates = addresses
                        .Where(x => x.AddressFamily == AddressFamily.InterNetwork)
                        .Select(x => x.ToString())
                        .ToArray();
                    if (candidates.Length > 0)
                    {
                        var picked = await presetSelector.PickAsync(candidates, port, ProbeTimeout, cancellationToken)
                            .ConfigureAwait(false);
                        if (picked != null) best = picked;
                    }
                }

                try
                {
                    var client = await ConnectTcpAsync(best.ToString(), port, cancellationToken).ConfigureAwait(false);
                    return new UpstreamConnection(client, false, best.ToString());
                }
                catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
                {
                    log.Warn("Upstream", $"DoH IP 连接失败 {best}: {ex.Message}");
                }
            }
            else if (!settings.DohFallbackToSystem)
            {
                throw new IOException($"DoH 解析失败且未允许回退系统 DNS: {host}");
            }
        }

        var directClient = await ConnectTcpAsync(host, port, cancellationToken).ConfigureAwait(false);
        return new UpstreamConnection(directClient, false, null);
    }

    async Task<TcpClient> ConnectTcpAsync(string host, int port, CancellationToken cancellationToken)
    {
        var client = new TcpClient { NoDelay = true };
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(ConnectTimeout);
            await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            client.NoDelay = true;
            return client;
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    async Task<TcpClient> ConnectViaRelayAsync(string host, int port, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(settings.RelayHost) || settings.RelayPort is <= 0 or > 65535)
        {
            throw new InvalidOperationException("上游中继地址无效");
        }

        var relay = new TcpClient { NoDelay = true };
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(ConnectTimeout);
            await relay.ConnectAsync(settings.RelayHost, settings.RelayPort, cts.Token).ConfigureAwait(false);
            relay.NoDelay = true;

            if (settings.RelayType == RelayType.Http)
            {
                await HttpConnectClient.ConnectAsync(
                    relay.GetStream(),
                    host,
                    port,
                    settings.RelayUserName,
                    settings.RelayPassword,
                    cts.Token).ConfigureAwait(false);
            }
            else
            {
                await Socks5Client.ConnectAsync(
                    relay.GetStream(),
                    host,
                    port,
                    settings.RelayUserName,
                    settings.RelayPassword,
                    cts.Token).ConfigureAwait(false);
            }
            return relay;
        }
        catch
        {
            relay.Dispose();
            throw;
        }
    }
}
