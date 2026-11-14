using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using NetAccel.Core.Net;

namespace NetAccel.Core.Lab;

public sealed record ProbeResult(bool Success, long ElapsedMs, string? Error, string? TlsVersion)
{
    public override string ToString()
        => Success
            ? $"成功 ({ElapsedMs}ms{(string.IsNullOrEmpty(TlsVersion) ? string.Empty : " " + TlsVersion)})"
            : $"失败 ({ElapsedMs}ms): {Error}";
}

/// <summary>
/// TLS 连通性探测：直连，或经由本地 SOCKS5 代理（会走完整的分片/改写/DoH 路径）。
/// 只验证“当前网络 + 当前设置”下握手是否成功，不能证明某个 DPI 设备一定被绕过。
/// </summary>
public static class SniConnectivityTester
{
    public static async Task<ProbeResult> ProbeDirectAsync(
        string host,
        int port,
        int timeoutSeconds,
        CancellationToken cancellationToken)
    {
        using var client = new TcpClient();
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = CreateTimeout(cancellationToken, timeoutSeconds);
            await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            return await HandshakeAsync(client.GetStream(), host, sw, cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return new ProbeResult(false, sw.ElapsedMilliseconds, Describe(ex), null);
        }
    }

    public static async Task<ProbeResult> ProbeViaSocks5Async(
        string host,
        int port,
        int socksPort,
        int timeoutSeconds,
        CancellationToken cancellationToken)
    {
        using var client = new TcpClient();
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = CreateTimeout(cancellationToken, timeoutSeconds);
            await client.ConnectAsync(IPAddress.Loopback, socksPort, cts.Token).ConfigureAwait(false);
            var stream = client.GetStream();

            if (!await SocksConnectAsync(stream, host, port, cts.Token).ConfigureAwait(false))
            {
                return new ProbeResult(false, sw.ElapsedMilliseconds, "SOCKS5 连接被拒绝", null);
            }

            return await HandshakeAsync(stream, host, sw, cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return new ProbeResult(false, sw.ElapsedMilliseconds, Describe(ex), null);
        }
    }

    static async Task<ProbeResult> HandshakeAsync(
        NetworkStream stream,
        string host,
        Stopwatch sw,
        CancellationToken cancellationToken)
    {
        using var ssl = new SslStream(stream, leaveInnerStreamOpen: true, (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = host,
            EnabledSslProtocols = SslProtocols.None,
        }, cancellationToken).ConfigureAwait(false);

        return new ProbeResult(true, sw.ElapsedMilliseconds, null, ssl.SslProtocol.ToString());
    }

    static async Task<bool> SocksConnectAsync(
        NetworkStream stream,
        string host,
        int port,
        CancellationToken cancellationToken)
    {
        await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, cancellationToken).ConfigureAwait(false);

        var greeting = new byte[2];
        if (!await ReadExactAsync(stream, greeting, cancellationToken).ConfigureAwait(false)) return false;
        if (greeting[0] != 0x05 || greeting[1] != 0x00) return false;

        var address = NetUtil.BuildSocks5Address(host, port);
        var request = new byte[3 + address.Length];
        request[0] = 0x05;
        request[1] = 0x01;
        request[2] = 0x00;
        address.CopyTo(request, 3);
        await stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);

        var reply = new byte[4];
        if (!await ReadExactAsync(stream, reply, cancellationToken).ConfigureAwait(false)) return false;
        if (reply[0] != 0x05 || reply[1] != 0x00) return false;

        var length = reply[3] switch
        {
            0x01 => 4,
            0x04 => 16,
            0x03 => await ReadOneByteAsync(stream, cancellationToken).ConfigureAwait(false),
            _ => 0,
        };

        var tail = new byte[length + 2];
        return tail.Length == 0 ||
               await ReadExactAsync(stream, tail, cancellationToken).ConfigureAwait(false);
    }

    static async Task<int> ReadOneByteAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[1];
        return await ReadExactAsync(stream, buffer, cancellationToken).ConfigureAwait(false) ? buffer[0] : 0;
    }

    static async Task<bool> ReadExactAsync(
        NetworkStream stream,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total), cancellationToken)
                .ConfigureAwait(false);
            if (read <= 0) return false;
            total += read;
        }
        return true;
    }

    static CancellationTokenSource CreateTimeout(CancellationToken cancellationToken, int seconds)
    {
        var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(seconds, 2, 30)));
        return cts;
    }

    static string Describe(Exception ex)
    {
        if (ex is OperationCanceledException) return "超时/已取消";
        if (ex is SocketException socket) return $"网络错误 {socket.SocketErrorCode}";
        if (ex is AuthenticationException) return "TLS 认证失败";
        if (ex is IOException io && io.InnerException is SocketException inner) return $"网络错误 {inner.SocketErrorCode}";
        return ex.Message;
    }
}
