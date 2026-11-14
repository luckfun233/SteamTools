using System.Net;
using System.Net.Sockets;
using System.Text;
using NetAccel.Core.Logging;
using NetAccel.Core.Models;
using NetAccel.Core.Rules;
using NetAccel.Core.Stats;

namespace NetAccel.Core.Net;

/// <summary>
/// 本地 HTTP 代理。支持 CONNECT 隧道（HTTPS）与普通 HTTP 绝对地址转发，
/// 并额外提供 /pac 端点，方便浏览器或系统使用 PAC。
/// </summary>
public sealed class HttpProxyServer : IDisposable
{
    const int MaxConcurrentConnections = 512;
    const int MaxHeaderBytes = 64 * 1024;

    readonly AccelSettings settings;
    readonly RuleEngine rules;
    readonly TunnelSession tunnel;
    readonly ProxyStats stats;
    readonly IAccelLogger log;

    readonly CancellationTokenSource cts = new();
    readonly SemaphoreSlim concurrency = new(MaxConcurrentConnections);
    TcpListener? listener;
    Task? acceptTask;

    public HttpProxyServer(
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
        var address = Socks5Server.ParseListenAddress(settings.ListenAddress);
        listener = new TcpListener(address, settings.HttpPort);
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        acceptTask = Task.Run(() => AcceptLoopAsync(cts.Token));
        log.Info("HTTP", $"已监听 {address}:{Port}");
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
                log.Warn("HTTP", "accept 失败: " + ex.Message);
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

                var header = await ReadHeaderBlockAsync(stream, cancellationToken).ConfigureAwait(false);
                if (header == null) return;

                var lines = header.Split("\r\n", StringSplitOptions.None);
                if (lines.Length == 0) return;

                var requestLine = lines[0].Split(' ');
                if (requestLine.Length < 3) return;

                var method = requestLine[0];
                var target = requestLine[1];

                if (method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
                {
                    await HandleConnectAsync(stream, target, cancellationToken).ConfigureAwait(false);
                    return;
                }

                await HandlePlainHttpAsync(stream, method, target, lines, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // 停止服务
            }
            catch (Exception ex)
            {
                stats.OnFailure();
                log.Warn("HTTP", $"请求处理失败: {ex.Message}");
            }
            finally
            {
                stats.OnActiveClosed();
            }
        }
    }

    async Task HandleConnectAsync(NetworkStream stream, string target, CancellationToken cancellationToken)
    {
        if (!NetUtil.TryParseHostPort(target, 443, out var host, out var port))
        {
            await WriteResponseAsync(stream, 400, "Bad Request", "目标地址无效", cancellationToken).ConfigureAwait(false);
            stats.OnFailure();
            return;
        }

        if (tunnel.IsBlocked(host))
        {
            await WriteResponseAsync(stream, 403, "Forbidden", "规则已阻断该域名", cancellationToken).ConfigureAwait(false);
            stats.OnFailure();
            return;
        }

        var excluded = rules.Current.IsExcluded(host);
        UpstreamConnection upstream;
        try
        {
            upstream = await tunnel.ConnectAsync(host, port, excluded, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            stats.OnFailure();
            log.Warn("HTTP", $"CONNECT {host}:{port} 失败: {ex.Message}");
            await WriteResponseAsync(stream, 502, "Bad Gateway", "无法连接目标", cancellationToken).ConfigureAwait(false);
            return;
        }

        var ok = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
        await stream.WriteAsync(ok, cancellationToken).ConfigureAwait(false);

        await tunnel.RunAsync(stream, upstream, host, port, cancellationToken).ConfigureAwait(false);
    }

    async Task HandlePlainHttpAsync(
        NetworkStream stream,
        string method,
        string target,
        string[] headerLines,
        CancellationToken cancellationToken)
    {
        // 只处理源站形式的 /pac，避免把远端 http://host/pac 误判成本地 PAC。
        if (target.StartsWith("/pac", StringComparison.OrdinalIgnoreCase))
        {
            var pac = BuildPac(settings.HttpPort, settings.Socks5Port);
            await WriteResponseAsync(stream, 200, "OK", pac, cancellationToken, "application/x-ns-proxy-autoconfig")
                .ConfigureAwait(false);
            return;
        }

        if (!Uri.TryCreate(target, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttp)
        {
            await WriteResponseAsync(stream, 400, "Bad Request",
                "普通 HTTP 转发只支持 http:// 绝对地址；HTTPS 请使用 CONNECT。", cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        var host = uri.Host;
        var port = uri.Port;

        if (tunnel.IsBlocked(host))
        {
            await WriteResponseAsync(stream, 403, "Forbidden", "规则已阻断该域名", cancellationToken).ConfigureAwait(false);
            return;
        }

        UpstreamConnection upstream;
        try
        {
            upstream = await tunnel.ConnectAsync(host, port, rules.Current.IsExcluded(host), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            stats.OnFailure();
            log.Warn("HTTP", $"转发 {host}:{port} 失败: {ex.Message}");
            await WriteResponseAsync(stream, 502, "Bad Gateway", "无法连接目标", cancellationToken).ConfigureAwait(false);
            return;
        }

        using (upstream.Client)
        {
            var upstreamStream = upstream.Stream;

            var requestBuilder = new StringBuilder();
            requestBuilder.Append(method).Append(' ').Append(uri.PathAndQuery).Append(" HTTP/1.1\r\n");

            long contentLength = 0;
            var hasContentLength = false;
            var chunked = false;

            for (var i = 1; i < headerLines.Length; i++)
            {
                var line = headerLines[i];
                if (line.Length == 0) continue;
                var colon = line.IndexOf(':');
                if (colon <= 0) continue;

                var name = line[..colon].Trim();
                var value = line[(colon + 1)..].Trim();

                if (name.Equals("Proxy-Connection", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("Connection", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("Keep-Alive", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) &&
                    long.TryParse(value, out var parsedLength))
                {
                    contentLength = parsedLength;
                    hasContentLength = true;
                }
                else if (name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase) &&
                         value.Contains("chunked", StringComparison.OrdinalIgnoreCase))
                {
                    chunked = true;
                }

                requestBuilder.Append(name).Append(": ").Append(value).Append("\r\n");
            }

            requestBuilder.Append("Connection: close\r\n\r\n");
            var requestBytes = Encoding.UTF8.GetBytes(requestBuilder.ToString());
            await upstreamStream.WriteAsync(requestBytes, cancellationToken).ConfigureAwait(false);
            stats.OnBytesUp(requestBytes.Length);

            if (hasContentLength && contentLength > 0)
            {
                await CopyExactAsync(stream, upstreamStream, contentLength, cancellationToken).ConfigureAwait(false);
            }
            else if (chunked)
            {
                await CopyChunkedBodyAsync(stream, upstreamStream, cancellationToken).ConfigureAwait(false);
            }

            var buffer = new byte[32 * 1024];
            while (!cancellationToken.IsCancellationRequested)
            {
                var read = await upstreamStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read <= 0) break;
                await stream.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                stats.OnBytesDown(read);
            }
        }
    }

    async Task CopyExactAsync(NetworkStream from, NetworkStream to, long count, CancellationToken cancellationToken)
    {
        var buffer = new byte[32 * 1024];
        var remaining = count;
        while (remaining > 0)
        {
            var want = (int)Math.Min(buffer.Length, remaining);
            var read = await from.ReadAsync(buffer.AsMemory(0, want), cancellationToken).ConfigureAwait(false);
            if (read <= 0) return;
            await to.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            stats.OnBytesUp(read);
            remaining -= read;
        }
    }

    async Task CopyChunkedBodyAsync(NetworkStream from, NetworkStream to, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var sizeLine = await ReadLineAsync(from, cancellationToken).ConfigureAwait(false);
            if (sizeLine == null) return;

            await to.WriteAsync(Encoding.ASCII.GetBytes(sizeLine + "\r\n"), cancellationToken).ConfigureAwait(false);
            var semicolon = sizeLine.IndexOf(';');
            var hex = semicolon >= 0 ? sizeLine[..semicolon] : sizeLine;
            if (!int.TryParse(hex.Trim(), System.Globalization.NumberStyles.HexNumber, null, out var size))
            {
                return;
            }

            if (size == 0)
            {
                // 读取可能的 trailers 直到空行
                while (true)
                {
                    var trailer = await ReadLineAsync(from, cancellationToken).ConfigureAwait(false);
                    if (string.IsNullOrEmpty(trailer)) break;
                    await to.WriteAsync(Encoding.ASCII.GetBytes(trailer + "\r\n"), cancellationToken).ConfigureAwait(false);
                }
                await to.WriteAsync(new byte[] { 0x0D, 0x0A }, cancellationToken).ConfigureAwait(false);
                return;
            }

            var buffer = new byte[Math.Min(size, 32 * 1024)];
            var remaining = size;
            while (remaining > 0)
            {
                var read = await from.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, remaining)), cancellationToken)
                    .ConfigureAwait(false);
                if (read <= 0) return;
                await to.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                stats.OnBytesUp(read);
                remaining -= read;
            }

            // 块尾的 CRLF
            var tail = new byte[2];
            if (!await NetUtil.ReadExactAsync(from, tail, 0, 2, cancellationToken).ConfigureAwait(false)) return;
            await to.WriteAsync(tail, cancellationToken).ConfigureAwait(false);
        }
    }

    static async Task<string?> ReadLineAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var buffer = new List<byte>(64);
        var one = new byte[1];
        while (buffer.Count < 8192)
        {
            if (!await NetUtil.ReadExactAsync(stream, one, 0, 1, cancellationToken).ConfigureAwait(false)) return null;
            if (one[0] == (byte)'\n')
            {
                if (buffer.Count > 0 && buffer[^1] == (byte)'\r') buffer.RemoveAt(buffer.Count - 1);
                return Encoding.ASCII.GetString(buffer.ToArray());
            }
            buffer.Add(one[0]);
        }
        return null;
    }

    async Task<string?> ReadHeaderBlockAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var buffer = new List<byte>(1024);
        var one = new byte[1];

        // 逐字节读取到 \r\n\r\n，避免把请求体一起读进缓冲区。
        while (buffer.Count < MaxHeaderBytes)
        {
            var read = await stream.ReadAsync(one.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
            if (read <= 0) return null;
            buffer.Add(one[0]);

            if (buffer.Count >= 4 &&
                buffer[^4] == (byte)'\r' &&
                buffer[^3] == (byte)'\n' &&
                buffer[^2] == (byte)'\r' &&
                buffer[^1] == (byte)'\n')
            {
                return Encoding.UTF8.GetString(buffer.ToArray(), 0, buffer.Count - 4);
            }
        }

        return null;
    }

    static async Task WriteResponseAsync(
        NetworkStream stream,
        int statusCode,
        string reason,
        string body,
        CancellationToken cancellationToken,
        string contentType = "text/plain; charset=utf-8")
    {
        var bodyBytes = Encoding.UTF8.GetBytes(body);
        var header = $"HTTP/1.1 {statusCode} {reason}\r\n" +
                     $"Content-Type: {contentType}\r\n" +
                     $"Content-Length: {bodyBytes.Length}\r\n" +
                     "Connection: close\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(header), cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(bodyBytes, cancellationToken).ConfigureAwait(false);
    }

    static string BuildPac(int httpPort, int socksPort)
        => "function FindProxyForURL(url, host) {\n" +
           "  if (isPlainHostName(host) || shExpMatch(host, \"*.local\")) return \"DIRECT\";\n" +
           $"  return \"PROXY 127.0.0.1:{httpPort}; SOCKS5 127.0.0.1:{socksPort}\";\n" +
           "}";

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
}
