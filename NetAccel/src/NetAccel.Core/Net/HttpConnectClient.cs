using System.Net.Sockets;
using System.Text;

namespace NetAccel.Core.Net;

/// <summary>
/// 最小 HTTP CONNECT 客户端，用于把流量交给公司代理 / 沙箱出口等 HTTP 代理。
/// 只读取响应头，不会多读隧道内的数据。
/// </summary>
internal static class HttpConnectClient
{
    const int MaxHeaderBytes = 16 * 1024;

    public static async Task ConnectAsync(
        Stream stream,
        string host,
        int port,
        string? userName,
        string? password,
        CancellationToken cancellationToken)
    {
        var target = host.Contains(':', StringComparison.Ordinal) && !host.StartsWith("[", StringComparison.Ordinal)
            ? $"[{host}]:{port}"
            : $"{host}:{port}";

        var builder = new StringBuilder();
        builder.Append("CONNECT ").Append(target).Append(" HTTP/1.1\r\n");
        builder.Append("Host: ").Append(target).Append("\r\n");
        builder.Append("Proxy-Connection: keep-alive\r\n");

        if (!string.IsNullOrEmpty(userName))
        {
            var credential = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{userName}:{password ?? string.Empty}"));
            builder.Append("Proxy-Authorization: Basic ").Append(credential).Append("\r\n");
        }
        builder.Append("\r\n");

        await stream.WriteAsync(Encoding.ASCII.GetBytes(builder.ToString()), cancellationToken).ConfigureAwait(false);

        var header = await ReadHeaderBlockAsync(stream, cancellationToken).ConfigureAwait(false)
                     ?? throw new IOException("HTTP 中继没有返回响应头");

        var firstLine = header.Split("\r\n", 2, StringSplitOptions.None)[0];
        var parts = firstLine.Split(' ', 3);
        if (parts.Length < 2 || !int.TryParse(parts[1], out var status) || status != 200)
        {
            throw new IOException($"HTTP 中继拒绝 CONNECT: {firstLine}");
        }
    }

    static async Task<string?> ReadHeaderBlockAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new List<byte>(256);
        var one = new byte[1];
        while (buffer.Count < MaxHeaderBytes)
        {
            if (!await NetUtil.ReadExactAsync(stream, one, 0, 1, cancellationToken).ConfigureAwait(false)) return null;
            buffer.Add(one[0]);

            if (buffer.Count >= 4 &&
                buffer[^4] == (byte)'\r' && buffer[^3] == (byte)'\n' &&
                buffer[^2] == (byte)'\r' && buffer[^1] == (byte)'\n')
            {
                return Encoding.ASCII.GetString(buffer.ToArray(), 0, buffer.Count - 4);
            }
        }
        return null;
    }
}
