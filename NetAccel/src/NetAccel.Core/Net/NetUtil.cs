using System.Net;
using System.Net.Sockets;

namespace NetAccel.Core.Net;

internal static class NetUtil
{
    /// <summary>本机/内网地址不做任何加速，避免把自己或局域网设备绕进代理。</summary>
    public static bool IsLocalHost(string host)
    {
        if (string.IsNullOrEmpty(host)) return true;
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase)) return true;
        if (host.EndsWith(".local", StringComparison.OrdinalIgnoreCase)) return true;
        if (host.EndsWith(".lan", StringComparison.OrdinalIgnoreCase)) return true;

        if (!IPAddress.TryParse(host.Trim('[', ']'), out var ip)) return false;
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return ip.IsIPv6LinkLocal || ip.Equals(IPAddress.IPv6Any) ||
                   (ip.GetAddressBytes()[0] & 0xFE) == 0xFC; // fc00::/7 唯一本地地址
        }

        var bytes = ip.GetAddressBytes();
        return bytes[0] == 10 ||
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
               (bytes[0] == 192 && bytes[1] == 168) ||
               bytes[0] == 127 ||
               (bytes[0] == 169 && bytes[1] == 254);
    }

    /// <summary>分号或逗号分隔的域名白名单；空表示全部允许。</summary>
    public static bool IsDomainAllowed(string host, string? patterns)
    {
        if (string.IsNullOrWhiteSpace(patterns)) return true;
        foreach (var pattern in patterns.Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries))
        {
            if (Rules.DomainPatternMatcher.IsMatch(host, pattern.Trim())) return true;
        }
        return false;
    }

    public static async Task<bool> ReadExactAsync(
        Stream stream,
        byte[] buffer,
        int offset,
        int count,
        CancellationToken cancellationToken = default)
    {
        var total = 0;
        while (total < count)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset + total, count - total), cancellationToken)
                .ConfigureAwait(false);
            if (read <= 0) return false;
            total += read;
        }
        return true;
    }

    public static byte[] BuildSocks5Address(string host, int port)
    {
        if (IPAddress.TryParse(host, out var ip))
        {
            var address = ip.GetAddressBytes();
            var result = new byte[4 + address.Length];
            result[3] = ip.AddressFamily == AddressFamily.InterNetworkV6 ? (byte)0x04 : (byte)0x01;
            address.CopyTo(result, 4);
            result[^2] = (byte)(port >> 8);
            result[^1] = (byte)(port & 0xFF);
            return result;
        }

        var hostBytes = System.Text.Encoding.ASCII.GetBytes(host);
        if (hostBytes.Length > 255) throw new IOException("域名过长");

        var buffer = new byte[5 + hostBytes.Length];
        buffer[3] = 0x03;
        buffer[4] = (byte)hostBytes.Length;
        hostBytes.CopyTo(buffer, 5);
        buffer[^2] = (byte)(port >> 8);
        buffer[^1] = (byte)(port & 0xFF);
        return buffer;
    }

    /// <summary>解析 HTTP 代理的 host:port，支持 IPv6 方括号。</summary>
    public static bool TryParseHostPort(string value, int defaultPort, out string host, out int port)
    {
        host = string.Empty;
        port = defaultPort;
        if (string.IsNullOrWhiteSpace(value)) return false;

        value = value.Trim();
        if (value.StartsWith("[", StringComparison.Ordinal))
        {
            var end = value.IndexOf(']');
            if (end <= 1) return false;
            host = value[1..end];
            if (end + 1 < value.Length && value[end + 1] == ':')
            {
                if (!int.TryParse(value[(end + 2)..], out port)) return false;
            }
            return port is > 0 and <= 65535;
        }

        var colon = value.LastIndexOf(':');
        if (colon > 0 && value.IndexOf(':') == colon)
        {
            host = value[..colon];
            if (!int.TryParse(value[(colon + 1)..], out port)) return false;
        }
        else
        {
            host = value;
        }

        return !string.IsNullOrWhiteSpace(host) && port is > 0 and <= 65535;
    }

    /// <summary>从 SOCKS5 请求的 ATYP 字段读取地址（不含端口）。</summary>
    public static async Task<(string? Host, IPAddress? Address)> ReadSocks5AddressAsync(
        Stream stream,
        byte atyp,
        CancellationToken cancellationToken)
    {
        switch (atyp)
        {
            case 0x01:
                {
                    var buf = new byte[4];
                    if (!await ReadExactAsync(stream, buf, 0, 4, cancellationToken).ConfigureAwait(false)) return (null, null);
                    return (null, new IPAddress(buf));
                }
            case 0x03:
                {
                    var len = new byte[1];
                    if (!await ReadExactAsync(stream, len, 0, 1, cancellationToken).ConfigureAwait(false)) return (null, null);
                    if (len[0] == 0) return (null, null);
                    var buf = new byte[len[0]];
                    if (!await ReadExactAsync(stream, buf, 0, buf.Length, cancellationToken).ConfigureAwait(false)) return (null, null);
                    return (System.Text.Encoding.ASCII.GetString(buf), null);
                }
            case 0x04:
                {
                    var buf = new byte[16];
                    if (!await ReadExactAsync(stream, buf, 0, 16, cancellationToken).ConfigureAwait(false)) return (null, null);
                    return (null, new IPAddress(buf));
                }
            default:
                return (null, null);
        }
    }

    public static async Task WriteSocks5ReplyAsync(Stream stream, byte reply, CancellationToken cancellationToken)
    {
        var buffer = new byte[] { 0x05, reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
        try
        {
            await stream.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // 客户端可能已断开
        }
    }
}
