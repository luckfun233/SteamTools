using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NetAccel.Core.Net;

/// <summary>
/// 极简 SOCKS5 客户端，仅用于把流量转交给上游中继（如本地 Clash/V2Ray）。
/// </summary>
internal static class Socks5Client
{
    public static async Task ConnectAsync(
        Stream stream,
        string host,
        int port,
        string? userName,
        string? password,
        CancellationToken cancellationToken)
    {
        var hasAuth = !string.IsNullOrEmpty(userName);
        var greeting = hasAuth
            ? new byte[] { 0x05, 0x02, 0x00, 0x02 }
            : new byte[] { 0x05, 0x01, 0x00 };

        await stream.WriteAsync(greeting, cancellationToken).ConfigureAwait(false);

        var response = new byte[2];
        if (!await NetUtil.ReadExactAsync(stream, response, 0, 2, cancellationToken).ConfigureAwait(false))
            throw new IOException("上游 SOCKS5 无响应");

        if (response[0] != 0x05 || response[1] == 0xFF)
            throw new IOException("上游 SOCKS5 拒绝认证方式");

        if (response[1] == 0x02)
        {
            var user = Encoding.UTF8.GetBytes(userName ?? string.Empty);
            var pass = Encoding.UTF8.GetBytes(password ?? string.Empty);
            if (user.Length > 255 || pass.Length > 255)
                throw new IOException("上游 SOCKS5 用户名或密码过长");

            var auth = new byte[3 + user.Length + pass.Length];
            auth[0] = 0x01;
            auth[1] = (byte)user.Length;
            user.CopyTo(auth, 2);
            auth[2 + user.Length] = (byte)pass.Length;
            pass.CopyTo(auth, 3 + user.Length);
            await stream.WriteAsync(auth, cancellationToken).ConfigureAwait(false);

            var authResponse = new byte[2];
            if (!await NetUtil.ReadExactAsync(stream, authResponse, 0, 2, cancellationToken).ConfigureAwait(false) ||
                authResponse[0] != 0x01 || authResponse[1] != 0x00)
            {
                throw new IOException("上游 SOCKS5 认证失败");
            }
        }

        var address = NetUtil.BuildSocks5Address(host, port);
        var request = new byte[3 + address.Length];
        request[0] = 0x05;
        request[1] = 0x01;
        request[2] = 0x00;
        address.CopyTo(request, 3);
        await stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);

        var header = new byte[4];
        if (!await NetUtil.ReadExactAsync(stream, header, 0, 4, cancellationToken).ConfigureAwait(false))
            throw new IOException("上游 SOCKS5 响应为空");
        if (header[0] != 0x05 || header[1] != 0x00)
            throw new IOException($"上游 SOCKS5 连接失败: {header[1]}");

        var length = header[3] switch
        {
            0x01 => 4,
            0x04 => 16,
            0x03 => await ReadOneByteAsync(stream, cancellationToken).ConfigureAwait(false),
            _ => 0,
        };

        var rest = new byte[length + 2];
        if (rest.Length > 0 &&
            !await NetUtil.ReadExactAsync(stream, rest, 0, rest.Length, cancellationToken).ConfigureAwait(false))
        {
            throw new IOException("上游 SOCKS5 响应不完整");
        }
    }

    static async Task<int> ReadOneByteAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[1];
        return await NetUtil.ReadExactAsync(stream, buffer, 0, 1, cancellationToken).ConfigureAwait(false)
            ? buffer[0]
            : 0;
    }
}
