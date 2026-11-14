using System.Text;
using NetAccel.Core.Tls;
using Xunit;

namespace NetAccel.Core.Tests;

public class TlsClientHelloTests
{
    [Fact]
    public void Parses_Sni()
    {
        var hello = BuildClientHello("api.github.com");
        Assert.True(TlsClientHello.TryGetSni(hello, out var sni));
        Assert.Equal("api.github.com", sni);
    }

    [Fact]
    public void Rewrites_To_Longer_Name()
    {
        var hello = BuildClientHello("api.github.com");
        Assert.True(TlsClientHello.TryRewriteSni(hello, "release-assets.githubusercontent.com", out var rewritten));
        Assert.True(TlsClientHello.TryGetSni(rewritten, out var sni));
        Assert.Equal("release-assets.githubusercontent.com", sni);
        Assert.True(rewritten.Length > hello.Length);
    }

    [Fact]
    public void Rewrites_To_Shorter_Name()
    {
        var hello = BuildClientHello("raw.githubusercontent.com");
        Assert.True(TlsClientHello.TryRewriteSni(hello, "baidu.com", out var rewritten));
        Assert.True(TlsClientHello.TryGetSni(rewritten, out var sni));
        Assert.Equal("baidu.com", sni);
        Assert.True(rewritten.Length < hello.Length);
    }

    [Fact]
    public void Removes_Sni()
    {
        var hello = BuildClientHello("github.com");
        Assert.True(TlsClientHello.TryRemoveSni(hello, out var rewritten));
        Assert.False(TlsClientHello.TryGetSni(rewritten, out _));
        Assert.Equal(hello.Length - (4 + 2 + 1 + 2 + "github.com".Length), rewritten.Length);
    }

    [Fact]
    public void Sni_Boundary_Fragment_Never_Contains_Full_Host()
    {
        const string host = "api.github.com";
        var hello = BuildClientHello(host);
        var chunks = TlsClientHello.FragmentBySni(hello);

        Assert.True(chunks.Count >= 3);
        Assert.Equal(hello, chunks.SelectMany(x => x).ToArray());
        foreach (var chunk in chunks)
        {
            Assert.DoesNotContain(host, Encoding.ASCII.GetString(chunk));
        }
    }

    [Fact]
    public void Sni_Pieces_Fragment_Reassembles()
    {
        const string host = "raw.githubusercontent.com";
        var hello = BuildClientHello(host);
        var chunks = TlsClientHello.FragmentBySniPieces(hello, 4);

        Assert.True(chunks.Count >= 5);
        Assert.Equal(hello, chunks.SelectMany(x => x).ToArray());
        Assert.NotEmpty(chunks);
    }

    [Fact]
    public void Tls_Record_Split_Produces_Multiple_Records()
    {
        var hello = BuildClientHello("api.github.com");
        var chunks = TlsClientHello.FragmentToTlsRecords(hello);

        Assert.True(chunks.Count >= 3);
        foreach (var chunk in chunks)
        {
            Assert.Equal(0x16, chunk[0]);
            Assert.True(chunk.Length >= 5);
        }

        // 负载重新拼接后应与原 record payload 一致（或包含后续 record）。
        var originalPayload = hello[5..];
        var reconstructed = chunks.SelectMany(x => x.Skip(5).ToArray()).ToArray();
        Assert.Equal(originalPayload.Length, reconstructed.Length);
    }

    [Fact]
    public void Random_Fragment_Reassembles()
    {
        var hello = BuildClientHello("huggingface.co");
        var chunks = TlsClientHello.FragmentRandom(hello, 16, new Random(1234));

        Assert.True(chunks.Count > 1);
        Assert.Equal(hello, chunks.SelectMany(x => x).ToArray());
    }

    [Fact]
    public void Invalid_Data_Does_Not_Throw()
    {
        Assert.False(TlsClientHello.TryGetSni(Array.Empty<byte>(), out _));
        Assert.False(TlsClientHello.TryGetSni(new byte[] { 0x16 }, out _));
        Assert.False(TlsClientHello.TryRewriteSni(new byte[] { 0x16, 0x03, 0x01, 0, 0 }, "a.com", out _));
        Assert.Empty(TlsClientHello.Fragment(Array.Empty<byte>(), TlsFragmentStrategy.SniBoundary, 16, 3));
    }

    [Fact]
    public void Fragment_Strategy_Matrix_Reassembles()
    {
        var hello = BuildClientHello("api.github.com");
        foreach (var strategy in Enum.GetValues<TlsFragmentStrategy>())
        {
            var chunks = TlsClientHello.Fragment(hello, strategy, 32, 3, new Random(7));
            Assert.NotEmpty(chunks);
            // TLS record 重封装策略会改写 record 头，不能简单按字节比较。
            if (strategy != TlsFragmentStrategy.TlsRecordSplit)
            {
                Assert.Equal(hello, chunks.SelectMany(x => x).ToArray());
            }
        }
    }

    /// <summary>构造一个最小但结构完整的 TLS 1.2/1.3 风格 ClientHello。</summary>
    internal static byte[] BuildClientHello(string host)
    {
        var hostBytes = Encoding.ASCII.GetBytes(host);

        // SNI extension: list length(2) + type(1) + name length(2) + name
        var sniExtDataLength = 2 + 1 + 2 + hostBytes.Length;
        var sniExt = new List<byte>();
        sniExt.AddRange(new byte[] { 0x00, 0x00 }); // extension type
        sniExt.AddRange(BigEndian((ushort)(sniExtDataLength))); // extension length
        sniExt.AddRange(BigEndian((ushort)(1 + 2 + hostBytes.Length))); // server_name_list length
        sniExt.Add(0x00); // host_name
        sniExt.AddRange(BigEndian((ushort)hostBytes.Length));
        sniExt.AddRange(hostBytes);

        var handshakeBody = new List<byte>();
        handshakeBody.AddRange(new byte[] { 0x03, 0x03 }); // client version
        handshakeBody.AddRange(new byte[32]); // random
        handshakeBody.Add(0x00); // session id length
        handshakeBody.AddRange(BigEndian(2)); // cipher suites length
        handshakeBody.AddRange(new byte[] { 0x13, 0x01 }); // TLS_AES_128_GCM_SHA256
        handshakeBody.Add(0x01); // compression methods length
        handshakeBody.Add(0x00); // null compression
        handshakeBody.AddRange(BigEndian((ushort)sniExt.Count)); // extensions length
        handshakeBody.AddRange(sniExt);

        var handshakeLength = handshakeBody.Count;
        var recordPayload = new List<byte>
        {
            0x01, // ClientHello
            (byte)((handshakeLength >> 16) & 0xFF),
            (byte)((handshakeLength >> 8) & 0xFF),
            (byte)(handshakeLength & 0xFF),
        };
        recordPayload.AddRange(handshakeBody);

        var record = new List<byte>
        {
            0x16, // handshake
            0x03, 0x01, // record version
            (byte)((recordPayload.Count >> 8) & 0xFF),
            (byte)(recordPayload.Count & 0xFF),
        };
        record.AddRange(recordPayload);
        return record.ToArray();
    }

    static byte[] BigEndian(ushort value) => new[] { (byte)(value >> 8), (byte)(value & 0xFF) };
}
