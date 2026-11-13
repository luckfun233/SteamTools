using NUnit.Framework;
using System.Application.Services.Implementation;
using System.Linq;
using System.Text;

namespace System.Application;

[TestFixture]
public class TlsClientHelloTest
{
    [Test]
    public void Parse_Rewrite_Remove_Sni()
    {
        var hello = CreateClientHello("github.com");

        Assert.That(TlsClientHello.TryGetSni(hello, out var sni), Is.True);
        Assert.That(sni, Is.EqualTo("github.com"));

        Assert.That(TlsClientHello.TryRewriteSni(hello, "huggingface.cn", out var longer), Is.True);
        Assert.That(longer.Length, Is.GreaterThan(hello.Length));
        Assert.That(TlsClientHello.TryGetSni(longer, out var longerSni), Is.True);
        Assert.That(longerSni, Is.EqualTo("huggingface.cn"));
        Assert.That(TlsClientHello.TryGetRecordLength(longer, out var recordLength), Is.True);
        Assert.That(recordLength, Is.EqualTo(longer.Length));

        Assert.That(TlsClientHello.TryRewriteSni(hello, "a.b", out var shorter), Is.True);
        Assert.That(shorter.Length, Is.LessThan(hello.Length));
        Assert.That(TlsClientHello.TryGetSni(shorter, out var shorterSni), Is.True);
        Assert.That(shorterSni, Is.EqualTo("a.b"));

        Assert.That(TlsClientHello.TryRemoveSni(hello, out var removed), Is.True);
        Assert.That(TlsClientHello.TryGetSni(removed, out _), Is.False);
        Assert.That(TlsClientHello.TryGetRecordLength(removed, out var removedLength), Is.True);
        Assert.That(removedLength, Is.EqualTo(removed.Length));
    }

    [Test]
    public void Fragment_Strategies_Reassemble_Exactly()
    {
        var hello = CreateClientHello("raw.githubusercontent.com", 3000);

        var fixedChunks = TlsClientHello.Fragment(hello, 64);
        Assert.That(Join(fixedChunks), Is.EqualTo(hello));

        var sniChunks = TlsClientHello.FragmentBySni(hello);
        Assert.That(sniChunks.Count, Is.EqualTo(3));
        Assert.That(Join(sniChunks), Is.EqualTo(hello));
        foreach (var chunk in sniChunks)
        {
            Assert.That(Encoding.ASCII.GetString(chunk).Contains("raw.githubusercontent.com", StringComparison.Ordinal), Is.False);
        }

        var recordChunks = TlsClientHello.FragmentByRecord(hello);
        Assert.That(Join(recordChunks), Is.EqualTo(hello));
    }

    [Test]
    public void SniPieces_Reassemble_And_Hide_Host()
    {
        var hello = CreateClientHello("github.com", 200);
        var chunks = TlsClientHello.FragmentBySniPieces(hello, 4);

        Assert.That(chunks, Has.Count.EqualTo(5));
        Assert.That(Join(chunks), Is.EqualTo(hello));
        foreach (var chunk in chunks)
        {
            Assert.That(Encoding.ASCII.GetString(chunk).Contains("github.com", StringComparison.Ordinal), Is.False);
        }
    }

    [Test]
    public void TlsRecordSplit_Produces_Valid_Records()
    {
        var hello = CreateClientHello("github.com", 200);
        var records = TlsClientHello.FragmentToTlsRecords(hello);

        Assert.That(records.Count, Is.GreaterThan(1));
        foreach (var record in records)
        {
            Assert.That(record[0], Is.EqualTo(0x16));
            var length = (record[3] << 8) | record[4];
            Assert.That(length, Is.EqualTo(record.Length - 5));
            Assert.That(Encoding.ASCII.GetString(record).Contains("github.com", StringComparison.Ordinal), Is.False);
        }

        var payloads = records.Select(x => x.Skip(5).ToArray()).ToArray();
        Assert.That(Join(payloads), Is.EqualTo(hello.Skip(5).ToArray()));

        var fixedRecords = TlsClientHello.FragmentToTlsRecordsFixed(hello, 64);
        var fixedPayloads = fixedRecords.Select(x => x.Skip(5).ToArray()).ToArray();
        Assert.That(Join(fixedPayloads), Is.EqualTo(hello.Skip(5).ToArray()));
    }

    [Test]
    public void Random_Fragment_Reassembles()
    {
        var hello = CreateClientHello("github.com", 500);
        var chunks = TlsClientHello.FragmentRandom(hello, 96, new Random(1234));

        Assert.That(chunks.Count, Is.GreaterThan(1));
        Assert.That(Join(chunks), Is.EqualTo(hello));
    }

    static byte[] Join(System.Collections.Generic.IReadOnlyList<byte[]> chunks)
    {
        var length = 0;
        foreach (var chunk in chunks) length += chunk.Length;
        var result = new byte[length];
        var offset = 0;
        foreach (var chunk in chunks)
        {
            Buffer.BlockCopy(chunk, 0, result, offset, chunk.Length);
            offset += chunk.Length;
        }
        return result;
    }

    internal static byte[] CreateClientHello(string host, int padding = 0)
    {
        var name = Encoding.ASCII.GetBytes(host);
        var sniDataLength = 2 + 1 + 2 + name.Length;
        var sniExtension = new byte[4 + sniDataLength];
        sniExtension[2] = (byte)(sniDataLength >> 8);
        sniExtension[3] = (byte)sniDataLength;
        var listLength = 1 + 2 + name.Length;
        sniExtension[4] = (byte)(listLength >> 8);
        sniExtension[5] = (byte)listLength;
        sniExtension[7] = (byte)(name.Length >> 8);
        sniExtension[8] = (byte)name.Length;
        name.CopyTo(sniExtension, 9);

        var body = new System.Collections.Generic.List<byte>
        {
            0x03, 0x03,
        };
        for (var i = 0; i < 32; i++) body.Add(0x42);
        body.Add(0);
        body.AddRange(new byte[] { 0x00, 0x02, 0x13, 0x01 });
        body.AddRange(new byte[] { 0x01, 0x00 });

        var extensions = new System.Collections.Generic.List<byte>();
        extensions.AddRange(sniExtension);
        if (padding > 0)
        {
            extensions.AddRange(new byte[] { 0x00, 0x15, (byte)(padding >> 8), (byte)padding });
            extensions.AddRange(new byte[padding]);
        }
        body.Add((byte)(extensions.Count >> 8));
        body.Add((byte)extensions.Count);
        body.AddRange(extensions);

        var handshake = new System.Collections.Generic.List<byte> { 0x01 };
        handshake.Add((byte)(body.Count >> 16));
        handshake.Add((byte)(body.Count >> 8));
        handshake.Add((byte)body.Count);
        handshake.AddRange(body);

        var record = new System.Collections.Generic.List<byte> { 0x16, 0x03, 0x01 };
        record.Add((byte)(handshake.Count >> 8));
        record.Add((byte)handshake.Count);
        record.AddRange(handshake);
        return record.ToArray();
    }
}
