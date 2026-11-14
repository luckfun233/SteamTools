using System.Text;

namespace NetAccel.Core.Tls;

/// <summary>TLS ClientHello 分片策略。</summary>
public enum TlsFragmentStrategy
{
    /// <summary>按固定大小拆分。</summary>
    Fixed = 0,

    /// <summary>在 SNI 主机名首字节处拆成三段，任何一段都不包含完整域名。</summary>
    SniBoundary = 1,

    /// <summary>按 TLS record 头和 handshake 头拆分。</summary>
    Record = 2,

    /// <summary>把 SNI 拆成多段，每段单独发送。</summary>
    SniPieces = 3,

    /// <summary>把 ClientHello 重新封装成多个 TLS record，并让 SNI 跨越 record 边界。</summary>
    TlsRecordSplit = 4,

    /// <summary>随机大小分片。</summary>
    Random = 5,

    /// <summary>
    /// TCP OOB（URG）拆分：利用带外字节制造乱序，参考 byedpi 的 --oob。
    /// 需要完整保留字节流，失败时自动回退普通分片。
    /// </summary>
    OobSplit = 6,

    /// <summary>
    /// 自动模式：默认 TLS record 拆分，失败后依次尝试 SNI 边界与不分片，
    /// 并按域名记住成功的策略。参考 byedpi 的 --auto 思路。
    /// </summary>
    Auto = 7,
}

/// <summary>
/// 最小 TLS ClientHello 解析：读取/改写/移除 SNI，按字节或 TLS record 分片。
/// 所有解析失败都返回 false 并让调用方原样转发，绝不抛出异常影响代理链路。
/// </summary>
public static class TlsClientHello
{
    const byte HandshakeContentType = 0x16;
    const byte ClientHelloHandshakeType = 0x01;
    const ushort ServerNameExtensionType = 0x0000;
    const int MaxRecordPayload = 16384;

    /// <summary>
    /// 返回第一段 TLS record 的总长度（5 + record length）。
    /// </summary>
    public static bool TryGetRecordLength(ReadOnlySpan<byte> data, out int totalLength)
    {
        totalLength = 0;
        if (data.Length < 5 || data[0] != HandshakeContentType) return false;

        var recordLength = ReadUInt16(data, 3);
        if (recordLength == 0 || recordLength > MaxRecordPayload) return false;

        totalLength = 5 + recordLength;
        if (totalLength < 5) return false;

        // 允许数据还没收全，但长度必须可信。
        return true;
    }

    public static bool TryGetSni(ReadOnlySpan<byte> data, out string? sni)
    {
        sni = null;
        if (!TryParse(data, out var info)) return false;

        var bytes = data.Slice(info.NameOffset, info.NameLength);
        if (!IsValidHostName(bytes)) return false;

        sni = Encoding.ASCII.GetString(bytes);
        return !string.IsNullOrEmpty(sni);
    }

    /// <summary>返回 SNI 主机名在 ClientHello 中的偏移和长度。</summary>
    public static bool TryGetSniRange(ReadOnlySpan<byte> data, out int offset, out int length)
    {
        offset = 0;
        length = 0;
        if (!TryParse(data, out var info)) return false;
        offset = info.NameOffset;
        length = info.NameLength;
        return true;
    }

    public static bool TryRewriteSni(ReadOnlySpan<byte> data, string newSni, out byte[] rewritten)
    {
        rewritten = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(newSni)) return false;

        if (string.Equals(newSni, "none", StringComparison.OrdinalIgnoreCase))
        {
            return TryRemoveSni(data, out rewritten);
        }

        newSni = newSni.Trim();
        if (newSni.Length > 255) return false;

        var newName = Encoding.ASCII.GetBytes(newSni);
        if (!IsValidHostName(newName)) return false;

        if (!TryParse(data, out var info)) return false;

        var delta = newName.Length - info.NameLength;
        if (delta == 0)
        {
            var copy = data.ToArray();
            newName.CopyTo(copy.AsSpan(info.NameOffset));
            rewritten = copy;
            return true;
        }

        if (data.Length + delta > MaxRecordPayload + 5) return false;

        var result = new byte[data.Length + delta];
        data[..info.NameOffset].CopyTo(result);
        newName.CopyTo(result.AsSpan(info.NameOffset));
        data[(info.NameOffset + info.NameLength)..].CopyTo(result.AsSpan(info.NameOffset + newName.Length));

        // 六级长度字段都要同步调整，漏掉任何一个都会让服务端解析失败。
        if (!TryAdd(result, info.NameLengthOffset, delta, out _)) return false;
        if (!TryAdd(result, info.ListLengthOffset, delta, out _)) return false;
        if (!TryAdd(result, info.ExtensionLengthOffset, delta, out _)) return false;
        if (!TryAdd(result, info.ExtensionsLengthOffset, delta, out _)) return false;
        if (!TryAdd(result, info.HandshakeLengthOffset, delta, out _, 3)) return false;
        if (!TryAdd(result, info.RecordLengthOffset, delta, out _)) return false;

        rewritten = result;
        return true;
    }

    /// <summary>移除 SNI 扩展，对应 DevSidecar 的 sni: "none"。</summary>
    public static bool TryRemoveSni(ReadOnlySpan<byte> data, out byte[] rewritten)
    {
        rewritten = Array.Empty<byte>();
        if (!TryParse(data, out var info)) return false;

        var removeLength = info.ExtensionTotalLength;
        if (removeLength <= 0 || removeLength > data.Length) return false;

        var result = new byte[data.Length - removeLength];
        data[..info.ExtensionHeaderOffset].CopyTo(result);
        data[(info.ExtensionHeaderOffset + removeLength)..].CopyTo(result.AsSpan(info.ExtensionHeaderOffset));

        if (!TryAdd(result, info.ExtensionsLengthOffset, -removeLength, out _)) return false;
        if (!TryAdd(result, info.HandshakeLengthOffset, -removeLength, out _, 3)) return false;
        if (!TryAdd(result, info.RecordLengthOffset, -removeLength, out _)) return false;

        rewritten = result;
        return true;
    }

    public static IReadOnlyList<byte[]> Fragment(ReadOnlySpan<byte> data, int chunkSize)
    {
        if (chunkSize < 1) chunkSize = 1;
        if (data.Length == 0) return Array.Empty<byte[]>();

        var result = new List<byte[]>((data.Length + chunkSize - 1) / chunkSize);
        for (var offset = 0; offset < data.Length; offset += chunkSize)
        {
            var length = Math.Min(chunkSize, data.Length - offset);
            result.Add(data.Slice(offset, length).ToArray());
        }
        return result;
    }

    /// <summary>在 SNI 首字节处拆成三段，确保没有任何一个 TCP 段包含完整主机名。</summary>
    public static IReadOnlyList<byte[]> FragmentBySni(ReadOnlySpan<byte> data)
    {
        if (!TryGetSniRange(data, out var offset, out var length) || length < 2)
        {
            return Fragment(data, Math.Max(1, Math.Min(64, data.Length)));
        }

        var first = data[..offset].ToArray();
        var second = data.Slice(offset, 1).ToArray();
        var third = data[(offset + 1)..].ToArray();

        var result = new List<byte[]>(3);
        if (first.Length > 0) result.Add(first);
        result.Add(second);
        if (third.Length > 0) result.Add(third);
        return result;
    }

    /// <summary>按 TLS record 头与 handshake 头拆分，强度弱于 SNI 边界拆分，仅作兼容策略。</summary>
    public static IReadOnlyList<byte[]> FragmentByRecord(ReadOnlySpan<byte> data)
    {
        if (data.Length <= 9 || data[0] != HandshakeContentType) return new[] { data.ToArray() };

        return new[]
        {
            data[..5].ToArray(),
            data.Slice(5, 4).ToArray(),
            data[9..].ToArray(),
        };
    }

    /// <summary>把 SNI 拆成多段，每段单独发送。</summary>
    public static IReadOnlyList<byte[]> FragmentBySniPieces(ReadOnlySpan<byte> data, int pieces)
    {
        if (!TryGetSniRange(data, out var offset, out var length) || length < 2)
        {
            return Fragment(data, Math.Max(1, Math.Min(64, data.Length)));
        }

        pieces = Math.Max(2, Math.Min(Math.Min(8, length), pieces));
        var result = new List<byte[]>(pieces + 1);
        if (offset > 0) result.Add(data[..offset].ToArray());

        var baseSize = length / pieces;
        var remainder = length % pieces;
        var position = offset;
        for (var i = 0; i < pieces; i++)
        {
            var size = baseSize + (i < remainder ? 1 : 0);
            var end = i == pieces - 1 ? data.Length : position + size;
            if (end <= position) continue;
            result.Add(data.Slice(position, end - position).ToArray());
            position = end;
        }
        return result;
    }

    /// <summary>
    /// 把 ClientHello 重新封装成多个 TLS record，并让 SNI 跨越 record 边界。
    /// TLS 允许 handshake 消息跨 record，服务端可以正常重组，只按 record 检查的 DPI 看不到完整域名。
    /// </summary>
    public static IReadOnlyList<byte[]> FragmentToTlsRecords(ReadOnlySpan<byte> data)
    {
        if (!TryGetSniRange(data, out var sniOffset, out var sniLength) || sniLength < 2)
        {
            return FragmentToTlsRecordsFixed(data, 64);
        }

        if (data.Length < 5 || data[0] != HandshakeContentType) return new[] { data.ToArray() };

        var recordLength = ReadUInt16(data, 3);
        if (5 + recordLength > data.Length || recordLength < 1) return new[] { data.ToArray() };

        // SNI 偏移相对整个 record，转成 record payload 偏移。
        var payloadOffset = sniOffset - 5;
        if (payloadOffset <= 0 || payloadOffset >= recordLength) return new[] { data.ToArray() };

        var segments = new List<(int Start, int Length)>();
        AddRecordSegment(segments, 0, payloadOffset);
        AddRecordSegment(segments, payloadOffset, 1);
        AddRecordSegment(segments, payloadOffset + 1, -1);
        return BuildTlsRecords(data, segments);
    }

    /// <summary>按固定大小把第一个 record 的 handshake 负载切成多个 TLS record。</summary>
    public static IReadOnlyList<byte[]> FragmentToTlsRecordsFixed(ReadOnlySpan<byte> data, int chunkSize)
    {
        if (data.Length < 5 || data[0] != HandshakeContentType) return new[] { data.ToArray() };
        if (chunkSize < 1) chunkSize = 1;

        var recordLength = ReadUInt16(data, 3);
        if (5 + recordLength > data.Length || recordLength < 1) return new[] { data.ToArray() };

        var segments = new List<(int Start, int Length)>();
        for (var offset = 0; offset < recordLength; offset += chunkSize)
        {
            var length = Math.Min(chunkSize, recordLength - offset);
            AddRecordSegment(segments, offset, length);
        }
        return BuildTlsRecords(data, segments);
    }

    public static IReadOnlyList<byte[]> FragmentRandom(ReadOnlySpan<byte> data, int maxChunkSize, Random? random = null)
    {
        maxChunkSize = Math.Max(1, maxChunkSize);
        if (data.Length == 0) return Array.Empty<byte[]>();

        var result = new List<byte[]>();
        var offset = 0;
        while (offset < data.Length)
        {
            var size = random == null ? NextSharedRandom(maxChunkSize) : random.Next(1, maxChunkSize + 1);
            var length = Math.Min(size, data.Length - offset);
            result.Add(data.Slice(offset, length).ToArray());
            offset += length;
        }
        return result;
    }

    public static IReadOnlyList<byte[]> Fragment(
        ReadOnlySpan<byte> data,
        TlsFragmentStrategy strategy,
        int chunkSize,
        int pieces = 3,
        Random? random = null)
    {
        if (data.Length == 0) return Array.Empty<byte[]>();

        return strategy switch
        {
            TlsFragmentStrategy.SniBoundary => FragmentBySni(data),
            TlsFragmentStrategy.Record => FragmentByRecord(data),
            TlsFragmentStrategy.SniPieces => FragmentBySniPieces(data, pieces),
            TlsFragmentStrategy.TlsRecordSplit => FragmentToTlsRecords(data),
            TlsFragmentStrategy.Random => FragmentRandom(data, chunkSize, random),
            _ => Fragment(data, chunkSize),
        };
    }

    static readonly Random sharedRandom = new();
    static readonly object sharedRandomLock = new();

    static int NextSharedRandom(int maxInclusive)
    {
        lock (sharedRandomLock) return sharedRandom.Next(1, maxInclusive + 1);
    }

    static void AddRecordSegment(List<(int Start, int Length)> segments, int start, int length)
    {
        // -1 表示一直延伸到 record payload 末尾。
        if (length < 0)
        {
            segments.Add((start, -1));
            return;
        }

        while (length > MaxRecordPayload)
        {
            segments.Add((start, MaxRecordPayload));
            start += MaxRecordPayload;
            length -= MaxRecordPayload;
        }
        if (length > 0) segments.Add((start, length));
    }

    static IReadOnlyList<byte[]> BuildTlsRecords(ReadOnlySpan<byte> data, List<(int Start, int Length)> segments)
    {
        if (data.Length < 5 || data[0] != HandshakeContentType) return new[] { data.ToArray() };

        var recordLength = ReadUInt16(data, 3);
        var recordEnd = 5 + recordLength;
        if (recordEnd > data.Length || recordLength < 1) return new[] { data.ToArray() };

        var versionMajor = data[1];
        var versionMinor = data[2];
        var result = new List<byte[]>(segments.Count + 1);

        foreach (var (start, length) in segments)
        {
            var end = length < 0 ? recordLength : Math.Min(recordLength, start + length);
            if (end <= start) continue;

            var payloadLength = end - start;
            if (payloadLength > MaxRecordPayload) continue;

            var record = new byte[5 + payloadLength];
            record[0] = HandshakeContentType;
            record[1] = versionMajor;
            record[2] = versionMinor;
            record[3] = (byte)(payloadLength >> 8);
            record[4] = (byte)payloadLength;
            data.Slice(5 + start, payloadLength).CopyTo(record.AsSpan(5));
            result.Add(record);
        }

        // 第一个 record 之后如果还有其它 record（例如 0-RTT / 中间人补丁），原样保留。
        if (recordEnd < data.Length) result.Add(data[recordEnd..].ToArray());

        return result.Count == 0 ? new[] { data.ToArray() } : result;
    }

    /// <summary>
    /// 解析单个 record 内的完整 ClientHello。只支持 SNI 位于第一个 record 的常见情况；
    /// 跨 record 的 ClientHello 会解析失败，调用方按普通流量转发。
    /// </summary>
    static bool TryParse(ReadOnlySpan<byte> data, out ClientHelloInfo info)
    {
        info = default;
        if (data.Length < 9 || data[0] != HandshakeContentType) return false;

        var recordLength = ReadUInt16(data, 3);
        var recordEnd = 5 + recordLength;
        if (recordLength < 4 || recordEnd > data.Length) return false;
        if (data[5] != ClientHelloHandshakeType) return false;

        var handshakeLength = ReadUInt24(data, 6);
        if (handshakeLength < 38 || 9 + handshakeLength > data.Length) return false;

        var pos = 9;
        if (pos + 2 + 32 > recordEnd) return false;
        pos += 2 + 32; // client_version + random

        if (pos + 1 > recordEnd) return false;
        var sessionLen = data[pos];
        pos += 1 + sessionLen;
        if (pos + 2 > recordEnd) return false;

        var cipherLen = ReadUInt16(data, pos);
        pos += 2 + cipherLen;
        if (pos + 1 > recordEnd) return false;

        var compressionLen = data[pos];
        pos += 1 + compressionLen;
        if (compressionLen < 1 || pos + 2 > recordEnd) return false;

        var extensionsLengthOffset = pos;
        var extensionsLength = ReadUInt16(data, pos);
        pos += 2;
        var extensionsEnd = pos + extensionsLength;
        if (extensionsEnd > recordEnd) return false;

        while (pos + 4 <= extensionsEnd)
        {
            var type = ReadUInt16(data, pos);
            var length = ReadUInt16(data, pos + 2);
            var extDataOffset = pos + 4;
            var extEnd = extDataOffset + length;
            if (extEnd > extensionsEnd) return false;

            if (type == ServerNameExtensionType && length >= 5)
            {
                var listLengthOffset = extDataOffset;
                var listLength = ReadUInt16(data, listLengthOffset);
                var nameType = data[extDataOffset + 2];
                var nameLengthOffset = extDataOffset + 3;
                var nameLength = ReadUInt16(data, nameLengthOffset);
                var nameOffset = extDataOffset + 5;

                if (nameType == 0 &&
                    listLength >= 3 &&
                    nameLength > 0 &&
                    nameOffset + nameLength <= extEnd)
                {
                    info = new ClientHelloInfo
                    {
                        NameOffset = nameOffset,
                        NameLength = nameLength,
                        NameLengthOffset = nameLengthOffset,
                        ListLengthOffset = listLengthOffset,
                        ExtensionHeaderOffset = pos,
                        ExtensionTotalLength = 4 + length,
                        ExtensionLengthOffset = pos + 2,
                        ExtensionsLengthOffset = extensionsLengthOffset,
                        HandshakeLengthOffset = 6,
                        RecordLengthOffset = 3,
                    };
                    return true;
                }
            }

            pos = extEnd;
        }

        return false;
    }

    static bool IsValidHostName(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0 || bytes.Length > 255) return false;
        foreach (var b in bytes)
        {
            // 仅允许可打印 ASCII，拒绝 NUL/控制字符避免注入。
            if (b <= 0x20 || b >= 0x7F) return false;
        }
        return true;
    }

    static bool TryAdd(byte[] data, int offset, int delta, out int value, int bytes = 2)
    {
        value = 0;
        if (offset < 0 || offset + bytes > data.Length) return false;

        var original = bytes == 3 ? ReadUInt24(data, offset) : ReadUInt16(data, offset);
        var updated = original + delta;
        var max = bytes == 3 ? 0xFFFFFF : 0xFFFF;
        if (updated < 0 || updated > max) return false;

        if (bytes == 3) WriteUInt24(data, offset, updated);
        else WriteUInt16(data, offset, updated);

        value = updated;
        return true;
    }

    static ushort ReadUInt16(ReadOnlySpan<byte> data, int offset)
        => (ushort)((data[offset] << 8) | data[offset + 1]);

    static int ReadUInt24(ReadOnlySpan<byte> data, int offset)
        => (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];

    static void WriteUInt16(byte[] data, int offset, int value)
    {
        data[offset] = (byte)((value >> 8) & 0xFF);
        data[offset + 1] = (byte)(value & 0xFF);
    }

    static void WriteUInt24(byte[] data, int offset, int value)
    {
        data[offset] = (byte)((value >> 16) & 0xFF);
        data[offset + 1] = (byte)((value >> 8) & 0xFF);
        data[offset + 2] = (byte)(value & 0xFF);
    }

    struct ClientHelloInfo
    {
        public int NameOffset;
        public int NameLength;
        public int NameLengthOffset;
        public int ListLengthOffset;
        public int ExtensionHeaderOffset;
        public int ExtensionTotalLength;
        public int ExtensionLengthOffset;
        public int ExtensionsLengthOffset;
        public int HandshakeLengthOffset;
        public int RecordLengthOffset;
    }
}
