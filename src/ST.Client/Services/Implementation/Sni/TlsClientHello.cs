using System;
using System.Collections.Generic;
using System.Text;

namespace System.Application.Services.Implementation
{
    /// <summary>
    /// 最小 TLS ClientHello 解析：读取/改写 SNI，按字节分片。
    /// 只处理单个 TLS record 内的 ClientHello，解析失败时调用方应原样转发。
    /// </summary>
    public static class TlsClientHello
    {
        const byte HandshakeContentType = 0x16;
        const byte ClientHelloHandshakeType = 0x01;
        const ushort ServerNameExtensionType = 0x0000;

        public static bool TryGetSni(ReadOnlySpan<byte> data, out string? sni)
        {
            sni = null;
            if (!TryParse(data, out var info)) return false;
            sni = Encoding.ASCII.GetString(data.Slice(info.NameOffset, info.NameLength));
            return !string.IsNullOrEmpty(sni);
        }

        public static bool TryRewriteSni(ReadOnlySpan<byte> data, string newSni, out byte[] rewritten)
        {
            rewritten = Array.Empty<byte>();
            if (string.IsNullOrWhiteSpace(newSni)) return false;
            if (newSni.Length > 255) return false;
            if (!TryParse(data, out var info)) return false;

            var newName = Encoding.ASCII.GetBytes(newSni);
            var delta = newName.Length - info.NameLength;
            if (delta == 0)
            {
                var copy = data.ToArray();
                newName.CopyTo(copy.AsSpan(info.NameOffset));
                rewritten = copy;
                return true;
            }

            var result = new byte[data.Length + delta];
            data.Slice(0, info.NameOffset).CopyTo(result);
            newName.CopyTo(result.AsSpan(info.NameOffset));
            data.Slice(info.NameOffset + info.NameLength).CopyTo(result.AsSpan(info.NameOffset + newName.Length));

            if (!TryAdd(result, info.NameLengthOffset, newName.Length, out _)) return false;
            if (!TryAdd(result, info.ListLengthOffset, delta, out _)) return false;
            if (!TryAdd(result, info.ExtensionLengthOffset, delta, out _)) return false;
            if (!TryAdd(result, info.ExtensionsLengthOffset, delta, out _)) return false;
            if (!TryAdd(result, info.HandshakeLengthOffset, delta, out _, 3)) return false;
            if (!TryAdd(result, info.RecordLengthOffset, delta, out _)) return false;

            rewritten = result;
            return true;
        }

        public static IReadOnlyList<byte[]> Fragment(ReadOnlySpan<byte> data, int chunkSize)
        {
            if (chunkSize < 1) chunkSize = 1;
            var result = new List<byte[]>();
            for (var offset = 0; offset < data.Length; offset += chunkSize)
            {
                var length = Math.Min(chunkSize, data.Length - offset);
                result.Add(data.Slice(offset, length).ToArray());
            }
            return result;
        }

        static bool TryParse(ReadOnlySpan<byte> data, out ClientHelloInfo info)
        {
            info = default;
            if (data.Length < 5 || data[0] != HandshakeContentType) return false;

            var recordLength = ReadUInt16(data, 3);
            var recordEnd = 5 + recordLength;
            if (recordEnd > data.Length || recordEnd < 9) return false;
            if (data[5] != ClientHelloHandshakeType) return false;

            var handshakeLength = ReadUInt24(data, 6);
            if (9 + handshakeLength > data.Length) return false;

            var pos = 9;
            if (pos + 2 + 32 > recordEnd) return false;
            pos += 2 + 32; // client version + random

            if (pos + 1 > recordEnd) return false;
            var sessionLen = data[pos];
            pos += 1 + sessionLen;
            if (pos + 2 > recordEnd) return false;

            var cipherLen = ReadUInt16(data, pos);
            pos += 2 + cipherLen;
            if (pos + 1 > recordEnd) return false;

            var compressionLen = data[pos];
            pos += 1 + compressionLen;
            if (pos + 2 > recordEnd) return false;

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
            public int ExtensionLengthOffset;
            public int ExtensionsLengthOffset;
            public int HandshakeLengthOffset;
            public int RecordLengthOffset;
        }
    }
}
