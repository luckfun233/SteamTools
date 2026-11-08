using System.Threading;

namespace System.Application.Services.Implementation
{
    /// <summary>
    /// SNI sidecar 运行统计，供设置页展示和问题诊断。
    /// </summary>
    public static class SniSidecarStats
    {
        static long connections;
        static long fragmented;
        static long rewritten;
        static long presetIp;
        static long relayed;
        static long failures;
        static long bytesUp;
        static long bytesDown;

        public static long Connections => Interlocked.Read(ref connections);
        public static long Fragmented => Interlocked.Read(ref fragmented);
        public static long Rewritten => Interlocked.Read(ref rewritten);
        public static long PresetIp => Interlocked.Read(ref presetIp);
        public static long Relayed => Interlocked.Read(ref relayed);
        public static long Failures => Interlocked.Read(ref failures);
        public static long BytesUp => Interlocked.Read(ref bytesUp);
        public static long BytesDown => Interlocked.Read(ref bytesDown);

        public static void OnConnection() => Interlocked.Increment(ref connections);
        public static void OnFragment() => Interlocked.Increment(ref fragmented);
        public static void OnRewrite() => Interlocked.Increment(ref rewritten);
        public static void OnPresetIp() => Interlocked.Increment(ref presetIp);
        public static void OnRelay() => Interlocked.Increment(ref relayed);
        public static void OnFailure() => Interlocked.Increment(ref failures);
        public static void OnBytesUp(long value) => Interlocked.Add(ref bytesUp, value);
        public static void OnBytesDown(long value) => Interlocked.Add(ref bytesDown, value);

        public static void Reset()
        {
            Interlocked.Exchange(ref connections, 0);
            Interlocked.Exchange(ref fragmented, 0);
            Interlocked.Exchange(ref rewritten, 0);
            Interlocked.Exchange(ref presetIp, 0);
            Interlocked.Exchange(ref relayed, 0);
            Interlocked.Exchange(ref failures, 0);
            Interlocked.Exchange(ref bytesUp, 0);
            Interlocked.Exchange(ref bytesDown, 0);
        }

        public static string ToDisplayString()
            => $"连接 {Connections} / 分片 {Fragmented} / 改写 {Rewritten} / 预置IP {PresetIp} / 中继 {Relayed} / 失败 {Failures}";
    }
}
