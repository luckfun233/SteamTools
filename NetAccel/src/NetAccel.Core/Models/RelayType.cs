namespace NetAccel.Core.Models;

/// <summary>上游中继协议。</summary>
public enum RelayType
{
    /// <summary>SOCKS5（Clash / V2Ray / sing-box 等）。</summary>
    Socks5 = 0,

    /// <summary>HTTP CONNECT（公司代理、沙箱出口、普通 HTTP 代理）。</summary>
    Http = 1,
}
