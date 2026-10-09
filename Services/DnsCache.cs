using System.Collections.Concurrent;
using System.Net;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Answers observed from the Microsoft-Windows-DNS-Client provider during a
/// capture, used at snapshot time to key network targets by hostname. Two
/// machines resolving the same CDN name get different addresses, so
/// "13.107.42.14:443" never matches across hosts while
/// "cdn.example.com:443" does.
///
/// Thread-safe: the app-runtime ETW thread writes, snapshots read.
/// </summary>
public sealed class DnsCache
{
    private readonly ConcurrentDictionary<string, string> _hostByIp = new(StringComparer.OrdinalIgnoreCase);
    private static readonly char[] ResultSeparators = { ';', ' ', '\t', ',' };

    public int Count => _hostByIp.Count;

    /// <summary>
    /// Record every address in a DNS-Client "query completed" result string
    /// against the queried name. The string looks like
    /// "type: 5 cdn.example.com;type: 1 93.184.216.34;::ffff:93.184.216.34;".
    /// </summary>
    public void Record(string queryName, string queryResults)
    {
        if (string.IsNullOrWhiteSpace(queryName)) return;
        var host = queryName.Trim().TrimEnd('.').ToLowerInvariant();
        if (host.Length == 0) return;

        foreach (var ip in ParseAddresses(queryResults))
        {
            _hostByIp[ip] = host;
        }
    }

    /// <summary>Hostname last seen resolving to <paramref name="ip"/>, or null.</summary>
    public string? HostFor(string ip)
    {
        if (string.IsNullOrEmpty(ip) || !IPAddress.TryParse(ip, out var address)) return null;
        return _hostByIp.TryGetValue(Normalize(address), out var host) ? host : null;
    }

    /// <summary>
    /// "ip:port" becomes "host:port" when the address was seen in a DNS
    /// answer; anything else (URLs, synthetic targets, unknown addresses) is
    /// returned unchanged.
    /// </summary>
    public string RewriteEndpoint(string endpoint)
    {
        if (string.IsNullOrEmpty(endpoint)) return endpoint;
        if (endpoint.Contains("://", StringComparison.Ordinal)) return endpoint;

        var split = endpoint.LastIndexOf(':');
        if (split <= 0) return endpoint;

        var host = HostFor(endpoint.Substring(0, split));
        return host is null ? endpoint : string.Concat(host, endpoint.AsSpan(split));
    }

    /// <summary>
    /// Addresses in a DNS-Client result string, normalised (IPv4-mapped IPv6
    /// becomes plain IPv4). Bare numbers such as the "5" in "type: 5" are
    /// not addresses even though IPAddress.TryParse accepts them.
    /// </summary>
    public static List<string> ParseAddresses(string? queryResults)
    {
        var list = new List<string>();
        if (string.IsNullOrWhiteSpace(queryResults)) return list;

        foreach (var raw in queryResults.Split(ResultSeparators, StringSplitOptions.RemoveEmptyEntries))
        {
            var token = raw.Trim();
            if (!LooksLikeAddress(token)) continue;
            if (!IPAddress.TryParse(token, out var address)) continue;
            var n = Normalize(address);
            if (!list.Contains(n, StringComparer.OrdinalIgnoreCase)) list.Add(n);
        }
        return list;
    }

    private static bool LooksLikeAddress(string token)
    {
        if (token.Contains(':')) return true; // IPv6 in any form
        var dots = 0;
        foreach (var c in token)
        {
            if (c == '.') dots++;
            else if (c < '0' || c > '9') return false;
        }
        return dots == 3;
    }

    private static string Normalize(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        return address.ToString();
    }
}
