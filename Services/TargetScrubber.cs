using System.Buffers;
using System.Globalization;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Strips secret-bearing and run-specific parts from captured targets at
/// capture time, before they enter the aggregation key, the baseline file
/// or the report. Scrubbing at capture rather than at save means the data
/// is never held in memory in its raw form either.
/// </summary>
public static class TargetScrubber
{
    private static readonly SearchValues<char> QueryOrFragment = SearchValues.Create("?#");

    /// <summary>
    /// Reduce a URL to scheme://host[:port]/path. The query string, fragment
    /// and userinfo are dropped: that is where SAS tokens, API keys, OAuth
    /// codes and session ids travel, and a baseline is a file users are told
    /// to share. A non-default port is kept because it identifies the
    /// dependency. Input that is not an absolute URL (WinINet sometimes
    /// reports a bare server name) is returned with anything from the first
    /// '?' or '#' removed and any leading "user:password@" removed.
    /// </summary>
    public static string ScrubUrl(string url)
    {
        if (string.IsNullOrEmpty(url)) return url;

        if (Uri.TryCreate(url, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.Host))
        {
            var port = uri.IsDefaultPort
                ? string.Empty
                : ":" + uri.Port.ToString(CultureInfo.InvariantCulture);
            return $"{uri.Scheme}://{uri.Host}{port}{uri.AbsolutePath}";
        }

        var cut = url.AsSpan().IndexOfAny(QueryOrFragment);
        var s = cut >= 0 ? url.Substring(0, cut) : url;

        var at = s.IndexOf('@');
        if (at >= 0)
        {
            var slash = s.IndexOf('/');
            if (slash < 0 || at < slash) s = s.Substring(at + 1);
        }
        return s;
    }
}
