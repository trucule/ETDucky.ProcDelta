using ETDucky.ProcDelta.Models;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Pre-save review of a baseline for entries the recording operator may not
/// want in a file they are about to share: account names, server names,
/// customer folder names. Deterministic string rules only. Nothing is
/// removed; the operator sees the list and decides.
///
/// What is NOT flagged, by design: tokenised paths (&lt;APPDATA&gt;\...),
/// raw local device paths (\Device\HarddiskVolume3\...), process basenames,
/// and ip:port network targets. Those carry no name the normaliser did not
/// already strip.
/// </summary>
public static class BaselineScrubber
{
    public sealed record Finding(string Reason, AccessKind Kind, string Target);

    public const string ReasonEmail = "contains '@' (email or account name)";
    public const string ReasonUncPath = "UNC path (names a server and share)";
    public const string ReasonUntokenisedPath = "path outside the standard Windows folders";

    public static List<Finding> FindSensitive(Baseline baseline)
    {
        var findings = new List<Finding>();
        foreach (var e in baseline.Entries)
        {
            var target = e.Target;
            var detail = e.Detail;

            if (target.Contains('@') || detail.Contains('@'))
            {
                findings.Add(new Finding(ReasonEmail, e.Kind, target));
                continue;
            }

            if (e.Kind is AccessKind.File or AccessKind.Process)
            {
                if (IsUnc(target))
                    findings.Add(new Finding(ReasonUncPath, e.Kind, target));
                else if (IsUntokenisedDrivePath(target))
                    findings.Add(new Finding(ReasonUntokenisedPath, e.Kind, target));
            }
        }
        return findings;
    }

    private static bool IsUnc(string t)
    {
        if (t.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) return true;
        if (!t.StartsWith(@"\\", StringComparison.Ordinal)) return false;
        // \\?\C:\ and \\.\ are local spellings, not servers.
        return !t.StartsWith(@"\\?\", StringComparison.Ordinal)
            && !t.StartsWith(@"\\.\", StringComparison.Ordinal);
    }

    /// <summary>
    /// A drive-letter path that survived normalisation unchanged. Everything
    /// under a known Windows folder became a token; what is left is D:\Clients\...
    /// and the like.
    /// </summary>
    private static bool IsUntokenisedDrivePath(string t)
        => t.Length >= 3 && char.IsAsciiLetter(t[0]) && t[1] == ':' && t[2] == '\\';
}
