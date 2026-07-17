using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Replaces machine- and user-specific path segments with portable tokens
/// so a baseline captured on one host can be compared meaningfully on
/// another. Without this, every file and registry path in the baseline
/// would carry the original recorder's username and computer name,
/// guaranteeing zero matches against any other machine.
///
/// File-system tokens used:
///   &lt;USER&gt;          → the user-profile directory (any user, not just the recorder)
///   &lt;APPDATA&gt;       → roaming app data
///   &lt;LOCALAPPDATA&gt;  → local app data
///   &lt;PROGRAMDATA&gt;   → C:\ProgramData
///   &lt;PROGRAMFILES&gt;  → C:\Program Files
///   &lt;PROGRAMFILES86&gt;→ C:\Program Files (x86)
///   &lt;WINDOWS&gt;       → C:\Windows
///   &lt;SYSTEM32&gt;      → C:\Windows\System32
///   &lt;TEMP&gt;          → per-user temp dir
///   &lt;USERS&gt;         → C:\Users (literal, parent of all profiles)
///
/// Registry normalisation (<see cref="NormalizeRegistry"/>) converts the
/// native object-manager paths ETW emits (\REGISTRY\MACHINE\…,
/// \REGISTRY\USER\S-1-5-21-…\…) into portable Win32 hive names, folding
/// the recording user's SID into HKEY_CURRENT_USER so user-hive entries
/// match across machines — SIDs are unique per user per machine, so raw
/// SID paths would never match anywhere else. ControlSetNNN is folded to
/// CurrentControlSet for the same reason.
///
/// Substitution order is by descending path length, computed at startup —
/// more specific paths must replace before their parents (TEMP before
/// LOCALAPPDATA, SYSTEM32 before WINDOWS) or the parent token swallows
/// the child path.
/// </summary>
public static class PathNormalizer
{
    private static readonly List<(string Token, string ActualPath)> _replacements;

    private static readonly string? _currentUserSid;

    // Any other user's SID (S-1-5-21-… is the "NT non-unique" account
    // authority used for real user accounts).
    private static readonly Regex _sidRegex =
        new(@"S-1-5-21-\d+(?:-\d+)+", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // ControlSet001 / ControlSet002 → CurrentControlSet (machine-specific
    // which numbered set is current).
    private static readonly Regex _controlSetRegex =
        new(@"\\SYSTEM\\ControlSet\d{3}(?=\\|$)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    static PathNormalizer()
    {
        var userProfile     = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var localAppData    = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData         = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var programData     = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var programFiles    = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var windowsDir      = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var system32        = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var temp            = Path.GetTempPath().TrimEnd('\\', '/');
        var users           = Path.GetDirectoryName(userProfile) ?? "C:\\Users";

        _replacements = new List<(string, string)>
        {
            ("<TEMP>",           temp),
            ("<LOCALAPPDATA>",   localAppData),
            ("<APPDATA>",        appData),
            ("<USER>",           userProfile),
            ("<USERS>",          users),
            ("<PROGRAMFILES86>", programFilesX86),
            ("<PROGRAMFILES>",   programFiles),
            ("<PROGRAMDATA>",    programData),
            ("<SYSTEM32>",       system32),
            ("<WINDOWS>",        windowsDir),
        };

        // Filter out any replacement whose actual path is empty (some
        // SpecialFolder lookups can return "" on stripped-down hosts) so we
        // don't accidentally replace every empty substring with the token.
        _replacements.RemoveAll(r => string.IsNullOrEmpty(r.ActualPath));

        // Longest-actual-path first, enforced structurally rather than by
        // hand-maintained list order (the old hand-ordering had TEMP after
        // LOCALAPPDATA, so temp paths tokenised as <LOCALAPPDATA>\Temp\… —
        // wrong the moment either machine redirects TEMP).
        _replacements.Sort((a, b) => b.ActualPath.Length.CompareTo(a.ActualPath.Length));

        try
        {
            _currentUserSid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value;
        }
        catch
        {
            _currentUserSid = null;
        }
    }

    /// <summary>
    /// Returns <paramref name="path"/> with the recorder's user/system
    /// segments swapped for portable tokens. Case-insensitive prefix match
    /// so paths captured with mixed case still normalize cleanly.
    /// </summary>
    public static string Normalize(string path)
    {
        if (string.IsNullOrEmpty(path)) return path;

        foreach (var (token, actual) in _replacements)
        {
            if (path.StartsWith(actual, StringComparison.OrdinalIgnoreCase))
            {
                return token + path.Substring(actual.Length);
            }
        }

        // Generic fallback: any path under C:\Users\<somename>\ that we
        // didn't catch above (e.g. a different user's profile) gets the
        // username segment replaced. This catches cases like reading
        // another user's profile when the recorder didn't.
        const string usersPrefix = @"C:\Users\";
        if (path.StartsWith(usersPrefix, StringComparison.OrdinalIgnoreCase))
        {
            var afterPrefix = path.Substring(usersPrefix.Length);
            var sep = afterPrefix.IndexOf('\\');
            if (sep > 0)
            {
                return "<USERS>\\<OTHERUSER>" + afterPrefix.Substring(sep);
            }
        }

        return path;
    }

    /// <summary>
    /// Inverse of <see cref="Normalize"/>. Given a baseline-style tokenised
    /// path, expand it to the current machine's actual path so the live-
    /// state inspector knows where to look. Paths containing tokens that
    /// cannot be resolved on this machine (e.g. &lt;OTHERUSER&gt;) are
    /// returned with the token intact — callers should treat any remaining
    /// '&lt;' as "not resolvable here" (see <see cref="ContainsToken"/>).
    /// </summary>
    public static string Expand(string normalizedPath)
    {
        if (string.IsNullOrEmpty(normalizedPath)) return normalizedPath;

        var result = normalizedPath;
        foreach (var (token, actual) in _replacements)
        {
            if (result.StartsWith(token, StringComparison.Ordinal))
            {
                return actual + result.Substring(token.Length);
            }
        }
        return result;
    }

    /// <summary>
    /// True when the path still contains an unresolved token (e.g.
    /// &lt;OTHERUSER&gt;, &lt;SID&gt;) after expansion, meaning it cannot
    /// be inspected literally on this machine.
    /// </summary>
    public static bool ContainsToken(string path)
        => !string.IsNullOrEmpty(path) && path.IndexOf('<') >= 0;

    /// <summary>
    /// Normalizes a kernel-ETW registry key path into a portable form:
    ///
    ///   \REGISTRY\MACHINE\…                    → HKEY_LOCAL_MACHINE\…
    ///   \REGISTRY\USER\&lt;current SID&gt;_Classes\… → HKEY_CURRENT_USER\Software\Classes\…
    ///   \REGISTRY\USER\&lt;current SID&gt;\…       → HKEY_CURRENT_USER\…
    ///   \REGISTRY\USER\&lt;other SID&gt;\…         → HKEY_USERS\&lt;SID&gt;\…  (tokenised)
    ///   …\SYSTEM\ControlSetNNN\…               → …\SYSTEM\CurrentControlSet\…
    ///
    /// Without this, every user-hive entry in a baseline carries the
    /// recording user's SID and can never match a capture from any other
    /// user or machine.
    /// </summary>
    public static string NormalizeRegistry(string keyPath)
    {
        if (string.IsNullOrEmpty(keyPath)) return keyPath;

        var p = keyPath;

        if (p.StartsWith(@"\REGISTRY\MACHINE", StringComparison.OrdinalIgnoreCase))
            p = "HKEY_LOCAL_MACHINE" + p.Substring(@"\REGISTRY\MACHINE".Length);
        else if (p.StartsWith(@"\REGISTRY\USER", StringComparison.OrdinalIgnoreCase))
            p = "HKEY_USERS" + p.Substring(@"\REGISTRY\USER".Length);

        if (_currentUserSid is not null)
        {
            var classesPrefix = $@"HKEY_USERS\{_currentUserSid}_Classes";
            if (p.StartsWith(classesPrefix, StringComparison.OrdinalIgnoreCase))
                p = @"HKEY_CURRENT_USER\Software\Classes" + p.Substring(classesPrefix.Length);
            else
            {
                var userPrefix = $@"HKEY_USERS\{_currentUserSid}";
                if (p.StartsWith(userPrefix, StringComparison.OrdinalIgnoreCase))
                    p = "HKEY_CURRENT_USER" + p.Substring(userPrefix.Length);
            }
        }

        // Any remaining real-user SID belongs to a *different* user —
        // tokenise so at least the shape matches across machines.
        p = _sidRegex.Replace(p, "<SID>");

        p = _controlSetRegex.Replace(p, @"\SYSTEM\CurrentControlSet");

        return p;
    }
}
