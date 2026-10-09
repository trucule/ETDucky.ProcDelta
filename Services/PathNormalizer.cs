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
///   &lt;USER&gt;          the user-profile directory (any user, not just the recorder)
///   &lt;APPDATA&gt;       roaming app data
///   &lt;LOCALAPPDATA&gt;  local app data
///   &lt;PROGRAMDATA&gt;   C:\ProgramData
///   &lt;PROGRAMFILES&gt;  C:\Program Files
///   &lt;PROGRAMFILES86&gt; C:\Program Files (x86)
///   &lt;WINDOWS&gt;       C:\Windows
///   &lt;SYSTEM32&gt;      C:\Windows\System32
///   &lt;TEMP&gt;          per-user temp dir
///   &lt;USERS&gt;         C:\Users (literal, parent of all profiles)
///
/// Volatile segment tokens (file paths only, see
/// <see cref="TokeniseVolatileSegments"/>): a segment that is a GUID becomes
/// &lt;GUID&gt;, a segment that is 16 or more hex digits becomes &lt;HEX&gt;,
/// and any *.tmp file becomes &lt;TMP&gt;.tmp. These names are generated per
/// run, so left alone they turn one dependency into a different key on every
/// capture: a missing dependency on one side and a novel entry on the other,
/// forever. Registry paths are NOT tokenised this way: a CLSID is a stable
/// identifier, not a random one.
///
/// Registry normalisation (<see cref="NormalizeRegistry"/>) converts the
/// native object-manager paths ETW emits (\REGISTRY\MACHINE\...,
/// \REGISTRY\USER\S-1-5-21-...\...) into portable Win32 hive names, folding
/// the recording user's SID into HKEY_CURRENT_USER so user-hive entries
/// match across machines. ControlSetNNN is folded to CurrentControlSet for
/// the same reason.
///
/// Substitution order is by descending path length, computed at startup:
/// more specific paths must replace before their parents (TEMP before
/// LOCALAPPDATA, SYSTEM32 before WINDOWS) or the parent token swallows
/// the child path.
/// </summary>
public static class PathNormalizer
{
    private static readonly List<(string Token, string ActualPath)> _replacements;

    private static readonly string? _currentUserSid;

    // Any other user's SID (S-1-5-21-... is the "NT non-unique" account
    // authority used for real user accounts).
    private static readonly Regex _sidRegex =
        new(@"S-1-5-21-\d+(?:-\d+)+", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // ControlSet001 / ControlSet002 -> CurrentControlSet (machine-specific
    // which numbered set is current).
    private static readonly Regex _controlSetRegex =
        new(@"\\SYSTEM\\ControlSet\d{3}(?=\\|$)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex _guidRegex =
        new(@"^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex _hexRegex =
        new(@"^[0-9a-f]{16,}$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public const string GuidToken = "<GUID>";
    public const string HexToken = "<HEX>";
    public const string TempFileToken = "<TMP>";

    static PathNormalizer()
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var temp = Path.GetTempPath().TrimEnd('\\', '/');
        var users = Path.GetDirectoryName(userProfile) ?? "C:\\Users";

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
        // hand-maintained list order.
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
    /// segments swapped for portable tokens and volatile segments (GUIDs,
    /// long hex names, *.tmp files) replaced by stable tokens. Case-
    /// insensitive prefix match so paths captured with mixed case still
    /// normalize cleanly.
    /// </summary>
    public static string Normalize(string path)
    {
        if (string.IsNullOrEmpty(path)) return path;
        return TokeniseVolatileSegments(NormalizeRoots(path));
    }

    private static string NormalizeRoots(string path)
    {
        foreach (var (token, actual) in _replacements)
        {
            if (path.StartsWith(actual, StringComparison.OrdinalIgnoreCase))
            {
                return string.Concat(token, path.AsSpan(actual.Length));
            }
        }

        // Generic fallback: any path under C:\Users\<somename>\ that we
        // didn't catch above (e.g. a different user's profile) gets the
        // username segment replaced.
        const string usersPrefix = @"C:\Users\";
        if (path.StartsWith(usersPrefix, StringComparison.OrdinalIgnoreCase))
        {
            var afterPrefix = path.Substring(usersPrefix.Length);
            var sep = afterPrefix.IndexOf('\\');
            if (sep > 0)
            {
                return string.Concat("<USERS>\\<OTHERUSER>", afterPrefix.AsSpan(sep));
            }
        }

        return path;
    }

    /// <summary>
    /// Replace per-run generated path segments with stable tokens. Pure
    /// string logic over backslash-separated segments; the root token and
    /// every ordinary segment are left untouched. A segment keeps its
    /// extension: "{guid}.json" becomes "&lt;GUID&gt;.json".
    /// </summary>
    public static string TokeniseVolatileSegments(string path)
    {
        if (string.IsNullOrEmpty(path)) return path;

        var segments = path.Split('\\');
        var changed = false;
        for (var i = 0; i < segments.Length; i++)
        {
            var replaced = TokeniseSegment(segments[i]);
            if (!ReferenceEquals(replaced, segments[i]))
            {
                segments[i] = replaced;
                changed = true;
            }
        }
        return changed ? string.Join("\\", segments) : path;
    }

    /// <summary>Returns the same string instance when nothing changed, so callers can test with ReferenceEquals.</summary>
    private static string TokeniseSegment(string segment)
    {
        if (segment.Length == 0) return segment;

        var dot = segment.LastIndexOf('.');
        var stem = dot > 0 ? segment.Substring(0, dot) : segment;
        var ext = dot > 0 ? segment.Substring(dot) : string.Empty;

        if (ext.Equals(".tmp", StringComparison.OrdinalIgnoreCase))
            return TempFileToken + ".tmp";
        if (stem.Length >= 32 && _guidRegex.IsMatch(stem))
            return GuidToken + ext;
        if (stem.Length >= 16 && _hexRegex.IsMatch(stem))
            return HexToken + ext;
        return segment;
    }

    /// <summary>
    /// Inverse of <see cref="Normalize"/> for the root tokens. Given a
    /// baseline-style tokenised path, expand it to the current machine's
    /// actual path so the live-state inspector knows where to look. Paths
    /// containing tokens that cannot be resolved on this machine (e.g.
    /// &lt;OTHERUSER&gt;, &lt;GUID&gt;) are returned with the token intact;
    /// callers treat any remaining '&lt;' as "not resolvable here" (see
    /// <see cref="ContainsToken"/>).
    /// </summary>
    public static string Expand(string normalizedPath)
    {
        if (string.IsNullOrEmpty(normalizedPath)) return normalizedPath;

        var result = normalizedPath;
        foreach (var (token, actual) in _replacements)
        {
            if (result.StartsWith(token, StringComparison.Ordinal))
            {
                return string.Concat(actual, result.AsSpan(token.Length));
            }
        }
        return result;
    }

    /// <summary>
    /// True when the path still contains an unresolved token (e.g.
    /// &lt;OTHERUSER&gt;, &lt;SID&gt;, &lt;GUID&gt;) after expansion, meaning
    /// it cannot be inspected literally on this machine.
    /// </summary>
    public static bool ContainsToken(string path)
        => !string.IsNullOrEmpty(path) && path.Contains('<');

    /// <summary>
    /// Normalizes a kernel-ETW registry key path into a portable form:
    ///
    ///   \REGISTRY\MACHINE\...                        HKEY_LOCAL_MACHINE\...
    ///   \REGISTRY\USER\&lt;current SID&gt;_Classes\...  HKEY_CURRENT_USER\Software\Classes\...
    ///   \REGISTRY\USER\&lt;current SID&gt;\...          HKEY_CURRENT_USER\...
    ///   \REGISTRY\USER\&lt;other SID&gt;\...            HKEY_USERS\&lt;SID&gt;\...  (tokenised)
    ///   ...\SYSTEM\ControlSetNNN\...                  ...\SYSTEM\CurrentControlSet\...
    /// </summary>
    public static string NormalizeRegistry(string keyPath)
    {
        if (string.IsNullOrEmpty(keyPath)) return keyPath;

        var p = keyPath;

        if (p.StartsWith(@"\REGISTRY\MACHINE", StringComparison.OrdinalIgnoreCase))
            p = string.Concat("HKEY_LOCAL_MACHINE", p.AsSpan(@"\REGISTRY\MACHINE".Length));
        else if (p.StartsWith(@"\REGISTRY\USER", StringComparison.OrdinalIgnoreCase))
            p = string.Concat("HKEY_USERS", p.AsSpan(@"\REGISTRY\USER".Length));

        if (_currentUserSid is not null)
        {
            var classesPrefix = $@"HKEY_USERS\{_currentUserSid}_Classes";
            if (p.StartsWith(classesPrefix, StringComparison.OrdinalIgnoreCase))
                p = string.Concat(@"HKEY_CURRENT_USER\Software\Classes", p.AsSpan(classesPrefix.Length));
            else
            {
                var userPrefix = $@"HKEY_USERS\{_currentUserSid}";
                if (p.StartsWith(userPrefix, StringComparison.OrdinalIgnoreCase))
                    p = string.Concat("HKEY_CURRENT_USER", p.AsSpan(userPrefix.Length));
            }
        }

        // Any remaining real-user SID belongs to a *different* user;
        // tokenise so at least the shape matches across machines.
        p = _sidRegex.Replace(p, "<SID>");

        p = _controlSetRegex.Replace(p, @"\SYSTEM\CurrentControlSet");

        return p;
    }
}
