using System;
using System.Collections.Generic;
using System.IO;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Replaces machine- and user-specific path segments with portable tokens
/// so a baseline captured on one host can be compared meaningfully on
/// another. Without this, every file and registry path in the baseline
/// would carry the original recorder's username and computer name,
/// guaranteeing zero matches against any other machine.
///
/// Tokens used:
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
/// Order of substitution matters — more specific paths must replace before
/// their parent paths (LOCALAPPDATA before USER, SYSTEM32 before WINDOWS).
/// </summary>
public static class PathNormalizer
{
    private static readonly List<(string Token, string ActualPath)> _replacements;

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

        // Ordering: longest path first. LOCALAPPDATA is under USER, SYSTEM32
        // is under WINDOWS, etc. — the more specific replacement has to win
        // the substitution race or the parent token swallows the child path.
        _replacements = new List<(string, string)>
        {
            ("<LOCALAPPDATA>",   localAppData),
            ("<APPDATA>",        appData),
            ("<TEMP>",           temp),
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
    /// state inspector knows where to look.
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
}
