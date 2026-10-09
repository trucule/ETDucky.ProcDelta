using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Registry path and value helpers shared by <see cref="RegistryValueCache"/>
/// (hashing during a recording) and <see cref="LiveStateInspector"/> (re-reading
/// during a diff). One implementation on both sides means a hash written into
/// a baseline is comparable with a hash computed on the live machine.
/// </summary>
[SupportedOSPlatform("windows")]
public static class RegistryPaths
{
    private static readonly string? _currentUserSid = ReadCurrentUserSid();

    /// <summary>
    /// Split a full key path into its hive root and sub-path. Accepts the
    /// normalized HKEY_* form (current captures) and the native \REGISTRY\...
    /// form (legacy baselines). The current user's SID under HKEY_USERS folds
    /// to HKEY_CURRENT_USER. Returns a null root for an unknown hive.
    /// </summary>
    public static (RegistryKey? Root, string SubPath) Split(string fullPath)
    {
        if (string.IsNullOrEmpty(fullPath)) return (null, "");

        var p = fullPath
            .Replace("\\REGISTRY\\MACHINE", "HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase)
            .Replace("\\REGISTRY\\USER", "HKEY_USERS", StringComparison.OrdinalIgnoreCase);

        if (_currentUserSid is not null)
        {
            var hkcuPrefix = $"HKEY_USERS\\{_currentUserSid}";
            if (p.StartsWith(hkcuPrefix, StringComparison.OrdinalIgnoreCase))
                p = string.Concat("HKEY_CURRENT_USER", p.AsSpan(hkcuPrefix.Length));
        }

        var split = p.IndexOf('\\');
        if (split <= 0) return (null, "");
        var hiveName = p.Substring(0, split);
        var sub = p.Substring(split + 1);

        RegistryKey? root = hiveName.ToUpperInvariant() switch
        {
            "HKEY_LOCAL_MACHINE" => Registry.LocalMachine,
            "HKEY_CURRENT_USER" => Registry.CurrentUser,
            "HKEY_USERS" => Registry.Users,
            "HKEY_CLASSES_ROOT" => Registry.ClassesRoot,
            "HKEY_CURRENT_CONFIG" => Registry.CurrentConfig,
            _ => null,
        };
        return (root, sub);
    }

    /// <summary>
    /// Render a registry value into a deterministic byte sequence so a hash is
    /// stable across machines for "same" values. Strings are UTF-8, DWORD and
    /// QWORD little-endian, multi-string joined with NUL, binary as-is. Returns
    /// null for kinds that are not hashed (None, Unknown).
    /// </summary>
    public static byte[]? ToBytes(object value, RegistryValueKind kind)
    {
        return kind switch
        {
            RegistryValueKind.String => Encoding.UTF8.GetBytes((string)value),
            RegistryValueKind.ExpandString => Encoding.UTF8.GetBytes((string)value),
            RegistryValueKind.MultiString => Encoding.UTF8.GetBytes(string.Join("\0", (string[])value)),
            RegistryValueKind.DWord => BitConverter.GetBytes(Convert.ToInt32(value, CultureInfo.InvariantCulture)),
            RegistryValueKind.QWord => BitConverter.GetBytes(Convert.ToInt64(value, CultureInfo.InvariantCulture)),
            RegistryValueKind.Binary => (byte[])value,
            _ => null,
        };
    }

    /// <summary>
    /// "sha256:" followed by lowercase hex. This is the form baseline entries
    /// carry in <c>ValueHash</c>, so a hidden value in a report can be matched
    /// against the baseline by eye.
    /// </summary>
    public static string HashString(byte[] bytes)
        => "sha256:" + Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static string? ReadCurrentUserSid()
    {
        try { return System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value; }
        catch { return null; }
    }
}
