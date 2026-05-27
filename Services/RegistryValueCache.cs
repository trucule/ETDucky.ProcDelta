using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Captures a SHA-256 hash and a type name for every distinct (key,
/// valueName) tuple observed during a recording. Used by
/// <see cref="BaselineRecorder"/> to populate <c>ValueHash</c> and
/// <c>ValueType</c> on baseline entries, and by <see cref="DiffEngine"/>
/// to detect value drift between baseline and live capture.
///
/// Strategy: kernel ETW does not include value content in its registry
/// events, so we do an immediate user-mode read-back on first encounter
/// of each (key, valueName). The read happens once per tuple per
/// recording — subsequent kernel events for the same tuple don't trigger
/// re-reads. The hash represents "what the value contained at the moment
/// the tracked process first touched it during this recording", which is
/// the right semantic for a known-good baseline.
///
/// Privacy: only the hash is stored. The value bytes themselves never
/// leave this service. The hash lets diff detect drift between machines
/// without exposing the value.
///
/// Read failures (ACL-blocked, value deleted by the time we look, type
/// not representable as bytes) are silent — the entry simply gets no
/// ValueHash and the diff engine treats it as "value hashing not
/// available" rather than as a drift signal.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RegistryValueCache
{
    private readonly ConcurrentDictionary<string, HashedValue> _hashes = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Schedule a read for (keyName, valueName) if not already cached.
    /// Returns immediately; the read runs synchronously on the calling
    /// thread (which is the ETW reader thread for the capture path —
    /// kept fast by skipping the read whenever the tuple is already in
    /// the cache, which is the steady-state case).
    /// </summary>
    public void Observe(string keyName, string valueName)
    {
        if (string.IsNullOrEmpty(keyName) || string.IsNullOrEmpty(valueName)) return;
        var k = Compose(keyName, valueName);
        if (_hashes.ContainsKey(k)) return;

        try
        {
            var (root, subPath) = SplitRegistryPath(keyName);
            if (root is null) return;

            using var key = root.OpenSubKey(subPath, writable: false);
            if (key is null) return;

            var raw = key.GetValue(valueName, defaultValue: null);
            if (raw is null) return;

            var kind = key.GetValueKind(valueName);
            var bytes = ToBytes(raw, kind);
            if (bytes is null) return;

            var hash = SHA256.HashData(bytes);
            var hex = "sha256:" + Convert.ToHexString(hash).ToLowerInvariant();
            _hashes[k] = new HashedValue(hex, kind.ToString());
        }
        catch
        {
            // Read failures are expected (ACL-blocked, ephemeral keys,
            // values that disappear between the kernel event and our
            // read). Don't record anything; the entry stays unhashed.
        }
    }

    /// <summary>
    /// Returns the cached (hash, type) for the given (key, valueName),
    /// or null if no value was captured.
    /// </summary>
    public HashedValue? Get(string keyName, string valueName)
    {
        if (string.IsNullOrEmpty(keyName) || string.IsNullOrEmpty(valueName)) return null;
        return _hashes.TryGetValue(Compose(keyName, valueName), out var v) ? v : null;
    }

    /// <summary>
    /// Compute a hash for the value as it exists on the LIVE host right
    /// now. Used by the diff engine to compare against a baseline hash.
    /// Returns null when the value can't be read.
    /// </summary>
    public static HashedValue? HashLiveValue(string keyName, string valueName)
    {
        if (string.IsNullOrEmpty(keyName) || string.IsNullOrEmpty(valueName)) return null;
        try
        {
            var (root, subPath) = SplitRegistryPath(keyName);
            if (root is null) return null;
            using var key = root.OpenSubKey(subPath, writable: false);
            if (key is null) return null;
            var raw = key.GetValue(valueName, defaultValue: null);
            if (raw is null) return null;
            var kind = key.GetValueKind(valueName);
            var bytes = ToBytes(raw, kind);
            if (bytes is null) return null;
            var hash = SHA256.HashData(bytes);
            var hex = "sha256:" + Convert.ToHexString(hash).ToLowerInvariant();
            return new HashedValue(hex, kind.ToString());
        }
        catch
        {
            return null;
        }
    }

    private static string Compose(string keyName, string valueName)
        => keyName + "" + valueName;

    /// <summary>
    /// Render a registry value into a deterministic byte sequence so the
    /// hash is stable across machines for "same" values. Strings → UTF-8.
    /// DWORDs/QWORDs → little-endian bytes. Multi-string → joined with
    /// NUL. Binary → as-is.
    /// </summary>
    private static byte[]? ToBytes(object value, RegistryValueKind kind)
    {
        return kind switch
        {
            RegistryValueKind.String       => Encoding.UTF8.GetBytes((string)value),
            RegistryValueKind.ExpandString => Encoding.UTF8.GetBytes((string)value),
            RegistryValueKind.MultiString  => Encoding.UTF8.GetBytes(string.Join("\0", (string[])value)),
            RegistryValueKind.DWord        => BitConverter.GetBytes(Convert.ToInt32(value, CultureInfo.InvariantCulture)),
            RegistryValueKind.QWord        => BitConverter.GetBytes(Convert.ToInt64(value, CultureInfo.InvariantCulture)),
            RegistryValueKind.Binary       => (byte[])value,
            _                              => null,
        };
    }

    /// <summary>
    /// Same hive-path parsing the LiveStateInspector uses. Copied here to
    /// keep the cache decoupled from the inspector.
    /// </summary>
    private static (RegistryKey? Root, string SubPath) SplitRegistryPath(string fullPath)
    {
        if (string.IsNullOrEmpty(fullPath)) return (null, "");

        var p = fullPath
            .Replace("\\REGISTRY\\MACHINE", "HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase)
            .Replace("\\REGISTRY\\USER",    "HKEY_USERS",         StringComparison.OrdinalIgnoreCase);

        var currentSid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value;
        if (currentSid is not null)
        {
            var hkcuPrefix = $"HKEY_USERS\\{currentSid}";
            if (p.StartsWith(hkcuPrefix, StringComparison.OrdinalIgnoreCase))
                p = "HKEY_CURRENT_USER" + p.Substring(hkcuPrefix.Length);
        }

        var split = p.IndexOf('\\');
        if (split <= 0) return (null, "");
        var hiveName = p.Substring(0, split);
        var sub = p.Substring(split + 1);

        RegistryKey? root = hiveName.ToUpperInvariant() switch
        {
            "HKEY_LOCAL_MACHINE"  => Registry.LocalMachine,
            "HKEY_CURRENT_USER"   => Registry.CurrentUser,
            "HKEY_USERS"          => Registry.Users,
            "HKEY_CLASSES_ROOT"   => Registry.ClassesRoot,
            "HKEY_CURRENT_CONFIG" => Registry.CurrentConfig,
            _ => null,
        };
        return (root, sub);
    }
}

/// <summary>Cached pair: SHA-256 hash string + registry type name.</summary>
public sealed record HashedValue(string Hash, string TypeName);
