using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using ETDucky.ProcDelta.Models;
using Microsoft.Win32;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Operator consent for what live inspection may do. Both default to off.
///
/// A baseline file is untrusted input: it may have come from a vendor, a
/// colleague, or a ticket attachment, and every target in it is a path,
/// host or key the inspector would otherwise touch while running elevated.
/// With the defaults the inspector makes no network connection (no TCP
/// probe, no UNC or redirector path, no network drive) and prints no
/// registry value content, whatever the file says.
/// </summary>
/// <param name="AllowNetwork">
/// Permit TCP probes to baseline hosts and existence/ACL checks on paths
/// that resolve over the network. Off: those candidates get a one-line
/// "probing disabled" note instead.
/// </param>
/// <param name="ShowRegistryValues">
/// Render registry value content into the report. Off: the report shows the
/// value's type, byte length and SHA-256 hash, which is enough to compare
/// against the baseline's <c>ValueHash</c> without copying secrets into a
/// file that gets attached to tickets.
/// </param>
/// <param name="InspectLive">
/// False for an offline diff of two baselines: nothing on this machine is
/// read at all, and every LiveState line says so.
/// </param>
public sealed record InspectOptions(bool AllowNetwork = false, bool ShowRegistryValues = false, bool InspectLive = true)
{
    public static readonly InspectOptions Default = new();
}

/// <summary>
/// At diagnosis-report time, re-reads each candidate target on the current
/// machine and returns a plain-language summary of what is actually there
/// right now. The kernel events tell you what failed during the captured
/// run; this tells you what state the machine is in now, which is what an
/// admin needs in order to fix the problem.
///
/// All methods are best-effort. If reading the live state fails (the path
/// vanished mid-inspection, the registry key is ACL-blocked even to us),
/// the inspector returns a sentence saying so rather than throwing.
///
/// Every check that could leave the machine goes through
/// <see cref="InspectOptions"/>. The network gate is evaluated before any
/// File.Exists / GetAccessControl / socket call, because an SMB open of a
/// UNC path authenticates as the operator.
/// </summary>
[SupportedOSPlatform("windows")]
public static class LiveStateInspector
{
    /// <summary>LiveState text for a network candidate when probing is off.</summary>
    public const string NetworkProbingDisabled = "(network target, probing disabled)";

    /// <summary>LiveState prefix for a file or image on a network or device path when probing is off.</summary>
    public const string NetworkPathDisabled = "(network or device path, probing disabled)";

    public static string Inspect(AccessKind kind, string target, string detail)
        => Inspect(kind, target, detail, InspectOptions.Default);

    public static string Inspect(AccessKind kind, string target, string detail, InspectOptions options)
    {
        try
        {
            // Synthetic / non-filesystem target namespaces first. Probing
            // these as paths or sockets produces misleading "not found"
            // sentences.
            if (target.StartsWith("service:", StringComparison.OrdinalIgnoreCase))
                return "(service lifecycle event; verify the service's state and start type in services.msc)";
            if (target.StartsWith("clr:", StringComparison.OrdinalIgnoreCase))
                return "(managed-runtime event; no on-disk artifact to probe)";
            if (target.StartsWith("cert:", StringComparison.OrdinalIgnoreCase))
                return "(certificate validation event; inspect the machine/user certificate stores manually)";
            if (target.StartsWith("tcp-connect-failure", StringComparison.OrdinalIgnoreCase))
                return "(aggregate TCP-failure signal; see the network candidates above for specific hosts)";
            if (target.StartsWith("dns:", StringComparison.OrdinalIgnoreCase))
                return options.AllowNetwork ? ResolveLive(target.Substring(4)) : NetworkProbingDisabled;

            return kind switch
            {
                AccessKind.Registry => InspectRegistry(target, detail, options.ShowRegistryValues),
                AccessKind.File => InspectPath(PathNormalizer.Expand(target), options.AllowNetwork, image: false),
                AccessKind.Network => options.AllowNetwork ? InspectNetwork(target) : NetworkProbingDisabled,
                AccessKind.Process => InspectPath(PathNormalizer.Expand(target), options.AllowNetwork, image: true),
                _ => "(live inspection not available for this access kind)",
            };
        }
        catch (Exception ex)
        {
            return $"(live inspection failed: {ex.GetType().Name}: {ex.Message})";
        }
    }

    /// <summary>
    /// True when touching <paramref name="path"/> would leave the machine or
    /// hit a device namespace: UNC in any spelling (\\server\share,
    /// \\?\UNC\server\share, \??\UNC\server\share), raw redirector paths
    /// (\Device\Mup, \Device\LanmanRedirector), \\.\ device paths, or a drive
    /// letter mapped to a network share. \\?\C:\... is local and returns
    /// false. Pure string logic plus one GetDriveType call; no I/O on the
    /// path itself.
    /// </summary>
    public static bool IsNetworkPath(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var p = path.Replace('/', '\\');

        if (p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) return true;
        if (p.StartsWith(@"\??\UNC\", StringComparison.OrdinalIgnoreCase)) return true;

        if (p.StartsWith(@"\\", StringComparison.Ordinal))
        {
            // \\?\C:\... is the extended-length spelling of a local path.
            // \\.\ is the device namespace (pipes, physical drives): never
            // probed. Anything else after \\ names a server.
            if (p.StartsWith(@"\\?\", StringComparison.Ordinal))
                return !IsLocalDriveRoot(p.Substring(4));
            return true;
        }

        if (p.StartsWith(@"\Device\Mup", StringComparison.OrdinalIgnoreCase)) return true;
        if (p.StartsWith(@"\Device\LanmanRedirector", StringComparison.OrdinalIgnoreCase)) return true;

        return IsNetworkDrive(p);
    }

    private static bool IsLocalDriveRoot(string p)
        => p.Length >= 2 && char.IsAsciiLetter(p[0]) && p[1] == ':' && !IsNetworkDrive(p);

    private static bool IsNetworkDrive(string p)
    {
        if (p.Length < 2 || !char.IsAsciiLetter(p[0]) || p[1] != ':') return false;
        try { return new DriveInfo(p.Substring(0, 2)).DriveType == DriveType.Network; }
        catch { return false; }
    }

    // ── Registry ─────────────────────────────────────────────────────────

    private static string InspectRegistry(string fullKeyPath, string valueName, bool showValues)
    {
        // A key that still carries an unresolvable token (another user's
        // SID) can't be opened literally on this machine.
        if (PathNormalizer.ContainsToken(fullKeyPath))
            return $"(key is under another user's hive, inspect manually: {fullKeyPath})";

        var (root, subPath) = RegistryPaths.Split(fullKeyPath);
        if (root is null) return $"Cannot parse registry root from '{fullKeyPath}'.";

        using var key = root.OpenSubKey(subPath, writable: false);
        if (key is null)
        {
            return $"Key does not exist on this machine: {fullKeyPath}";
        }

        if (string.IsNullOrEmpty(valueName))
        {
            // Key-only access (Open / Create / Delete). Surface the subkey
            // and value counts so the operator can tell whether it's an
            // empty stub or fully populated.
            return $"Key present. {key.SubKeyCount} subkey(s), {key.ValueCount} value(s).";
        }

        // Unexpanded, to match the bytes the recorder hashed.
        var rawValue = key.GetValue(valueName, defaultValue: null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (rawValue is null)
        {
            return $"Key present, but value '{valueName}' is not set.";
        }

        var valueKind = key.GetValueKind(valueName);
        if (showValues)
        {
            return $"Value present (type {valueKind}): {RenderRegistryValue(rawValue, valueKind)}";
        }

        // Hidden by default: type, size and the same hash form the baseline
        // carries. Enough to confirm or rule out drift without copying the
        // content into a report that will be attached to a ticket.
        var bytes = RegistryPaths.ToBytes(rawValue, valueKind);
        if (bytes is null)
            return $"Value present (type {valueKind}). Content hidden.";
        return $"Value present (type {valueKind}, {bytes.Length} bytes, {RegistryPaths.HashString(bytes)}). Content hidden.";
    }

    private static string RenderRegistryValue(object value, RegistryValueKind kind)
    {
        return kind switch
        {
            RegistryValueKind.Binary => $"<{((byte[])value).Length} bytes of binary>",
            RegistryValueKind.MultiString => "[" + string.Join(", ", (string[])value) + "]",
            _ => Truncate(value.ToString() ?? "<null>", 120),
        };
    }

    // ── File / process image ─────────────────────────────────────────────

    private static string InspectPath(string expandedPath, bool allowNetwork, bool image)
    {
        if (string.IsNullOrEmpty(expandedPath))
            return "Path empty after expansion.";

        if (PathNormalizer.ContainsToken(expandedPath))
            return $"(path is relative to another user's profile, inspect manually: {expandedPath})";

        // Gate before any filesystem call: File.Exists on \\server\share
        // opens an SMB session as the operator.
        if (!allowNetwork && IsNetworkPath(expandedPath))
            return $"{NetworkPathDisabled} {expandedPath}";

        return image ? InspectProcessImage(expandedPath) : InspectFile(expandedPath);
    }

    private static string InspectFile(string expandedPath)
    {
        if (File.Exists(expandedPath))
        {
            var fi = new FileInfo(expandedPath);
            var acl = SummariseFileAcl(expandedPath);
            return $"File present, {fi.Length:N0} bytes, last write {fi.LastWriteTime:yyyy-MM-dd HH:mm:ss}. ACL: {acl}";
        }
        if (Directory.Exists(expandedPath))
        {
            var acl = SummariseDirectoryAcl(expandedPath);
            return $"Directory present. ACL: {acl}";
        }
        return $"Path does not exist: {expandedPath}";
    }

    private static string InspectProcessImage(string imagePath)
    {
        if (File.Exists(imagePath))
        {
            var fi = new FileInfo(imagePath);
            return $"Image present, {fi.Length:N0} bytes, last write {fi.LastWriteTime:yyyy-MM-dd HH:mm:ss}.";
        }
        return $"Image not found at {imagePath} (process was either uninstalled or never installed on this host).";
    }

    private static string SummariseFileAcl(string path)
    {
        try
        {
            var fi = new FileInfo(path);
            var sec = fi.GetAccessControl();
            return SummariseAcl(sec.GetAccessRules(true, true, typeof(NTAccount)));
        }
        catch (Exception ex) { return $"(read failed: {ex.GetType().Name})"; }
    }

    private static string SummariseDirectoryAcl(string path)
    {
        try
        {
            var di = new DirectoryInfo(path);
            var sec = di.GetAccessControl();
            return SummariseAcl(sec.GetAccessRules(true, true, typeof(NTAccount)));
        }
        catch (Exception ex) { return $"(read failed: {ex.GetType().Name})"; }
    }

    private static string SummariseAcl(AuthorizationRuleCollection rules)
    {
        var parts = new List<string>();
        foreach (FileSystemAccessRule r in rules)
        {
            // Compact: principal=allow|DENY:rights
            var who = r.IdentityReference.Value;
            var rights = ShortenRights(r.FileSystemRights.ToString());
            var kind = r.AccessControlType == AccessControlType.Allow ? "allow" : "DENY";
            parts.Add($"{who}={kind}:{rights}");
        }
        if (parts.Count == 0) return "(no entries)";
        return string.Join(" | ", parts);
    }

    private static string ShortenRights(string s)
    {
        // Strip the dozen flag names FullControl decomposes into to keep
        // the report readable. Replace common aggregates with shorter labels.
        return s
            .Replace("FullControl, Synchronize", "FullControl")
            .Replace("ReadAndExecute, Synchronize", "ReadExec");
    }

    // ── Network ──────────────────────────────────────────────────────────

    private static string InspectNetwork(string target)
    {
        string host;
        int port;

        // WinINet events carry URLs; kernel connect events carry
        // "ip:port". Handle both shapes.
        if (target.Contains("://", StringComparison.Ordinal))
        {
            if (!Uri.TryCreate(target, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Host))
                return $"Cannot parse URL '{Truncate(target, 80)}'.";
            host = uri.Host;
            port = uri.Port; // scheme default when unspecified
        }
        else
        {
            var split = target.LastIndexOf(':');
            if (split <= 0) return $"Cannot parse host:port from '{Truncate(target, 80)}'.";
            host = target.Substring(0, split);
            if (!int.TryParse(target.AsSpan(split + 1), out port))
                return $"Cannot parse port from '{Truncate(target, 80)}'.";
        }

        try
        {
            using var client = new TcpClient();
            var connectTask = client.ConnectAsync(host, port);
            if (!connectTask.Wait(TimeSpan.FromSeconds(3)))
            {
                // Observe the abandoned task's eventual fault so it can't
                // surface as an UnobservedTaskException.
                _ = connectTask.ContinueWith(t => _ = t.Exception,
                    TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
                return $"TCP probe to {host}:{port} timed out after 3s.";
            }
            return $"TCP probe to {host}:{port} succeeded.";
        }
        catch (Exception ex)
        {
            return $"TCP probe to {host}:{port} failed: {ex.GetType().Name}: {ex.Message}";
        }
    }

    /// <summary>Resolve a name on this machine now. Only reached when network probing is allowed.</summary>
    private static string ResolveLive(string host)
    {
        if (string.IsNullOrWhiteSpace(host)) return "Cannot resolve an empty name.";
        try
        {
            var task = System.Net.Dns.GetHostAddressesAsync(host);
            if (!task.Wait(TimeSpan.FromSeconds(3)))
            {
                _ = task.ContinueWith(t => _ = t.Exception,
                    TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
                return $"DNS lookup of {host} timed out after 3s.";
            }
            var addresses = task.Result;
            return addresses.Length == 0
                ? $"DNS lookup of {host} returned no addresses."
                : $"DNS lookup of {host} resolved to {string.Join(", ", addresses.Select(a => a.ToString()))}.";
        }
        catch (Exception ex)
        {
            var inner = ex is AggregateException agg && agg.InnerException is not null ? agg.InnerException : ex;
            return $"DNS lookup of {host} failed: {inner.GetType().Name}: {inner.Message}";
        }
    }

    private static string Truncate(string s, int n)
        => s.Length <= n ? s : string.Concat(s.AsSpan(0, n), "…");
}
