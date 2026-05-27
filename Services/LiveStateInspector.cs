using System;
using System.IO;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using ETDucky.ProcDelta.Models;
using Microsoft.Win32;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// At diagnosis-report time, re-reads each candidate target on the current
/// machine and returns a plain-language summary of what's actually there
/// right now. The kernel events tell you what failed during the captured
/// run; this tells you what state the machine is in now, which is what an
/// admin actually needs to fix the problem.
///
/// All methods are best-effort. If reading the live state fails (the path
/// vanished mid-inspection, the registry key is ACL-blocked even to us),
/// the inspector returns a sentence saying so rather than throwing.
/// </summary>
[SupportedOSPlatform("windows")]
public static class LiveStateInspector
{
    public static string Inspect(EnvironmentalAccess access)
        => Inspect(access.Kind, access.Target, access.Detail);

    public static string Inspect(Baseline.Entry entry)
        => Inspect(entry.Kind, entry.Target, entry.Detail);

    public static string Inspect(AccessKind kind, string target, string detail)
    {
        try
        {
            return kind switch
            {
                AccessKind.Registry => InspectRegistry(target, detail),
                AccessKind.File     => InspectFile(PathNormalizer.Expand(target)),
                AccessKind.Network  => InspectNetwork(target),
                AccessKind.Process  => InspectProcessImage(PathNormalizer.Expand(target)),
                _                   => "(live inspection not available for this access kind)",
            };
        }
        catch (Exception ex)
        {
            return $"(live inspection failed: {ex.GetType().Name}: {ex.Message})";
        }
    }

    // ── Registry ─────────────────────────────────────────────────────────

    private static string InspectRegistry(string fullKeyPath, string valueName)
    {
        var (root, subPath) = SplitRegistryPath(fullKeyPath);
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

        var rawValue = key.GetValue(valueName, defaultValue: null);
        if (rawValue is null)
        {
            return $"Key present, but value '{valueName}' is not set.";
        }

        var valueKind = key.GetValueKind(valueName);
        var rendered = RenderRegistryValue(rawValue, valueKind);
        return $"Value present (type {valueKind}): {rendered}";
    }

    private static string RenderRegistryValue(object value, RegistryValueKind kind)
    {
        return kind switch
        {
            RegistryValueKind.Binary    => $"<{((byte[])value).Length} bytes of binary>",
            RegistryValueKind.MultiString => "[" + string.Join(", ", (string[])value) + "]",
            _ => Truncate(value.ToString() ?? "<null>", 120),
        };
    }

    private static (RegistryKey? Root, string SubPath) SplitRegistryPath(string fullPath)
    {
        if (string.IsNullOrEmpty(fullPath)) return (null, "");

        // ETW kernel registry events emit native object-manager paths
        // (\REGISTRY\MACHINE\... and \REGISTRY\USER\...). Convert to the
        // Win32 hive names the .NET RegistryKey API understands.
        var p = fullPath.Replace("\\REGISTRY\\MACHINE", "HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase)
                        .Replace("\\REGISTRY\\USER",    "HKEY_USERS",         StringComparison.OrdinalIgnoreCase);

        // Map well-known SID under HKEY_USERS to HKEY_CURRENT_USER when it
        // matches the current process's identity.
        var currentSid = WindowsIdentity.GetCurrent().User?.Value;
        if (currentSid is not null)
        {
            var hkcuPrefix = $"HKEY_USERS\\{currentSid}";
            if (p.StartsWith(hkcuPrefix, StringComparison.OrdinalIgnoreCase))
            {
                p = "HKEY_CURRENT_USER" + p.Substring(hkcuPrefix.Length);
            }
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

    // ── File ─────────────────────────────────────────────────────────────

    private static string InspectFile(string expandedPath)
    {
        if (string.IsNullOrEmpty(expandedPath))
            return "Path empty after expansion.";

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
        var parts = new System.Collections.Generic.List<string>();
        foreach (FileSystemAccessRule r in rules)
        {
            // Compact: principal:rights:allow|deny
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

    private static string InspectNetwork(string hostPort)
    {
        // Target shape is "host:port" or "ip:port".
        var split = hostPort.LastIndexOf(':');
        if (split <= 0) return $"Cannot parse host:port from '{hostPort}'.";

        var host = hostPort.Substring(0, split);
        if (!int.TryParse(hostPort.Substring(split + 1), out var port))
            return $"Cannot parse port from '{hostPort}'.";

        try
        {
            using var client = new TcpClient();
            var connectTask = client.ConnectAsync(host, port);
            if (!connectTask.Wait(TimeSpan.FromSeconds(3)))
                return $"TCP probe to {host}:{port} timed out after 3s.";
            return $"TCP probe to {host}:{port} succeeded.";
        }
        catch (Exception ex)
        {
            return $"TCP probe to {host}:{port} failed: {ex.GetType().Name}: {ex.Message}";
        }
    }

    // ── Process image ────────────────────────────────────────────────────

    private static string InspectProcessImage(string imagePath)
    {
        if (File.Exists(imagePath))
        {
            var fi = new FileInfo(imagePath);
            return $"Image present, {fi.Length:N0} bytes, last write {fi.LastWriteTime:yyyy-MM-dd HH:mm:ss}.";
        }
        return $"Image not found at {imagePath} (process was either uninstalled or never installed on this host).";
    }

    private static string Truncate(string s, int n)
        => s.Length <= n ? s : s.Substring(0, n) + "…";
}
