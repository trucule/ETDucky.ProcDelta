using System.Diagnostics;
using Microsoft.Win32;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Launch-and-track support. The tool runs elevated (kernel ETW requires
/// it), but the application under test must not: an app started with an
/// administrator token sees a different registry view, different
/// virtualisation rules and different network identity than the user's
/// real session, which makes a baseline unrepresentative.
///
/// With no arguments the launch is handed to explorer.exe, which runs at
/// the user's normal integrity level and starts the target the way a
/// double-click would. With arguments the target is started directly and
/// inherits this tool's elevation; the result says so, and the UI shows it.
///
/// The target may be a full path, a path relative to the current directory,
/// or a bare name. A bare name is looked up the way the Run dialog looks it
/// up: the current directory, each PATH entry, then the App Paths registry
/// keys. A bare name without an extension gets .exe.
/// </summary>
public static class ProcessLauncher
{
    /// <param name="Started">The target process was created.</param>
    /// <param name="Elevated">The target inherited this tool's elevation.</param>
    /// <param name="Note">One line for the console or the UI.</param>
    /// <param name="ResolvedPath">Full path of the executable that was resolved, or empty when none was found.</param>
    public sealed record LaunchResult(bool Started, bool Elevated, string Note, string ResolvedPath = "");

    private const string AppPathsKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\";

    private static readonly (RegistryHive Hive, RegistryView View)[] AppPathsHives =
    {
        (RegistryHive.CurrentUser, RegistryView.Default),
        (RegistryHive.LocalMachine, RegistryView.Registry64),
        (RegistryHive.LocalMachine, RegistryView.Registry32),
    };

    public static LaunchResult Launch(string exePath, string? arguments)
    {
        if (string.IsNullOrWhiteSpace(exePath)) return new LaunchResult(false, false, "No executable given.");

        var resolved = ResolveExecutable(exePath);
        if (resolved is null)
        {
            return new LaunchResult(false, false,
                $"Not found: {exePath}. Give a full path, or a name that is on PATH or registered under App Paths.");
        }
        exePath = resolved;

        var workingDirectory = Path.GetDirectoryName(exePath) ?? Environment.CurrentDirectory;
        var fallbackReason = string.Empty;

        if (string.IsNullOrWhiteSpace(arguments))
        {
            try
            {
                var explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
                using var p = Process.Start(new ProcessStartInfo(explorer, "\"" + exePath + "\"")
                {
                    UseShellExecute = false,
                    WorkingDirectory = workingDirectory,
                });
                return new LaunchResult(true, false, $"Launched {exePath} through explorer.exe at the user's normal integrity level.", exePath);
            }
            catch (Exception ex)
            {
                fallbackReason = $" (explorer.exe handoff failed: {ex.Message})";
            }
        }

        try
        {
            using var p = Process.Start(new ProcessStartInfo(exePath, arguments ?? string.Empty)
            {
                UseShellExecute = true,
                WorkingDirectory = workingDirectory,
            });
            return new LaunchResult(true, true, $"Launched {exePath} directly; the app inherits this tool's elevation.{fallbackReason}", exePath);
        }
        catch (Exception ex)
        {
            return new LaunchResult(false, false, $"Launch failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Process pattern for a launch target: the file name of the executable
    /// it resolves to, so "notepad" tracks notepad.exe. A target that does
    /// not resolve keeps its own file name; the launch then reports it.
    /// </summary>
    public static string PatternFor(string exePath)
        => Path.GetFileName(ResolveExecutable(exePath) ?? exePath.Trim().Trim('"'));

    /// <summary>
    /// Full path of the executable a launch target names, or null when
    /// nothing matches. Rooted paths and paths with a directory part are
    /// taken as given. A bare name is searched in the current directory,
    /// then each PATH entry, then HKCU and HKLM App Paths (64-bit and
    /// 32-bit views). A bare name without an extension gets .exe.
    /// </summary>
    public static string? ResolveExecutable(string exePath)
    {
        if (string.IsNullOrWhiteSpace(exePath)) return null;
        var target = exePath.Trim().Trim('"');
        if (target.Length == 0) return null;

        try
        {
            if (Path.IsPathRooted(target)
                || target.Contains(Path.DirectorySeparatorChar)
                || target.Contains(Path.AltDirectorySeparatorChar))
            {
                var full = Path.GetFullPath(target);
                return File.Exists(full) ? full : null;
            }

            var name = Path.HasExtension(target) ? target : target + ".exe";

            var candidate = Path.GetFullPath(Path.Combine(Environment.CurrentDirectory, name));
            if (File.Exists(candidate)) return candidate;

            var pathVar = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            foreach (var dir in pathVar.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                try
                {
                    candidate = Path.GetFullPath(Path.Combine(dir.Trim('"'), name));
                    if (File.Exists(candidate)) return candidate;
                }
                catch (ArgumentException)
                {
                    // A malformed PATH entry. Skip it, as the shell does.
                }
            }

            return AppPathsLookup(name);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException or IOException)
        {
            return null;
        }
    }

    /// <summary>
    /// The App Paths registration for an executable name, the mechanism the
    /// Run dialog and ShellExecute use for names that are not on PATH. Reads
    /// only; a value that does not point at an existing file is ignored.
    /// </summary>
    private static string? AppPathsLookup(string name)
    {
        foreach (var (hive, view) in AppPathsHives)
        {
            try
            {
                using var root = RegistryKey.OpenBaseKey(hive, view);
                using var key = root.OpenSubKey(AppPathsKey + name);
                if (key?.GetValue(null) is string value && !string.IsNullOrWhiteSpace(value))
                {
                    var path = Environment.ExpandEnvironmentVariables(value.Trim().Trim('"'));
                    if (File.Exists(path)) return Path.GetFullPath(path);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or ArgumentException)
            {
                // Unreadable hive or malformed value; try the next hive.
            }
        }
        return null;
    }
}
