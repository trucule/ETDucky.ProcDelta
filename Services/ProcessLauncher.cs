using System.Diagnostics;

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
/// </summary>
public static class ProcessLauncher
{
    public sealed record LaunchResult(bool Started, bool Elevated, string Note);

    public static LaunchResult Launch(string exePath, string? arguments)
    {
        if (string.IsNullOrWhiteSpace(exePath)) return new LaunchResult(false, false, "No executable given.");
        if (!File.Exists(exePath)) return new LaunchResult(false, false, $"Not found: {exePath}");

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
                return new LaunchResult(true, false, "Launched through explorer.exe at the user's normal integrity level.");
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
            return new LaunchResult(true, true, "Launched directly; the app inherits this tool's elevation." + fallbackReason);
        }
        catch (Exception ex)
        {
            return new LaunchResult(false, false, $"Launch failed: {ex.Message}");
        }
    }

    /// <summary>Process pattern for a launched executable: its file name.</summary>
    public static string PatternFor(string exePath)
        => Path.GetFileName(exePath);
}
