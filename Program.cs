namespace ETDucky.ProcDelta;

/// <summary>
/// Entry point. With arguments the tool runs headless (<see cref="Cli"/>);
/// without, it opens the window.
///
/// ETW capture requires elevation (the manifest forces a UAC prompt at
/// launch) so by the time MainForm constructs, we already have the
/// privilege to create a TraceEventSession.
///
/// Global exception handlers: an unhandled exception must not silently
/// kill the process. That would strand any running kernel ETW session
/// until reboot (it survives process death and consumes one of the host's
/// 8 slots; the startup orphan sweep reclaims it on next launch, but the
/// operator deserves an error dialog rather than a vanishing window). The
/// full exception, with line numbers from the embedded PDB, is written to
/// a crash log under the user's local app data so a report can carry it.
/// </summary>
internal static class Program
{
    [STAThread]
    static int Main(string[] args)
    {
        if (args.Length > 0) return Cli.Run(args);

        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) => ShowFatal(e.Exception);
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            if (e.ExceptionObject is Exception ex) ShowFatal(ex);
        };
        TaskScheduler_Hookup();

        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
        return 0;
    }

    private static void TaskScheduler_Hookup()
    {
        // Background-task faults (e.g. an abandoned probe task) should
        // never escalate; observe and drop.
        System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (_, e) => e.SetObserved();
    }

    /// <summary>Folder for crash logs: %LOCALAPPDATA%\ETDucky.ProcDelta. The only file the tool writes without being asked.</summary>
    public static string CrashLogDirectory
        => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ETDucky.ProcDelta");

    private static void ShowFatal(Exception ex)
    {
        string? logPath = null;
        try
        {
            Directory.CreateDirectory(CrashLogDirectory);
            logPath = Path.Combine(CrashLogDirectory, $"crash-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
            File.WriteAllText(logPath, ex.ToString());
        }
        catch
        {
            logPath = null;
        }

        try
        {
            MessageBox.Show(
                "Unexpected error: " + ex.GetType().Name + ": " + ex.Message + Environment.NewLine + Environment.NewLine +
                (logPath is null ? "The crash log could not be written." : "Details with line numbers were written to " + logPath) + Environment.NewLine + Environment.NewLine +
                "If a capture was running, stop and restart it. Any stranded ETW session will be cleaned up automatically the next time the tool starts.",
                "ProcDelta", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        catch { /* nothing else to do */ }
    }
}
