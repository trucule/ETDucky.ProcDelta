using System;
using System.Threading;
using System.Windows.Forms;

namespace ETDucky.ProcDelta;

/// <summary>
/// WinForms entry point. ETW capture requires elevation (the manifest forces
/// a UAC prompt at launch) so by the time MainForm constructs, we already
/// have the privilege to create a TraceEventSession.
///
/// Global exception handlers: an unhandled exception must not silently
/// kill the process — that would strand any running kernel ETW session
/// until reboot (it survives process death and consumes one of the host's
/// 8 slots; the startup orphan sweep reclaims it on next launch, but the
/// operator deserves an error dialog rather than a vanishing window).
/// </summary>
internal static class Program
{
    [STAThread]
    static void Main()
    {
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) => ShowFatal(e.Exception);
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            if (e.ExceptionObject is Exception ex) ShowFatal(ex);
        };
        TaskScheduler_Hookup();

        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }

    private static void TaskScheduler_Hookup()
    {
        // Background-task faults (e.g. an abandoned probe task) should
        // never escalate; observe and drop.
        System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (_, e) => e.SetObserved();
    }

    private static void ShowFatal(Exception ex)
    {
        try
        {
            MessageBox.Show(
                "Unexpected error: " + ex.GetType().Name + ": " + ex.Message + Environment.NewLine + Environment.NewLine +
                "If a capture was running, stop and restart it. Any stranded ETW session will be cleaned up automatically the next time the tool starts.",
                "ProcDelta", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        catch { /* nothing else to do */ }
    }
}
