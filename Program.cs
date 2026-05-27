using System;
using System.Windows.Forms;

namespace ETDucky.ProcDelta;

/// <summary>
/// WinForms entry point. ETW capture requires elevation (the manifest forces
/// a UAC prompt at launch) so by the time MainForm constructs, we already
/// have the privilege to create a TraceEventSession.
/// </summary>
internal static class Program
{
    [STAThread]
    static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}
