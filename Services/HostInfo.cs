using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace ETDucky.ProcDelta.Services;

/// <summary>Facts about the local host that belong in a baseline or report header.</summary>
[SupportedOSPlatform("windows")]
public static class HostInfo
{
    /// <summary>
    /// "10.0.26100.1234": major.minor.build.UBR from the CurrentVersion key.
    /// Environment.OSVersion stops at the build number, and the UBR is the
    /// part that changes with cumulative updates.
    /// </summary>
    public static string OsBuild()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", writable: false);
            if (key is not null)
            {
                var major = key.GetValue("CurrentMajorVersionNumber");
                var minor = key.GetValue("CurrentMinorVersionNumber");
                var build = key.GetValue("CurrentBuildNumber") as string;
                var ubr = key.GetValue("UBR");
                if (major is int ma && minor is int mi && !string.IsNullOrEmpty(build))
                {
                    var s = string.Format(CultureInfo.InvariantCulture, "{0}.{1}.{2}", ma, mi, build);
                    if (ubr is int u) s += "." + u.ToString(CultureInfo.InvariantCulture);
                    return s;
                }
            }
        }
        catch
        {
            // Fall through to the runtime's view.
        }
        return Environment.OSVersion.Version.ToString();
    }
}
