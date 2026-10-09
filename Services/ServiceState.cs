using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Local, read-only view of a Windows service: its state from the Service
/// Control Manager and its start type from the registry. A baseline that
/// recorded a service start describes a transition, and a later run only
/// sees that transition when the service is stopped at the time. Knowing
/// whether the service is running now separates "already there" from
/// "stopped or disabled". A status query needs no elevation and makes no
/// network call.
/// </summary>
public static class ServiceState
{
    /// <summary>Prefix of service lifecycle targets as the app-runtime capture records them.</summary>
    public const string TargetPrefix = "service:";

    public enum Status
    {
        Unavailable,
        NotInstalled,
        Stopped,
        Starting,
        Running,
        Paused,
        Stopping,
    }

    public static bool IsServiceTarget(string target)
        => !string.IsNullOrEmpty(target) && target.StartsWith(TargetPrefix, StringComparison.OrdinalIgnoreCase);

    public static string NameOf(string target)
        => IsServiceTarget(target) ? target.Substring(TargetPrefix.Length) : target;

    /// <summary>
    /// A service start event. The other lifecycle events the capture keeps
    /// (stop, failure, start-type change) are transitions the baseline
    /// happened to see, not something a run depends on.
    /// </summary>
    public static bool IsStartOperation(string operation)
        => !string.IsNullOrEmpty(operation)
        && operation.Contains("ServiceStart", StringComparison.OrdinalIgnoreCase)
        && !operation.Contains("StartType", StringComparison.OrdinalIgnoreCase);

    /// <summary>Current state of the named service on this host.</summary>
    public static Status Query(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return Status.Unavailable;

        var scm = OpenSCManager(null, null, ScManagerConnect);
        if (scm == IntPtr.Zero) return Status.Unavailable;
        try
        {
            var service = OpenService(scm, name, ServiceQueryStatus);
            if (service == IntPtr.Zero)
            {
                return Marshal.GetLastWin32Error() == ErrorServiceDoesNotExist ? Status.NotInstalled : Status.Unavailable;
            }
            try
            {
                if (!QueryServiceStatus(service, out var status)) return Status.Unavailable;
                return status.CurrentState switch
                {
                    ServiceStopped => Status.Stopped,
                    ServiceStartPending => Status.Starting,
                    ServiceStopPending => Status.Stopping,
                    ServiceRunning => Status.Running,
                    ServiceContinuePending => Status.Starting,
                    ServicePausePending => Status.Stopping,
                    ServicePaused => Status.Paused,
                    _ => Status.Unavailable,
                };
            }
            finally
            {
                _ = CloseServiceHandle(service);
            }
        }
        finally
        {
            _ = CloseServiceHandle(scm);
        }
    }

    /// <summary>Start type from the service's registry key: Boot, System, Automatic, Automatic (delayed), Manual, Disabled, or unknown.</summary>
    public static string StartTypeOf(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "unknown";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + name);
            if (key?.GetValue("Start") is not int start) return "unknown";
            var delayed = key.GetValue("DelayedAutostart") is int d && d == 1;
            return start switch
            {
                0 => "Boot",
                1 => "System",
                2 => delayed ? "Automatic (delayed)" : "Automatic",
                3 => "Manual",
                4 => "Disabled",
                _ => "unknown",
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return "unknown";
        }
    }

    /// <summary>One sentence for the report's live-state line.</summary>
    public static string Describe(string name)
    {
        var status = Query(name);
        if (status == Status.NotInstalled) return $"Service {name} is not installed on this host.";
        if (status == Status.Unavailable) return $"Service {name}: state could not be read.";

        var startType = StartTypeOf(name);
        var state = status switch
        {
            Status.Running => "running",
            Status.Stopped => "stopped",
            Status.Paused => "paused",
            Status.Starting => "starting",
            Status.Stopping => "stopping",
            _ => "in an unknown state",
        };
        var sentence = $"Service {name} is {state} (start type {startType}).";
        if (status == Status.Stopped && startType == "Disabled")
            sentence += " A disabled service cannot be started by the application.";
        return sentence;
    }

    // Service Control Manager access, read-only. Constants from winsvc.h.
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const int ErrorServiceDoesNotExist = 1060;

    private const uint ServiceStopped = 1;
    private const uint ServiceStartPending = 2;
    private const uint ServiceStopPending = 3;
    private const uint ServiceRunning = 4;
    private const uint ServiceContinuePending = 5;
    private const uint ServicePausePending = 6;
    private const uint ServicePaused = 7;

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusData
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr scManager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatus(IntPtr service, out ServiceStatusData status);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);
}
