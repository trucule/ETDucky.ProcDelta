using System.Globalization;
using ETDucky.ProcDelta.Models;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Captures application-runtime ETW providers on a separate (non-kernel)
/// session so the kernel session can stay focused on Process / FileIO /
/// Registry / Network. Two-session design keeps each lifecycle simple and
/// keeps either kind of capture buildable independently.
///
/// Providers enabled in v1, chosen for highest payoff in app-crash
/// diagnosis without overwhelming the diff with noise:
///
///   Microsoft-Windows-Services       service start / stop / SCM errors
///   Microsoft-Windows-WinINet        HTTP/HTTPS at the WinINet layer
///                                    (proxy errors, cert errors,
///                                    connection failures)
///   Microsoft-Windows-CAPI2          certificate chain validation
///   .NET Common Language Runtime     managed unhandled exceptions,
///                                    assembly load failures
///
/// All four are user-mode manifest providers and can coexist on one
/// session.
///
/// PID filtering: same <see cref="ProcessTracker"/> the kernel capture
/// uses — EXCEPT for the Services provider, whose events are emitted by
/// the Service Control Manager (services.exe), a PID that is never
/// tracked. Gating those events on the tracked set silently discarded
/// every one of them; service lifecycle events are recorded regardless of
/// PID instead (they are low-volume and diagnostically relevant to the
/// window being captured).
/// </summary>
public sealed class AppRuntimeCapture : IDisposable
{
    // Provider GUIDs are stable across Windows releases. Sourced from
    // each provider's manifest.
    private static readonly Guid ProviderServices = new("0063715b-eeda-4007-9429-ad526f62696e");
    private static readonly Guid ProviderWinInet = new("43d1a55c-76d6-4f7e-995c-64c711e5cafe");
    private static readonly Guid ProviderCapi2 = new("5bbca4a8-b209-48dc-a8c7-b23d3e5216fb");
    private static readonly Guid ProviderClrRuntime = new("e13c0d23-ccbc-4e12-931b-d9cc2eee27e4");

    // .NET CLR keywords — values from clretwall.man in the .NET source.
    // We enable Exception (0x8000) and Loader (0x8) for managed-exception
    // surface and assembly-load-failure surface respectively.
    private const ulong ClrKeywordException = 0x8000;
    private const ulong ClrKeywordLoader = 0x8;

    private readonly ProcessTracker _tracker;
    private readonly CaptureSession _session;
    private TraceEventSession? _trace;
    private Task? _processTask;
    private volatile bool _stopping;

    /// <summary>
    /// Raised (from a background thread) when the event pump dies while a
    /// capture is supposed to be running. App-runtime capture is
    /// best-effort, so the kernel capture continues — but the operator
    /// should know this surface went dark.
    /// </summary>
    public event Action<string>? Faulted;

    public AppRuntimeCapture(ProcessTracker tracker, CaptureSession session)
    {
        _tracker = tracker;
        _session = session;
    }

    public void Start()
    {
        if (_trace is not null) throw new InvalidOperationException("App-runtime capture already started.");

        var sessionName = EnvironmentalCapture.SessionNamePrefix + "App_" + Guid.NewGuid().ToString("N").Substring(0, 11);

        _stopping = false;
        _trace = new TraceEventSession(sessionName) { StopOnDispose = true };

        _trace.EnableProvider(ProviderServices, TraceEventLevel.Informational);
        _trace.EnableProvider(ProviderWinInet, TraceEventLevel.Informational);
        _trace.EnableProvider(ProviderCapi2, TraceEventLevel.Warning);
        _trace.EnableProvider(ProviderClrRuntime,
            TraceEventLevel.Informational,
            ClrKeywordException | ClrKeywordLoader);

        // Generic Dynamic.All handler — these four providers don't have
        // first-party TraceEvent parser classes in the version we ship,
        // so we read each event's metadata via the universal dynamic
        // surface and decide what to record by ProviderGuid + EventName.
        _trace.Source.Dynamic.All += HandleEvent;

        _processTask = Task.Run(() =>
        {
            string? fault = null;
            try
            {
                _trace.Source.Process();
                if (!_stopping) fault = "the app-runtime ETW session stopped unexpectedly.";
            }
            catch (Exception ex)
            {
                if (!_stopping) fault = $"{ex.GetType().Name}: {ex.Message}";
            }
            if (fault is not null) Faulted?.Invoke(fault);
        });
    }

    public async Task StopAsync()
    {
        if (_trace is null) return;
        _stopping = true;
        try { _trace.Source.StopProcessing(); } catch { }
        if (_processTask is not null)
            await Task.WhenAny(_processTask, Task.Delay(TimeSpan.FromSeconds(2)));
        try { _trace.Dispose(); } catch { }
        _trace = null;
        _processTask = null;
    }

    public void Dispose()
    {
        _stopping = true;
        try { _trace?.Dispose(); } catch { }
        _trace = null;
    }

    private void HandleEvent(TraceEvent data)
    {
        // Classify which provider it came from. Cheap GUID compare beats
        // string compare on ProviderName.
        var pg = data.ProviderGuid;

        // Services events come from services.exe (the SCM), never from a
        // tracked PID — see class remarks. All other providers emit from
        // the app's own process and go through the tracked-PID gate.
        if (pg == ProviderServices)
        {
            RecordServiceEvent(data);
            return;
        }

        if (!_tracker.IsTracked(data.ProcessID)) return;

        if (pg == ProviderWinInet) RecordWinInetEvent(data);
        else if (pg == ProviderCapi2) RecordCapi2Event(data);
        else if (pg == ProviderClrRuntime) RecordClrEvent(data);
        // else: provider we enabled but don't currently render — ignore.
    }

    private void RecordServiceEvent(TraceEvent data)
    {
        var name = data.EventName ?? string.Empty;
        // Filter to events that carry "this service started / stopped /
        // failed". The provider emits ~30 event kinds; only the
        // lifecycle-significant ones belong in a baseline.
        if (!IsServiceLifecycleEvent(name)) return;

        var svc = TryPayloadString(data, "ServiceName") ?? TryPayloadString(data, "Name") ?? "(unknown)";
        var result = ExtractResult(data);
        _session.Append(new EnvironmentalAccess
        {
            Kind = AccessKind.Process,
            Target = $"service:{svc}",
            Operation = name,
            Result = result,
            Detail = data.ProviderName,
            ProcessId = data.ProcessID,
            ProcessImage = "services.exe",
            TimestampUtc = data.TimeStamp.ToUniversalTime(),
        });
    }

    private void RecordWinInetEvent(TraceEvent data)
    {
        var name = data.EventName ?? string.Empty;
        // WinINet is chatty. Keep failures and request lifecycle events.
        if (!IsWinInetInterestingEvent(name)) return;

        var url = TryPayloadString(data, "Url")
               ?? TryPayloadString(data, "ServerName")
               ?? TryPayloadString(data, "Hostname")
               ?? "(unknown)";
        var result = ExtractResult(data);
        _session.Append(new EnvironmentalAccess
        {
            Kind = AccessKind.Network,
            Target = url,
            Operation = name,
            Result = result,
            Detail = data.ProviderName,
            ProcessId = data.ProcessID,
            ProcessImage = _tracker.ImageNameFor(data.ProcessID),
            TimestampUtc = data.TimeStamp.ToUniversalTime(),
        });
    }

    private void RecordCapi2Event(TraceEvent data)
    {
        // CAPI2 emits dense chain-building events at Verbose; we enabled
        // Warning above so only failures + suspicious chains arrive.
        var name = data.EventName ?? string.Empty;
        var subject = TryPayloadString(data, "Subject")
                   ?? TryPayloadString(data, "CertificateName")
                   ?? "(unknown subject)";
        var result = ExtractResult(data);
        _session.Append(new EnvironmentalAccess
        {
            Kind = AccessKind.Network,    // cert validation is a network-adjacent dependency
            Target = $"cert:{subject}",
            Operation = name,
            Result = result,
            Detail = data.ProviderName,
            ProcessId = data.ProcessID,
            ProcessImage = _tracker.ImageNameFor(data.ProcessID),
            TimestampUtc = data.TimeStamp.ToUniversalTime(),
        });
    }

    private void RecordClrEvent(TraceEvent data)
    {
        var name = data.EventName ?? string.Empty;
        // Only the diagnostically-interesting CLR events. ExceptionThrown
        // surfaces what threw before death. AssemblyLoad/Failure surface
        // missing or wrong-version DLLs.
        if (name == "Exception/Start"
         || name == "Exception/Thrown_V1"
         || name == "ExceptionThrown_V1"
         || name == "Loader/AssemblyLoad"
         || name == "AssemblyLoad")
        {
            var exType = TryPayloadString(data, "ExceptionType");
            var asm = TryPayloadString(data, "FullyQualifiedAssemblyName") ?? TryPayloadString(data, "AssemblyName");
            var target = exType ?? asm ?? "(unknown)";
            _session.Append(new EnvironmentalAccess
            {
                Kind = AccessKind.Process,
                Target = $"clr:{target}",
                Operation = name,
                Result = TryPayloadString(data, "ExceptionMessage") ?? "(event)",
                Detail = ".NET CLR Runtime",
                ProcessId = data.ProcessID,
                ProcessImage = _tracker.ImageNameFor(data.ProcessID),
                TimestampUtc = data.TimeStamp.ToUniversalTime(),
            });
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    /// <summary>
    /// Best-effort: extract a payload string by field name, returning null
    /// when the field doesn't exist. The Dynamic provider exposes payload
    /// names + values generically; not every event we receive has every
    /// field we might want.
    /// </summary>
    private static string? TryPayloadString(TraceEvent data, string fieldName)
    {
        try
        {
            var v = data.PayloadByName(fieldName);
            return v?.ToString();
        }
        catch { return null; }
    }

    private static string ExtractResult(TraceEvent data)
    {
        // Convention: providers commonly use "Status", "ErrorCode",
        // "Result", or "HResult" for outcome. Look for each in turn.
        foreach (var field in new[] { "Status", "ErrorCode", "Result", "HResult" })
        {
            var v = TryPayloadString(data, field);
            if (v is null) continue;
            return NormalizeOutcome(v);
        }
        // No outcome field — call it SUCCESS for diff purposes (the event
        // fired, that's a positive observation in itself).
        return "SUCCESS";
    }

    /// <summary>
    /// Canonicalise an outcome value so the same code compares equal
    /// between baseline and live even when one OS build's manifest renders
    /// it decimal and another hex ("2147954407" vs "0x80072EE7").
    /// Zero in any spelling → "SUCCESS"; other numerics → "0xXXXXXXXX";
    /// non-numeric strings pass through unchanged.
    /// </summary>
    private static string NormalizeOutcome(string v)
    {
        var s = v.Trim();
        if (s.Length == 0) return "SUCCESS";
        if (s.Equals("SUCCESS", StringComparison.OrdinalIgnoreCase)) return "SUCCESS";

        ulong parsed;
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (!ulong.TryParse(s.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out parsed))
                return v;
        }
        else if (long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var dec))
        {
            parsed = unchecked((ulong)dec);
        }
        else
        {
            return v;
        }

        if (parsed == 0) return "SUCCESS";
        return $"0x{unchecked((uint)parsed):X8}";
    }

    private static bool IsServiceLifecycleEvent(string name)
        => name.Contains("ServiceStart", StringComparison.OrdinalIgnoreCase)
        || name.Contains("ServiceStop", StringComparison.OrdinalIgnoreCase)
        || name.Contains("ServiceFail", StringComparison.OrdinalIgnoreCase)
        || name.Contains("ServiceError", StringComparison.OrdinalIgnoreCase)
        || name.Contains("StartType", StringComparison.OrdinalIgnoreCase);

    private static bool IsWinInetInterestingEvent(string name)
        => name.Contains("OpenRequest", StringComparison.OrdinalIgnoreCase)
        || name.Contains("SendRequest", StringComparison.OrdinalIgnoreCase)
        || name.Contains("Connect", StringComparison.OrdinalIgnoreCase)
        || name.Contains("Resolve", StringComparison.OrdinalIgnoreCase)
        || name.Contains("Error", StringComparison.OrdinalIgnoreCase)
        || name.Contains("Failure", StringComparison.OrdinalIgnoreCase)
        || name.Contains("ProxyDetect", StringComparison.OrdinalIgnoreCase);
}
