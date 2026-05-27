using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using ETDucky.ProcDelta.Models;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Drives the kernel ETW session that observes registry / file / network /
/// process activity, filters per-PID via the <see cref="ProcessTracker"/>,
/// and appends every kept access to the <see cref="CaptureSession"/>.
///
/// Uses a PRIVATE kernel session (System Trace Provider Group, Windows 8+)
/// rather than the legacy single-instance NT Kernel Logger. Naming the
/// session anything other than KernelTraceEventParser.KernelSessionName
/// tells TraceEvent to use the private mechanism, which allows multiple
/// concurrent kernel sessions on the host. Coexists with PerfView, xperf,
/// the ET Ducky agent, etc. Up to 8 private kernel sessions per host.
/// </summary>
public sealed class EnvironmentalCapture : IDisposable
{
    private readonly ProcessTracker _tracker;
    private readonly CaptureSession _session;
    private readonly RegistryValueCache _registryValues = new();
    private readonly object _lock = new();
    private TraceEventSession? _trace;
    private Task? _processTask;
    private CancellationTokenSource? _cts;

    /// <summary>
    /// File-I/O Init events (Create / Delete) carry the path and IRP pointer
    /// but not the result. The matching FileIOOperationEnd event carries the
    /// NTSTATUS but not the path. Same IrpPtr links the pair. This dictionary
    /// holds the Init side while waiting for the End.
    /// </summary>
    private readonly ConcurrentDictionary<ulong, PendingFileOp> _pendingFileOps = new();

    private readonly record struct PendingFileOp(
        string Operation,
        string FileName,
        int ProcessId,
        DateTime TimestampUtc,
        uint CreateOptions);

    /// <summary>
    /// Hashes of registry value contents observed during the capture.
    /// Populated lazily as Query/SetValue events arrive; consumed by
    /// BaselineRecorder during Build to attach ValueHash + ValueType
    /// to the matching entries.
    /// </summary>
    public RegistryValueCache RegistryValues => _registryValues;

    public EnvironmentalCapture(ProcessTracker tracker, CaptureSession session)
    {
        _tracker = tracker;
        _session = session;
    }

    public void Start()
    {
        if (_trace is not null) throw new InvalidOperationException("Capture already started.");

        // Unique private-kernel-session name (any name other than
        // KernelTraceEventParser.KernelSessionName triggers the
        // private-session mechanism). The 32-char limit on ETW session
        // names plus our 17-char prefix leaves 15 for the GUID fragment.
        var sessionName = "ETDuckyProcDelta_" + Guid.NewGuid().ToString("N").Substring(0, 14);

        try { TraceEventSession.GetActiveSession(sessionName)?.Dispose(); }
        catch { /* best effort */ }

        _cts = new CancellationTokenSource();
        _trace = new TraceEventSession(sessionName) { StopOnDispose = true };

        _trace.EnableKernelProvider(
            KernelTraceEventParser.Keywords.Process       // tracker spawn/exit
          | KernelTraceEventParser.Keywords.FileIOInit    // Create/Delete Init (paths + IrpPtr)
          | KernelTraceEventParser.Keywords.FileIO        // OperationEnd (IrpPtr + NTSTATUS)
          | KernelTraceEventParser.Keywords.Registry      // every registry op with status
          | KernelTraceEventParser.Keywords.NetworkTCPIP  // TCP connect
        );

        WireCallbacks(_trace.Source.Kernel);

        _processTask = Task.Run(() =>
        {
            try { _trace.Source.Process(); }
            catch { /* expected on dispose */ }
        });
    }

    public async Task StopAsync()
    {
        if (_trace is null) return;

        _session.StoppedAtUtc = DateTime.UtcNow;
        try { _cts?.Cancel(); } catch { }
        try { _trace.Source.StopProcessing(); } catch { }

        if (_processTask is not null)
            await Task.WhenAny(_processTask, Task.Delay(TimeSpan.FromSeconds(2)));

        try { _trace.Dispose(); } catch { }
        _trace = null;
        _processTask = null;
        _cts?.Dispose();
        _cts = null;
    }

    public void Dispose()
    {
        try { _trace?.Dispose(); } catch { }
        _trace = null;
    }

    private void WireCallbacks(KernelTraceEventParser kernel)
    {
        // Process lifetime — feeds the tracker so it picks up children
        // of already-matched processes. The tracker is the gate; only
        // events whose PID is currently tracked make it into the session.
        kernel.ProcessStart += data =>
        {
            _tracker.OnProcessStart(data.ProcessID, data.ParentID, data.ImageFileName);
            if (_tracker.IsTracked(data.ProcessID))
            {
                AppendIfTracked(new EnvironmentalAccess
                {
                    Kind         = AccessKind.Process,
                    Target       = data.ImageFileName ?? string.Empty,
                    Operation    = "Start",
                    Result       = "SUCCESS",
                    Detail       = $"parent PID {data.ParentID}",
                    ProcessId    = data.ProcessID,
                    ProcessImage = _tracker.ImageNameFor(data.ProcessID),
                    TimestampUtc = data.TimeStamp.ToUniversalTime(),
                });
                _session.MatchedPids.Add(data.ProcessID);
            }
        };

        kernel.ProcessStop += data =>
        {
            if (_tracker.IsTracked(data.ProcessID))
            {
                AppendIfTracked(new EnvironmentalAccess
                {
                    Kind         = AccessKind.Process,
                    Target       = data.ImageFileName ?? string.Empty,
                    Operation    = "Stop",
                    Result       = $"ExitCode={data.ExitStatus}",
                    Detail       = string.Empty,
                    ProcessId    = data.ProcessID,
                    ProcessImage = _tracker.ImageNameFor(data.ProcessID),
                    TimestampUtc = data.TimeStamp.ToUniversalTime(),
                });
            }
            _tracker.OnProcessStop(data.ProcessID);
        };

        // Registry — Status is non-zero on failure.
        kernel.RegistryQueryValue  += d => RecordRegistry(d, "QueryValue");
        kernel.RegistrySetValue    += d => RecordRegistry(d, "SetValue");
        kernel.RegistryOpen        += d => RecordRegistry(d, "OpenKey");
        kernel.RegistryCreate      += d => RecordRegistry(d, "CreateKey");
        kernel.RegistryDelete      += d => RecordRegistry(d, "DeleteKey");
        kernel.RegistryDeleteValue += d => RecordRegistry(d, "DeleteValue");

        // File I/O — Init events carry the path + IRP, OperationEnd
        // carries the NTSTATUS. Same IRP links the pair.
        kernel.FileIOCreate += data =>
        {
            if (!_tracker.IsTracked(data.ProcessID)) return;
            _pendingFileOps[unchecked((ulong)(long)data.IrpPtr)] = new PendingFileOp(
                Operation:     "Create",
                FileName:      data.FileName ?? string.Empty,
                ProcessId:     data.ProcessID,
                TimestampUtc:  data.TimeStamp.ToUniversalTime(),
                CreateOptions: unchecked((uint)data.CreateOptions));
        };

        kernel.FileIODelete += data =>
        {
            if (!_tracker.IsTracked(data.ProcessID)) return;
            _pendingFileOps[unchecked((ulong)(long)data.IrpPtr)] = new PendingFileOp(
                Operation:     "Delete",
                FileName:      data.FileName ?? string.Empty,
                ProcessId:     data.ProcessID,
                TimestampUtc:  data.TimeStamp.ToUniversalTime(),
                CreateOptions: 0);
        };

        kernel.FileIOOperationEnd += data =>
        {
            var key = unchecked((ulong)(long)data.IrpPtr);
            if (!_pendingFileOps.TryRemove(key, out var pending)) return;

            var image = _tracker.ImageNameFor(pending.ProcessId);
            AppendIfTracked(new EnvironmentalAccess
            {
                Kind         = AccessKind.File,
                Target       = PathNormalizer.Normalize(pending.FileName),
                Operation    = pending.Operation,
                Result       = NtStatusName(data.NtStatus),
                Detail       = pending.CreateOptions != 0 ? $"options=0x{pending.CreateOptions:X}" : string.Empty,
                ProcessId    = pending.ProcessId,
                ProcessImage = image,
                TimestampUtc = pending.TimestampUtc,
            });
        };

        // Network — TCP connect successes (both IPv4 and IPv6).
        kernel.TcpIpConnect += data =>
        {
            if (!_tracker.IsTracked(data.ProcessID)) return;
            AppendIfTracked(new EnvironmentalAccess
            {
                Kind         = AccessKind.Network,
                Target       = FormatEndpoint(data.daddr, data.dport),
                Operation    = "Connect",
                Result       = "SUCCESS",
                Detail       = $"src={FormatEndpoint(data.saddr, data.sport)}",
                ProcessId    = data.ProcessID,
                ProcessImage = _tracker.ImageNameFor(data.ProcessID),
                TimestampUtc = data.TimeStamp.ToUniversalTime(),
            });
        };

        kernel.TcpIpConnectIPV6 += data =>
        {
            if (!_tracker.IsTracked(data.ProcessID)) return;
            AppendIfTracked(new EnvironmentalAccess
            {
                Kind         = AccessKind.Network,
                Target       = FormatEndpoint(data.daddr, data.dport),
                Operation    = "Connect",
                Result       = "SUCCESS",
                Detail       = $"src={FormatEndpoint(data.saddr, data.sport)} v6",
                ProcessId    = data.ProcessID,
                ProcessImage = _tracker.ImageNameFor(data.ProcessID),
                TimestampUtc = data.TimeStamp.ToUniversalTime(),
            });
        };
    }

    private void RecordRegistry(RegistryTraceData data, string op)
    {
        if (!_tracker.IsTracked(data.ProcessID)) return;
        var keyName = data.KeyName ?? string.Empty;
        var valueName = data.ValueName ?? string.Empty;
        var success = data.Status == 0;

        AppendIfTracked(new EnvironmentalAccess
        {
            Kind         = AccessKind.Registry,
            Target       = keyName,
            Operation    = op,
            Result       = success ? "SUCCESS" : NtStatusName(data.Status),
            Detail       = valueName,
            ProcessId    = data.ProcessID,
            ProcessImage = _tracker.ImageNameFor(data.ProcessID),
            TimestampUtc = data.TimeStamp.ToUniversalTime(),
        });

        // Hash the value content on first encounter of (key, valueName).
        // Only on success (failed reads have nothing to hash) and only for
        // operations that actually touch a value.
        if (success && !string.IsNullOrEmpty(valueName)
            && (op == "QueryValue" || op == "SetValue"))
        {
            _registryValues.Observe(keyName, valueName);
        }
    }

    private void AppendIfTracked(EnvironmentalAccess access)
    {
        lock (_lock) _session.Accesses.Add(access);
    }

    private static string FormatEndpoint(IPAddress? addr, int port)
    {
        var s = addr?.ToString() ?? "?";
        return s + ":" + port.ToString();
    }

    private static string NtStatusName(int status)
    {
        var u = unchecked((uint)status);
        return u switch
        {
            0u          => "SUCCESS",
            0xC0000022u => "ACCESS_DENIED",
            0xC0000034u => "OBJECT_NAME_NOT_FOUND",
            0xC000003Au => "OBJECT_PATH_NOT_FOUND",
            0xC0000043u => "SHARING_VIOLATION",
            0xC000000Du => "INVALID_PARAMETER",
            0xC000007Bu => "INVALID_IMAGE_FORMAT",
            0xC0000018u => "CONFLICTING_ADDRESSES",
            0xC0000035u => "OBJECT_NAME_COLLISION",
            0xC0000056u => "DELETE_PENDING",
            0xC0000061u => "PRIVILEGE_NOT_HELD",
            0xC0000017u => "NO_MEMORY",
            _ => $"0x{u:X8}",
        };
    }
}
