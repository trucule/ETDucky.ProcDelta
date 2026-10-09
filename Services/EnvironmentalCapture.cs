using System.Collections.Concurrent;
using System.Net;
using ETDucky.ProcDelta.Models;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using System.Globalization;

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
    /// <summary>
    /// Common prefix for every session this tool creates (kernel and
    /// app-runtime). Used by <see cref="CleanupOrphanedSessions"/> to
    /// reclaim slots left behind by a crashed run.
    /// </summary>
    public const string SessionNamePrefix = "ETDuckyProcDelta";

    /// <summary>
    /// Kernel buffer pool. FileIO OperationEnd is system-wide volume (every
    /// I/O completion on the box reaches user mode before the PID gate), so
    /// the pool is sized for a busy host rather than TraceEvent's default.
    /// </summary>
    public const int KernelBufferSizeMB = 128;

    private readonly ProcessTracker _tracker;
    private readonly CaptureSession _session;
    private readonly RegistryValueCache? _registryValues;
    private TraceEventSession? _trace;
    private Task? _processTask;
    private volatile bool _stopping;
    private int _eventsLostAtStop;

    /// <summary>
    /// Raised (from a background thread) when the event pump dies while a
    /// capture is supposed to be running — parser fault, session torn down
    /// externally (logman stop), etc. Without this the UI would keep
    /// showing "Running…" while nothing is being recorded.
    /// </summary>
    public event Action<string>? Faulted;

    /// <summary>
    /// Events the kernel session has reported dropped (buffers full). Live
    /// while the session runs, frozen at stop. Non-zero means the capture is
    /// incomplete; the status line shows it during the run so the operator
    /// knows before they finish reproducing, not after.
    /// </summary>
    public int EventsLost
    {
        get
        {
            var trace = _trace;
            if (trace is null || _stopping) return _eventsLostAtStop;
            try { return trace.EventsLost; } catch { return _eventsLostAtStop; }
        }
    }

    /// <summary>
    /// File-I/O Init events (Create / Delete) carry the path and IRP pointer
    /// but not the result. The matching FileIOOperationEnd event carries the
    /// NTSTATUS but not the path. Same IrpPtr links the pair. This dictionary
    /// holds the Init side while waiting for the End. Swept periodically so
    /// Init events whose End never arrives can't accumulate forever.
    /// </summary>
    private readonly ConcurrentDictionary<ulong, PendingFileOp> _pendingFileOps = new();
    private int _pendingSweepCounter;
    private const int PendingSweepEvery = 4096;
    private static readonly TimeSpan PendingMaxAge = TimeSpan.FromSeconds(30);

    private readonly record struct PendingFileOp(
        string Operation,
        string FileName,
        int ProcessId,
        DateTime TimestampUtc,
        uint CreateOptions);

    /// <summary>
    /// Hashes of registry value contents observed during the capture.
    /// Populated as Query/SetValue events arrive (read-back runs on a
    /// background worker, not the ETW dispatch thread); consumed by
    /// BaselineRecorder during Build to attach ValueHash + ValueType
    /// to the matching entries.
    /// </summary>
    public RegistryValueCache? RegistryValues => _registryValues;

    public EnvironmentalCapture(ProcessTracker tracker, CaptureSession session)
        : this(tracker, session, new RegistryValueCache())
    {
    }

    /// <param name="tracker">Decides which PIDs are recorded.</param>
    /// <param name="session">Receives every kept access.</param>
    /// <param name="registryValues">
    /// Null for replay of a recorded trace: this machine's registry has
    /// nothing to do with the machine the trace came from.
    /// </param>
    public EnvironmentalCapture(ProcessTracker tracker, CaptureSession session, RegistryValueCache? registryValues)
    {
        _tracker = tracker;
        _session = session;
        _registryValues = registryValues;
        _tracker.RootImageResolved += OnRootImageResolved;
    }

    private void OnRootImageResolved(string path, string version)
        => _session.NoteRootImage(PathNormalizer.Normalize(path), version);

    /// <summary>
    /// Run the same callbacks over a recorded .etl file (xperf, PerfView,
    /// wpr) instead of a live session. Returns a session whose timestamps
    /// are the trace's own. The tracker is not seeded from this machine's
    /// processes; the trace's rundown events seed it.
    /// </summary>
    public static CaptureSession Replay(string etlPath, string processPattern, string actionDescription = "")
    {
        using var source = new ETWTraceEventSource(etlPath);
        var session = new CaptureSession
        {
            ProcessPattern = processPattern,
            ActionDescription = actionDescription,
            StartedAtUtc = source.SessionStartTime.ToUniversalTime(),
        };
        var tracker = new ProcessTracker(processPattern, seedFromRunningProcesses: false);
        using var kernel = new EnvironmentalCapture(tracker, session, registryValues: null);
        kernel.WireCallbacks(source);
        AppRuntimeCapture.WireReplay(source, tracker, session);
        source.Process();
        session.StoppedAtUtc = session.StartedAtUtc + source.SessionDuration;
        return session;
    }

    /// <summary>
    /// Stop and remove ETW sessions left running by a previous crashed
    /// instance. Session names are randomised per start, so without this
    /// sweep an orphaned session survives until reboot and permanently
    /// consumes one of the host's 8 kernel-session slots per crash.
    /// Only sessions carrying our prefix are touched — they can only be
    /// strays from this tool.
    /// </summary>
    public static void CleanupOrphanedSessions()
    {
        try
        {
            // If another ProcDelta instance is running it may legitimately
            // own an active session — don't sweep out from under it.
            var me = System.Diagnostics.Process.GetCurrentProcess();
            var others = System.Diagnostics.Process.GetProcessesByName(me.ProcessName);
            var anotherInstance = others.Any(p => p.Id != me.Id);
            foreach (var p in others) { try { p.Dispose(); } catch { } }
            if (anotherInstance) return;
        }
        catch { /* if we can't tell, err on the side of sweeping */ }

        try
        {
            foreach (var name in TraceEventSession.GetActiveSessionNames()
                         .Where(n => n.StartsWith(SessionNamePrefix, StringComparison.OrdinalIgnoreCase))
                         .ToList())
            {
                try
                {
                    using var stray = TraceEventSession.GetActiveSession(name);
                    stray?.Stop(noThrow: true);
                }
                catch { /* best effort per session */ }
            }
        }
        catch { /* best effort overall */ }
    }

    public void Start()
    {
        if (_trace is not null) throw new InvalidOperationException("Capture already started.");

        // Unique private-kernel-session name (any name other than
        // KernelTraceEventParser.KernelSessionName triggers the
        // private-session mechanism). The 32-char limit on ETW session
        // names plus our prefix leaves room for the GUID fragment.
        var sessionName = string.Concat(SessionNamePrefix, "_", Guid.NewGuid().ToString("N").AsSpan(0, 14));

        _stopping = false;
        _eventsLostAtStop = 0;
        _trace = new TraceEventSession(sessionName)
        {
            StopOnDispose = true,
            BufferSizeMB = KernelBufferSizeMB,
        };

        _trace.EnableKernelProvider(
            KernelTraceEventParser.Keywords.Process       // tracker spawn/exit
          | KernelTraceEventParser.Keywords.FileIOInit    // Create/Delete Init (paths + IrpPtr)
          | KernelTraceEventParser.Keywords.FileIO        // OperationEnd (IrpPtr + NTSTATUS)
          | KernelTraceEventParser.Keywords.Registry      // every registry op with status
          | KernelTraceEventParser.Keywords.NetworkTCPIP  // TCP connect + connect failures
        );

        WireCallbacks(_trace.Source);

        _processTask = Task.Run(() =>
        {
            string? fault = null;
            try
            {
                _trace.Source.Process();
                // Process() returned on its own — if we didn't ask it to
                // stop, the session was torn down externally.
                if (!_stopping) fault = "the ETW session stopped unexpectedly (possibly stopped by another tool).";
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

        try { _eventsLostAtStop = _trace.EventsLost; } catch { }
        _stopping = true;
        _session.StoppedAtUtc = DateTime.UtcNow;

        // Session first, consumer second: stopping the session flushes its
        // buffers to the real-time consumer and Process() returns once they
        // are drained. Stopping the consumer first discards whatever ETW had
        // not flushed yet, which is the last second before a crash.
        try { _trace.Stop(noThrow: true); } catch { }
        if (_processTask is not null)
        {
            var finished = await Task.WhenAny(_processTask, Task.Delay(TimeSpan.FromSeconds(10)));
            if (finished != _processTask)
            {
                try { _trace.Source.StopProcessing(); } catch { }
                await Task.WhenAny(_processTask, Task.Delay(TimeSpan.FromSeconds(2)));
            }
        }

        // Let queued registry read-backs finish before the recorder
        // consumes the cache.
        if (_registryValues is not null)
        {
            try { await _registryValues.DrainAsync(TimeSpan.FromSeconds(5)); } catch { }
        }

        // A root resolved before anyone subscribed (seeded at construction)
        // is published here instead.
        if (_tracker.RootImagePath.Length > 0)
            _session.NoteRootImage(PathNormalizer.Normalize(_tracker.RootImagePath), _tracker.RootFileVersion);

        try { _trace.Dispose(); } catch { }
        _trace = null;
        _processTask = null;
    }

    public void Dispose()
    {
        _stopping = true;
        try { _trace?.Dispose(); } catch { }
        _trace = null;
        try { _registryValues?.Dispose(); } catch { }
        _tracker.RootImageResolved -= OnRootImageResolved;
    }

    internal void WireCallbacks(TraceEventSource source)
    {
        var kernel = source.Kernel;
        // Process lifetime — feeds the tracker so it picks up children
        // of already-matched processes. The tracker is the gate; only
        // events whose PID is currently tracked make it into the session.
        kernel.ProcessStart += data =>
        {
            _tracker.OnProcessStart(data.ProcessID, data.ParentID, data.ImageFileName);
            if (_tracker.IsTracked(data.ProcessID))
            {
                // Detail used to carry the parent PID, which differs on every
                // run and turned each process start into a guaranteed false
                // "missing dependency". The parent's image name is what a
                // reader wants, and it goes in the non-key ProcessImage slot.
                _session.Append(new EnvironmentalAccess
                {
                    Kind = AccessKind.Process,
                    Target = data.ImageFileName ?? string.Empty,
                    Operation = "Start",
                    Result = ResultSemantics.Success,
                    Detail = string.Empty,
                    ProcessId = data.ProcessID,
                    ProcessImage = _tracker.KnownImageNameFor(data.ParentID),
                    TimestampUtc = data.TimeStamp.ToUniversalTime(),
                });
                _session.AddMatchedPid(data.ProcessID);
            }
        };

        // Rundown: processes that were already running when the session
        // started. Feeds the tracker (so pre-existing children of a
        // matched process are followed) but records no access row — a
        // DCStart is not an observed action by the app.
        kernel.ProcessDCStart += data =>
        {
            _tracker.OnProcessStart(data.ProcessID, data.ParentID, data.ImageFileName);
            if (_tracker.IsTracked(data.ProcessID))
                _session.AddMatchedPid(data.ProcessID);
        };

        kernel.ProcessStop += data =>
        {
            if (_tracker.IsNameMatched(data.ProcessID))
                _session.NoteRootExit(data.TimeStamp.ToUniversalTime());

            if (_tracker.IsTracked(data.ProcessID))
            {
                _session.Append(new EnvironmentalAccess
                {
                    Kind = AccessKind.Process,
                    Target = data.ImageFileName ?? string.Empty,
                    Operation = "Stop",
                    Result = $"ExitCode={data.ExitStatus}",
                    Detail = string.Empty,
                    ProcessId = data.ProcessID,
                    ProcessImage = _tracker.ImageNameFor(data.ProcessID),
                    TimestampUtc = data.TimeStamp.ToUniversalTime(),
                });
            }
            _tracker.OnProcessStop(data.ProcessID);
        };

        // Registry — Status is non-zero on failure.
        kernel.RegistryQueryValue += d => RecordRegistry(d, "QueryValue");
        kernel.RegistrySetValue += d => RecordRegistry(d, "SetValue");
        kernel.RegistryOpen += d => RecordRegistry(d, "OpenKey");
        kernel.RegistryCreate += d => RecordRegistry(d, "CreateKey");
        kernel.RegistryDelete += d => RecordRegistry(d, "DeleteKey");
        kernel.RegistryDeleteValue += d => RecordRegistry(d, "DeleteValue");

        // File I/O — Init events carry the path + IRP, OperationEnd
        // carries the NTSTATUS. Same IRP links the pair.
        kernel.FileIOCreate += data =>
        {
            if (!_tracker.IsTracked(data.ProcessID)) return;
            _pendingFileOps[unchecked((ulong)(long)data.IrpPtr)] = new PendingFileOp(
                Operation: "Create",
                FileName: data.FileName ?? string.Empty,
                ProcessId: data.ProcessID,
                TimestampUtc: data.TimeStamp.ToUniversalTime(),
                CreateOptions: unchecked((uint)data.CreateOptions));
            SweepPendingIfDue();
        };

        kernel.FileIODelete += data =>
        {
            if (!_tracker.IsTracked(data.ProcessID)) return;
            _pendingFileOps[unchecked((ulong)(long)data.IrpPtr)] = new PendingFileOp(
                Operation: "Delete",
                FileName: data.FileName ?? string.Empty,
                ProcessId: data.ProcessID,
                TimestampUtc: data.TimeStamp.ToUniversalTime(),
                CreateOptions: 0);
            SweepPendingIfDue();
        };

        kernel.FileIOOperationEnd += data =>
        {
            var key = unchecked((ulong)(long)data.IrpPtr);
            if (!_pendingFileOps.TryRemove(key, out var pending)) return;

            var image = _tracker.ImageNameFor(pending.ProcessId);
            _session.Append(new EnvironmentalAccess
            {
                Kind = AccessKind.File,
                Target = PathNormalizer.Normalize(pending.FileName),
                Operation = pending.Operation,
                Result = ResultSemantics.ResultFor(data.NtStatus),
                // CreateOptions deliberately NOT recorded in Detail: Detail
                // participates in the aggregation/diff key, and apps open
                // the same file with varying options across runs — keying
                // on them turns identical file dependencies into spurious
                // "not in baseline" rows.
                Detail = string.Empty,
                ProcessId = pending.ProcessId,
                ProcessImage = image,
                TimestampUtc = pending.TimestampUtc,
            });
        };

        // Network — TCP connects (IPv4 + IPv6). The kernel's Connect
        // events only fire for SUCCESSFUL connections, so per-target
        // failure diagnosis comes from the diff engine's missing-
        // dependency pass (baseline connect present, live absent).
        kernel.TcpIpConnect += data =>
        {
            if (!_tracker.IsTracked(data.ProcessID)) return;
            _session.Append(new EnvironmentalAccess
            {
                Kind = AccessKind.Network,
                Target = FormatEndpoint(data.daddr, data.dport),
                Operation = "Connect",
                Result = "SUCCESS",
                // The source endpoint (ephemeral port!) must not go into
                // Detail — Detail is part of the aggregation/diff key, and
                // an ephemeral port makes every connection a unique row
                // that can never match the baseline.
                Detail = string.Empty,
                ProcessId = data.ProcessID,
                ProcessImage = _tracker.ImageNameFor(data.ProcessID),
                TimestampUtc = data.TimeStamp.ToUniversalTime(),
            });
        };

        kernel.TcpIpConnectIPV6 += data =>
        {
            if (!_tracker.IsTracked(data.ProcessID)) return;
            _session.Append(new EnvironmentalAccess
            {
                Kind = AccessKind.Network,
                Target = FormatEndpoint(data.daddr, data.dport),
                Operation = "Connect",
                Result = "SUCCESS",
                Detail = string.Empty,
                ProcessId = data.ProcessID,
                ProcessImage = _tracker.ImageNameFor(data.ProcessID),
                TimestampUtc = data.TimeStamp.ToUniversalTime(),
            });
        };

        // TCP failure event. It carries only a protocol + failure code (no
        // address, and often no usable PID), so it can't be diffed per
        // target — but its presence during a tracked window is a strong
        // supporting signal alongside a missing-dependency finding.
        kernel.TcpIpFail += data =>
        {
            // Attribute when possible; record unattributed fails too —
            // they are rare, and a connect failure during the capture
            // window is diagnostic even without a PID.
            var tracked = _tracker.IsTracked(data.ProcessID);
            if (!tracked && data.ProcessID > 0) return; // some other app's failure
            _session.Append(new EnvironmentalAccess
            {
                Kind = AccessKind.Network,
                Target = "tcp-connect-failure",
                Operation = "ConnectFail",
                Result = $"FailureCode={data.FailureCode}",
                Detail = $"proto={data.Proto}",
                ProcessId = data.ProcessID,
                ProcessImage = tracked ? _tracker.ImageNameFor(data.ProcessID) : string.Empty,
                TimestampUtc = data.TimeStamp.ToUniversalTime(),
            });
        };
    }

    /// <summary>
    /// Reusable scratch buffer for <see cref="RegistryStatusOf"/>. Safe
    /// without locking: each ETW session dispatches its callbacks on a
    /// single thread, and only the kernel session's callbacks touch this.
    /// </summary>
    private readonly byte[] _regStatusBuf = new byte[4];

    /// <summary>
    /// WORKAROUND for an upstream TraceEvent bug (present in 3.2.4 and
    /// still in perfview main): RegistryTraceData.Status parses the
    /// NTSTATUS with GetInt32At(8) but DISCARDS the value and always
    /// returns 0 — so every registry op would read as SUCCESS and a
    /// registry regression (a headline diagnosis of this tool) could
    /// never fire. Read the NTSTATUS directly from the raw payload
    /// instead: Int32 at offset 8 for V2+ events, the same offset the
    /// broken property intended to use.
    /// </summary>
    private int RegistryStatusOf(RegistryTraceData data)
    {
        try
        {
            if (data.Version < 2 || data.EventDataLength < 12) return 0;
            data.EventData(_regStatusBuf, 0, 8, 4);
            return BitConverter.ToInt32(_regStatusBuf, 0);
        }
        catch { return 0; }
    }

    private void RecordRegistry(RegistryTraceData data, string op)
    {
        if (!_tracker.IsTracked(data.ProcessID)) return;

        // KeyName resolution relies on TraceEvent's KCB map; operations on
        // keys opened before the session started can resolve to an empty
        // name. An empty target can never be matched against a baseline or
        // inspected live, so it would only pollute the aggregate — drop it.
        var keyName = data.KeyName;
        if (string.IsNullOrEmpty(keyName)) return;

        var normalizedKey = PathNormalizer.NormalizeRegistry(keyName);
        var valueName = data.ValueName ?? string.Empty;
        var status = RegistryStatusOf(data);
        var success = ResultSemantics.NtSuccess(status);

        _session.Append(new EnvironmentalAccess
        {
            Kind = AccessKind.Registry,
            Target = normalizedKey,
            Operation = op,
            Result = success ? ResultSemantics.Success : ResultSemantics.NtStatusName(status),
            Detail = valueName,
            ProcessId = data.ProcessID,
            ProcessImage = _tracker.ImageNameFor(data.ProcessID),
            TimestampUtc = data.TimeStamp.ToUniversalTime(),
        });

        // Hash the value content on first encounter of (key, valueName).
        // Only on success (failed reads have nothing to hash) and only for
        // operations that actually touch a value. Keyed by the normalized
        // path — the same form baseline entries carry.
        if (success && _registryValues is not null && !string.IsNullOrEmpty(valueName)
            && (op == "QueryValue" || op == "SetValue"))
        {
            _registryValues.Observe(normalizedKey, valueName);
        }
    }

    /// <summary>
    /// Every <see cref="PendingSweepEvery"/> Init events, evict pending
    /// file ops older than <see cref="PendingMaxAge"/> — their End event
    /// is never coming (dropped, or the IRP completed unobserved), and a
    /// stale entry could otherwise mispair with a reused IRP pointer.
    /// </summary>
    private void SweepPendingIfDue()
    {
        if (Interlocked.Increment(ref _pendingSweepCounter) % PendingSweepEvery != 0) return;

        var cutoff = DateTime.UtcNow - PendingMaxAge;
        foreach (var kv in _pendingFileOps)
        {
            if (kv.Value.TimestampUtc < cutoff)
                _pendingFileOps.TryRemove(kv.Key, out _);
        }
    }

    private static string FormatEndpoint(IPAddress? addr, int port)
    {
        var s = addr?.ToString() ?? "?";
        return s + ":" + port.ToString(CultureInfo.InvariantCulture);
    }
}
