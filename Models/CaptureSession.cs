using System;
using System.Collections.Generic;

namespace ETDucky.ProcDelta.Models;

/// <summary>
/// In-memory state of an in-flight or recently-completed capture.
///
/// Thread-safety and memory design: the session OWNS its synchronisation.
/// Both ETW capture pumps (kernel + app-runtime) append through
/// <see cref="Append"/>, and the UI reads through the snapshot accessors —
/// all guarded by one internal lock, so writers can never race each other
/// or a reader. (Previously each capture class had its own private lock
/// around a shared list, which is no locking at all.)
///
/// Accesses are aggregated INCREMENTALLY by (Kind, Target, Operation,
/// Detail) as they arrive, instead of buffering every raw event: memory
/// stays flat on chatty apps (a repeated key updates in place), and the
/// recorder / diff engine consume the aggregate directly. A small ring
/// buffer of the most recent raw events feeds the live-tail UI.
///
/// Not serialized to disk — baselines are the durable artifact.
/// </summary>
public sealed class CaptureSession
{
    private const int TailCapacity = 50;

    private readonly object _sync = new();
    private readonly Dictionary<string, Agg> _aggregates = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<EnvironmentalAccess> _tail = new(TailCapacity);
    private readonly HashSet<int> _matchedPids = new();
    private long _totalEvents;
    private DateTime _lastEventUtc;

    public string ProcessPattern { get; init; } = string.Empty;

    /// <summary>What the operator told the tool they were about to do.</summary>
    public string ActionDescription { get; set; } = string.Empty;

    public DateTime StartedAtUtc { get; init; } = DateTime.UtcNow;
    public DateTime? StoppedAtUtc { get; set; }

    public TimeSpan Duration =>
        (StoppedAtUtc ?? DateTime.UtcNow) - StartedAtUtc;

    /// <summary>Total raw events appended (pre-aggregation).</summary>
    public long TotalEventCount { get { lock (_sync) return _totalEvents; } }

    /// <summary>Number of distinct aggregated (Kind, Target, Op, Detail) rows.</summary>
    public int AggregateCount { get { lock (_sync) return _aggregates.Count; } }

    /// <summary>Timestamp of the most recent appended event (UTC), or StartedAtUtc if none.</summary>
    public DateTime LastEventUtc { get { lock (_sync) return _totalEvents > 0 ? _lastEventUtc : StartedAtUtc; } }

    /// <summary>Number of PIDs that matched the pattern at some point.</summary>
    public int MatchedPidCount { get { lock (_sync) return _matchedPids.Count; } }

    /// <summary>
    /// Composes the aggregation/diff key for an access. The DiffEngine uses
    /// the same composition for baseline entries so the two sides match.
    /// </summary>
    public static string ComposeKey(AccessKind kind, string target, string operation, string detail)
        => $"{(int)kind}|{target}|{operation}|{detail}";

    /// <summary>Thread-safe append from any capture pump.</summary>
    public void Append(EnvironmentalAccess access)
    {
        var key = ComposeKey(access.Kind, access.Target, access.Operation, access.Detail);
        lock (_sync)
        {
            if (_aggregates.TryGetValue(key, out var agg))
            {
                agg.LastResult       = access.Result;
                agg.LastTimestampUtc = access.TimestampUtc;
                agg.Count++;
            }
            else
            {
                _aggregates[key] = new Agg
                {
                    Kind             = access.Kind,
                    Target           = access.Target,
                    Operation        = access.Operation,
                    Detail           = access.Detail,
                    LastResult       = access.Result,
                    LastTimestampUtc = access.TimestampUtc,
                    Count            = 1,
                };
            }

            _totalEvents++;
            if (access.TimestampUtc > _lastEventUtc) _lastEventUtc = access.TimestampUtc;

            if (_tail.Count == TailCapacity) _tail.Dequeue();
            _tail.Enqueue(access);
        }
    }

    /// <summary>Thread-safe: record a PID that matched the pattern.</summary>
    public void AddMatchedPid(int pid)
    {
        lock (_sync) _matchedPids.Add(pid);
    }

    /// <summary>Snapshot of the most recent raw events (oldest first) for the live-tail UI.</summary>
    public List<EnvironmentalAccess> SnapshotTail()
    {
        lock (_sync) return new List<EnvironmentalAccess>(_tail);
    }

    /// <summary>
    /// Immutable snapshot of the aggregated accesses, for the recorder and
    /// the diff engine. Safe to call while the capture is still appending.
    /// </summary>
    public List<AggregatedAccess> SnapshotAggregates()
    {
        lock (_sync)
        {
            var list = new List<AggregatedAccess>(_aggregates.Count);
            foreach (var a in _aggregates.Values)
            {
                list.Add(new AggregatedAccess(
                    a.Kind, a.Target, a.Operation, a.Detail,
                    a.LastResult, a.LastTimestampUtc, a.Count));
            }
            return list;
        }
    }

    private sealed class Agg
    {
        public AccessKind Kind;
        public string Target = string.Empty;
        public string Operation = string.Empty;
        public string Detail = string.Empty;
        public string LastResult = string.Empty;
        public DateTime LastTimestampUtc;
        public int Count;
    }
}

/// <summary>One aggregated (Kind, Target, Operation, Detail) row snapshot.</summary>
public sealed record AggregatedAccess(
    AccessKind Kind,
    string Target,
    string Operation,
    string Detail,
    string LastResult,
    DateTime LastTimestampUtc,
    int Count);
