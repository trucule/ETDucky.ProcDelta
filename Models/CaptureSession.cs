using ETDucky.ProcDelta.Services;

namespace ETDucky.ProcDelta.Models;

/// <summary>
/// In-memory state of an in-flight or recently-completed capture.
///
/// Thread-safety and memory design: the session OWNS its synchronisation.
/// Both ETW capture pumps (kernel + app-runtime) append through
/// <see cref="Append"/>, and the UI reads through the snapshot accessors,
/// all guarded by one internal lock, so writers can never race each other
/// or a reader.
///
/// Accesses are aggregated INCREMENTALLY by (Kind, Target, Operation,
/// Detail) as they arrive, instead of buffering every raw event: memory
/// stays flat on chatty apps. Each aggregate keeps a count per distinct
/// result (so classification cannot flip on event ordering), first and
/// last timestamps (so the diff knows how far a run got), and the set of
/// process images that made the access. A small ring buffer of the most
/// recent raw events feeds the live-tail UI.
///
/// Network targets are recorded as ip:port during capture and rewritten
/// to host:port at snapshot time through <see cref="Dns"/>, because the
/// DNS answer and the TCP connect arrive on two independent ETW sessions
/// and the answer is not guaranteed to be delivered first.
///
/// Not serialized to disk; baselines are the durable artifact.
/// </summary>
public sealed class CaptureSession
{
    private const int TailCapacity = 50;

    private readonly object _sync = new();
    private readonly Dictionary<string, Agg> _aggregates = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<EnvironmentalAccess> _tail = new(TailCapacity);
    private readonly HashSet<int> _matchedPids = new();
    private long _totalEvents;
    private DateTime _firstEventUtc;
    private DateTime _lastEventUtc;
    private DateTime? _lastRootExitUtc;
    private string _appImagePath = string.Empty;
    private string _appVersion = string.Empty;

    public string ProcessPattern { get; init; } = string.Empty;

    /// <summary>What the operator told the tool they were about to do.</summary>
    public string ActionDescription { get; set; } = string.Empty;

    public DateTime StartedAtUtc { get; init; } = DateTime.UtcNow;
    public DateTime? StoppedAtUtc { get; set; }

    public TimeSpan Duration =>
        (StoppedAtUtc ?? DateTime.UtcNow) - StartedAtUtc;

    /// <summary>DNS answers seen during the capture. Populated by the app-runtime pump.</summary>
    public DnsCache Dns { get; } = new();

    /// <summary>Total raw events appended (pre-aggregation).</summary>
    public long TotalEventCount { get { lock (_sync) return _totalEvents; } }

    /// <summary>Number of distinct aggregated (Kind, Target, Op, Detail) rows.</summary>
    public int AggregateCount { get { lock (_sync) return _aggregates.Count; } }

    /// <summary>Timestamp of the first tracked event (UTC), or StartedAtUtc if none.</summary>
    public DateTime FirstEventUtc { get { lock (_sync) return _totalEvents > 0 ? _firstEventUtc : StartedAtUtc; } }

    /// <summary>Timestamp of the most recent tracked event (UTC), or StartedAtUtc if none.</summary>
    public DateTime LastEventUtc { get { lock (_sync) return _totalEvents > 0 ? _lastEventUtc : StartedAtUtc; } }

    /// <summary>Span from the first tracked event to the last; zero when nothing was captured.</summary>
    public TimeSpan TrackedActivity
    {
        get { lock (_sync) return _totalEvents > 0 ? _lastEventUtc - _firstEventUtc : TimeSpan.Zero; }
    }

    /// <summary>
    /// Exit time of the last name-matched (root) process, when one exited
    /// during the capture. Null means no root process exited, so "near
    /// exit" has no anchor and is not claimed.
    /// </summary>
    public DateTime? LastRootExitUtc { get { lock (_sync) return _lastRootExitUtc; } }

    /// <summary>Tokenised image path of the first root process, when known.</summary>
    public string AppImagePath { get { lock (_sync) return _appImagePath; } }

    /// <summary>File version of the first root process image, when known.</summary>
    public string AppVersion { get { lock (_sync) return _appVersion; } }

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
            if (!_aggregates.TryGetValue(key, out var agg))
            {
                agg = new Agg(access.Kind, access.Target, access.Operation, access.Detail, access.TimestampUtc);
                _aggregates[key] = agg;
            }
            agg.Observe(access.Result, access.TimestampUtc, access.ProcessImage);

            if (_totalEvents == 0 || access.TimestampUtc < _firstEventUtc) _firstEventUtc = access.TimestampUtc;
            if (access.TimestampUtc > _lastEventUtc) _lastEventUtc = access.TimestampUtc;
            _totalEvents++;

            if (_tail.Count == TailCapacity) _tail.Dequeue();
            _tail.Enqueue(access);
        }
    }

    /// <summary>Thread-safe: record a PID that matched the pattern.</summary>
    public void AddMatchedPid(int pid)
    {
        lock (_sync) _matchedPids.Add(pid);
    }

    /// <summary>A name-matched (root) process exited at <paramref name="utc"/>.</summary>
    public void NoteRootExit(DateTime utc)
    {
        lock (_sync)
        {
            if (_lastRootExitUtc is null || utc > _lastRootExitUtc.Value) _lastRootExitUtc = utc;
        }
    }

    /// <summary>Image path and version of a root process. First one wins.</summary>
    public void NoteRootImage(string tokenisedPath, string fileVersion)
    {
        lock (_sync)
        {
            if (_appImagePath.Length > 0) return;
            _appImagePath = tokenisedPath ?? string.Empty;
            _appVersion = fileVersion ?? string.Empty;
        }
    }

    /// <summary>
    /// Populate the aggregates from a saved baseline so it can stand in for
    /// a live capture (offline diff of two baselines). Timestamps are
    /// reconstructed from the entry offsets.
    /// </summary>
    public void ImportBaseline(Baseline baseline)
    {
        lock (_sync)
        {
            var origin = StartedAtUtc;
            foreach (var e in baseline.Entries)
            {
                var key = ComposeKey(e.Kind, e.Target, e.Operation, e.Detail);
                var first = e.FirstSeenOffsetMs >= 0 ? origin.AddMilliseconds(e.FirstSeenOffsetMs) : origin;
                var last = e.LastSeenOffsetMs >= 0 ? origin.AddMilliseconds(e.LastSeenOffsetMs) : first;
                var agg = new Agg(e.Kind, e.Target, e.Operation, e.Detail, first);
                agg.Import(e, first, last);
                _aggregates[key] = agg;

                if (_totalEvents == 0 || first < _firstEventUtc) _firstEventUtc = first;
                if (last > _lastEventUtc) _lastEventUtc = last;
                _totalEvents += Math.Max(1, e.AccessCount);
            }
            if (_appImagePath.Length == 0)
            {
                _appImagePath = baseline.AppImagePath;
                _appVersion = baseline.AppVersion;
            }
            StoppedAtUtc = origin + baseline.Duration;
        }
    }

    /// <summary>Snapshot of the most recent raw events (oldest first) for the live-tail UI.</summary>
    public List<EnvironmentalAccess> SnapshotTail()
    {
        lock (_sync) return new List<EnvironmentalAccess>(_tail);
    }

    /// <summary>
    /// Immutable snapshot of the aggregated accesses, for the recorder and
    /// the diff engine. Safe to call while the capture is still appending.
    /// Network ip:port targets are rewritten to host:port through the DNS
    /// cache, and rows that collapse onto the same key are merged.
    /// </summary>
    public List<AggregatedAccess> SnapshotAggregates()
    {
        lock (_sync)
        {
            var merged = new Dictionary<string, Agg>(_aggregates.Count, StringComparer.OrdinalIgnoreCase);
            foreach (var a in _aggregates.Values)
            {
                var target = a.Kind == AccessKind.Network ? Dns.RewriteEndpoint(a.Target) : a.Target;
                var key = ComposeKey(a.Kind, target, a.Operation, a.Detail);
                if (merged.TryGetValue(key, out var existing))
                {
                    existing.Absorb(a);
                }
                else
                {
                    merged[key] = a.CloneWithTarget(target);
                }
            }

            var list = new List<AggregatedAccess>(merged.Count);
            foreach (var a in merged.Values) list.Add(a.ToRecord());
            return list;
        }
    }

    private sealed class Agg
    {
        public readonly AccessKind Kind;
        public readonly string Target;
        public readonly string Operation;
        public readonly string Detail;
        public readonly Dictionary<string, int> Results = new(StringComparer.OrdinalIgnoreCase);
        public readonly List<string> Images = new();
        public string LastResult = string.Empty;
        public DateTime FirstTimestampUtc;
        public DateTime LastTimestampUtc;
        public int Count;

        public Agg(AccessKind kind, string target, string operation, string detail, DateTime first)
        {
            Kind = kind;
            Target = target;
            Operation = operation;
            Detail = detail;
            FirstTimestampUtc = first;
            LastTimestampUtc = first;
        }

        public void Observe(string result, DateTime utc, string image)
        {
            Results.TryGetValue(result, out var n);
            Results[result] = n + 1;
            Count++;
            if (utc < FirstTimestampUtc) FirstTimestampUtc = utc;
            if (utc >= LastTimestampUtc)
            {
                LastTimestampUtc = utc;
                LastResult = result;
            }
            if (!string.IsNullOrEmpty(image) && !Images.Contains(image, StringComparer.OrdinalIgnoreCase))
                Images.Add(image);
        }

        public void Import(Baseline.Entry e, DateTime first, DateTime last)
        {
            foreach (var kv in e.Results)
            {
                Results.TryGetValue(kv.Key, out var n);
                Results[kv.Key] = n + kv.Value;
            }
            if (Results.Count == 0 && !string.IsNullOrEmpty(e.Result))
                Results[e.Result] = Math.Max(1, e.AccessCount);
            Count = Math.Max(1, e.AccessCount);
            FirstTimestampUtc = first;
            LastTimestampUtc = last;
            LastResult = e.Result;
            foreach (var img in e.Images)
            {
                if (!Images.Contains(img, StringComparer.OrdinalIgnoreCase)) Images.Add(img);
            }
        }

        public void Absorb(Agg other)
        {
            foreach (var kv in other.Results)
            {
                Results.TryGetValue(kv.Key, out var n);
                Results[kv.Key] = n + kv.Value;
            }
            Count += other.Count;
            if (other.FirstTimestampUtc < FirstTimestampUtc) FirstTimestampUtc = other.FirstTimestampUtc;
            if (other.LastTimestampUtc >= LastTimestampUtc)
            {
                LastTimestampUtc = other.LastTimestampUtc;
                LastResult = other.LastResult;
            }
            foreach (var img in other.Images)
            {
                if (!Images.Contains(img, StringComparer.OrdinalIgnoreCase)) Images.Add(img);
            }
        }

        public Agg CloneWithTarget(string target)
        {
            var c = new Agg(Kind, target, Operation, Detail, FirstTimestampUtc)
            {
                LastResult = LastResult,
                LastTimestampUtc = LastTimestampUtc,
                Count = Count,
            };
            foreach (var kv in Results) c.Results[kv.Key] = kv.Value;
            c.Images.AddRange(Images);
            return c;
        }

        public AggregatedAccess ToRecord()
            => new(Kind, Target, Operation, Detail, LastResult, FirstTimestampUtc, LastTimestampUtc, Count,
                   new Dictionary<string, int>(Results, StringComparer.OrdinalIgnoreCase),
                   Images.ToArray());
    }
}

/// <summary>One aggregated (Kind, Target, Operation, Detail) row snapshot.</summary>
public sealed record AggregatedAccess(
    AccessKind Kind,
    string Target,
    string Operation,
    string Detail,
    string LastResult,
    DateTime FirstTimestampUtc,
    DateTime LastTimestampUtc,
    int Count,
    IReadOnlyDictionary<string, int> Results,
    IReadOnlyList<string> Images);
