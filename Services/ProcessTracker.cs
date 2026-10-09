using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Maintains the live set of "tracked" process IDs based on a name pattern.
/// A PID joins the set when its image filename matches the pattern (a
/// "root"). A PID also joins when its parent PID is already in the set (so
/// a service that spawns children, like Acrobat.exe -> AcroCEF.exe ->
/// AdobeCollabSync.exe, is followed automatically). A PID leaves the set
/// when the process exits.
///
/// The capture loop calls <see cref="OnProcessStart"/> for every kernel
/// ProcessStart AND ProcessDCStart (rundown) event, and
/// <see cref="OnProcessStop"/> for every Stop, and queries
/// <see cref="IsTracked"/> to decide whether to record subsequent
/// registry / file / network accesses by that PID.
///
/// The tracker also remembers every (pid -> parent, name) it has seen,
/// tracked or not, so that when a parent joins the set later (e.g. a
/// rundown event arrives after its child's), the whole known descendant
/// tree cascades in.
///
/// When a root joins, its image path and file version are read off the
/// process (on a worker, a moment later, because the module list is not
/// ready at the instant of the start event) and published through
/// <see cref="RootImageResolved"/> so the baseline can carry the app version.
///
/// Patterns support '*' and '?' wildcards ("Acro*") in addition to exact
/// names; names without wildcards get ".exe" appended when missing.
///
/// Thread-safe: callbacks come in from the ETW reader thread; the UI
/// thread may query <see cref="TrackedCount"/> for status.
/// </summary>
public sealed class ProcessTracker
{
    private readonly HashSet<string> _exactNames;
    private readonly List<Regex> _wildcardPatterns;
    private readonly ConcurrentDictionary<int, TrackedProcess> _tracked = new();

    /// <summary>
    /// Every process seen this session (from seeding, rundown, or live
    /// starts), tracked or not, so late-joining parents can cascade to
    /// already-seen children and so a parent's image name is known.
    /// </summary>
    private readonly ConcurrentDictionary<int, (int ParentPid, string ImageName)> _seen = new();

    /// <summary>
    /// False for ETL replay: the PIDs in the trace belong to another machine
    /// and must never be opened here.
    /// </summary>
    private readonly bool _resolveRootImages;

    private int _rootInfoPublished;

    /// <summary>
    /// Raised once, from a worker thread, with the (full image path, file
    /// version) of the first root process whose module list could be read.
    /// Subscribers that attach after the fact read <see cref="RootImagePath"/>
    /// and <see cref="RootFileVersion"/> instead.
    /// </summary>
    public event Action<string, string>? RootImageResolved;

    /// <summary>Full image path of the first root process, once resolved; empty until then.</summary>
    public string RootImagePath { get; private set; } = string.Empty;

    /// <summary>File version of the first root process image, once resolved; empty until then.</summary>
    public string RootFileVersion { get; private set; } = string.Empty;

    /// <summary>Creates a tracker for a process-name pattern.</summary>
    /// <param name="processPattern">
    /// Pipe-separated list of image file names (basenames, with or without
    /// ".exe"; '*'/'?' wildcards allowed). Case-insensitive.
    /// Example: "AcroCEF.exe|AdobeCollabSync.exe" or "Acro*".
    /// </param>
    /// <param name="seedFromRunningProcesses">
    /// Seed with already-running matches so an app that is already up is
    /// tracked from the first event. False for ETL replay, where the
    /// processes of interest are in the trace, not on this machine.
    /// </param>
    public ProcessTracker(string processPattern, bool seedFromRunningProcesses = true)
    {
        (_exactNames, _wildcardPatterns) = ParsePattern(processPattern);
        _resolveRootImages = seedFromRunningProcesses;
        if (seedFromRunningProcesses) SeedFromRunningProcesses();
    }

    /// <summary>Number of currently-tracked PIDs (for status display).</summary>
    public int TrackedCount => _tracked.Count;

    /// <summary>Snapshot of currently-tracked PIDs (for diagnostics).</summary>
    public IReadOnlyCollection<int> TrackedPids => _tracked.Keys.ToArray();

    /// <summary>
    /// True when <paramref name="pid"/> should be observed. Called once per
    /// kernel access event, so kept lock-free via ConcurrentDictionary.
    /// </summary>
    public bool IsTracked(int pid)
        => pid > 0 && _tracked.ContainsKey(pid);

    /// <summary>True when the PID is tracked because its own name matched the pattern (a root), not through a parent.</summary>
    public bool IsNameMatched(int pid)
        => pid > 0 && _tracked.TryGetValue(pid, out var p) && p.MatchedByName;

    /// <summary>
    /// Image filename (just the basename, e.g. "AcroCEF.exe") of the
    /// tracked PID, or empty if not tracked. Used by the capture path to
    /// stamp every recorded access with its source image.
    /// </summary>
    public string ImageNameFor(int pid)
        => _tracked.TryGetValue(pid, out var p) ? p.ImageName : string.Empty;

    /// <summary>
    /// Image filename of any process this tracker has seen, tracked or not
    /// (explorer.exe launching the app, say). Empty when unknown.
    /// </summary>
    public string KnownImageNameFor(int pid)
    {
        if (pid <= 0) return string.Empty;
        if (_tracked.TryGetValue(pid, out var t)) return t.ImageName;
        return _seen.TryGetValue(pid, out var s) ? s.ImageName : string.Empty;
    }

    /// <summary>
    /// Track a specific PID as a root regardless of the pattern (launch-and-
    /// track). Its known descendants cascade in.
    /// </summary>
    public void TrackPid(int pid, string imageName)
    {
        if (pid <= 0) return;
        var name = string.IsNullOrEmpty(imageName) ? KnownImageNameFor(pid) : imageName;
        _seen.TryGetValue(pid, out var seen);
        _seen[pid] = (seen.ParentPid, name);
        if (_tracked.TryAdd(pid, new TrackedProcess(pid, seen.ParentPid, name, DateTime.UtcNow, true)))
        {
            CascadeKnownChildren(pid);
            PublishRootInfo(pid);
        }
    }

    /// <summary>
    /// Register a process (live start or rundown). Joins the tracked set if
    /// its image matches the pattern or its parent is already tracked; when
    /// it joins, any already-seen descendants cascade in with it.
    /// </summary>
    public void OnProcessStart(int pid, int parentPid, string imagePath)
    {
        if (pid <= 0) return;
        var basename = Path.GetFileName(imagePath ?? string.Empty);
        if (string.IsNullOrEmpty(basename)) return;

        _seen[pid] = (parentPid, basename);

        if (_tracked.ContainsKey(pid)) return;

        var matchedByName = MatchesPattern(basename);
        var matchedByParent = parentPid > 0 && _tracked.ContainsKey(parentPid);
        if (!matchedByName && !matchedByParent) return;

        _tracked[pid] = new TrackedProcess(pid, parentPid, basename, DateTime.UtcNow, matchedByName);
        CascadeKnownChildren(pid);
        if (matchedByName) PublishRootInfo(pid);
    }

    /// <summary>Remove a PID from the tracked set on process exit.</summary>
    public void OnProcessStop(int pid)
    {
        _tracked.TryRemove(pid, out _);
        _seen.TryRemove(pid, out _);
    }

    private bool MatchesPattern(string basename)
    {
        if (_exactNames.Contains(basename)) return true;
        foreach (var rx in _wildcardPatterns)
        {
            if (rx.IsMatch(basename)) return true;
        }
        return false;
    }

    /// <summary>
    /// After <paramref name="parentPid"/> joins the tracked set, pull in
    /// every already-seen process whose ancestry chains to it. Handles
    /// rundown events arriving in arbitrary order (child before parent).
    /// </summary>
    private void CascadeKnownChildren(int parentPid)
    {
        foreach (var kv in _seen)
        {
            if (kv.Value.ParentPid == parentPid && !_tracked.ContainsKey(kv.Key))
            {
                _tracked[kv.Key] = new TrackedProcess(kv.Key, parentPid, kv.Value.ImageName, DateTime.UtcNow, false);
                CascadeKnownChildren(kv.Key);
            }
        }
    }

    /// <summary>
    /// Seed the tracker with already-running processes that match the
    /// pattern at construction time, so the first accesses by an already-
    /// running matched process aren't dropped while we wait for the kernel
    /// session's rundown (DCStart) events. Children of those processes are
    /// filled in by the DCStart events via the cascade above.
    /// </summary>
    private void SeedFromRunningProcesses()
    {
        Process[] all;
        try { all = Process.GetProcesses(); }
        catch { return; }

        foreach (var p in all)
        {
            try
            {
                var basename = p.ProcessName + ".exe";
                _seen[p.Id] = (0, basename);
                if (MatchesPattern(basename))
                {
                    _tracked[p.Id] = new TrackedProcess(p.Id, 0, basename, DateTime.UtcNow, true);
                    PublishRootInfo(p.Id);
                }
            }
            catch { /* access to a particular process can be denied; skip */ }
            finally { try { p.Dispose(); } catch { } }
        }
    }

    /// <summary>
    /// Read the root's image path and file version off the live process a
    /// moment after it starts. Only the first successful read is published.
    /// Never on the ETW dispatch thread: opening a process and walking its
    /// modules can take tens of milliseconds.
    /// </summary>
    private void PublishRootInfo(int pid)
    {
        if (!_resolveRootImages) return;
        if (Volatile.Read(ref _rootInfoPublished) != 0) return;

        _ = Task.Run(async () =>
        {
            for (var attempt = 0; attempt < 5; attempt++)
            {
                await Task.Delay(attempt == 0 ? 150 : 400).ConfigureAwait(false);
                if (Volatile.Read(ref _rootInfoPublished) != 0) return;

                string? path = null;
                try
                {
                    using var process = Process.GetProcessById(pid);
                    path = process.MainModule?.FileName;
                }
                catch
                {
                    // Not ready yet, exited, or protected. Retry a few times.
                }
                if (string.IsNullOrEmpty(path)) continue;

                var version = string.Empty;
                try { version = FileVersionInfo.GetVersionInfo(path).FileVersion ?? string.Empty; } catch { }

                if (Interlocked.CompareExchange(ref _rootInfoPublished, 1, 0) == 0)
                {
                    RootImagePath = path;
                    RootFileVersion = version;
                    try { RootImageResolved?.Invoke(path, version); } catch { }
                }
                return;
            }
        });
    }

    private static (HashSet<string> Exact, List<Regex> Wildcards) ParsePattern(string pattern)
    {
        var exact = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var wildcards = new List<Regex>();
        if (string.IsNullOrWhiteSpace(pattern)) return (exact, wildcards);

        foreach (var raw in pattern.Split('|', StringSplitOptions.RemoveEmptyEntries))
        {
            var name = raw.Trim();
            if (name.Length == 0) continue;

            if (name.Contains('*') || name.Contains('?'))
            {
                // Wildcard entry -> anchored, case-insensitive regex.
                // "Acro*" matches "Acrobat.exe" without needing ".exe"
                // appended (the trailing * covers it).
                var rx = "^" + Regex.Escape(name).Replace(@"\*", ".*").Replace(@"\?", ".") + "$";
                try { wildcards.Add(new Regex(rx, RegexOptions.IgnoreCase | RegexOptions.Compiled)); }
                catch { /* unparseable pattern segment; skip */ }
            }
            else
            {
                if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) name += ".exe";
                exact.Add(name);
            }
        }
        return (exact, wildcards);
    }

    private sealed record TrackedProcess(
        int Pid,
        int ParentPid,
        string ImageName,
        DateTime FirstSeenUtc,
        bool MatchedByName);
}
