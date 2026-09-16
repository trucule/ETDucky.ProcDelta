using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Maintains the live set of "tracked" process IDs based on a name pattern.
/// A PID joins the set when its image filename matches the pattern. A PID
/// also joins when its parent PID is already in the set (so a service that
/// spawns children — like Acrobat.exe → AcroCEF.exe → AdobeCollabSync.exe —
/// is followed automatically). A PID leaves the set when the process exits.
///
/// The capture loop calls <see cref="OnProcessStart"/> for every kernel
/// ProcessStart AND ProcessDCStart (rundown) event, and
/// <see cref="OnProcessStop"/> for every Stop, and queries
/// <see cref="IsTracked"/> to decide whether to record subsequent
/// registry / file / network accesses by that PID.
///
/// The tracker also remembers every (pid → parent, name) it has seen —
/// tracked or not — so that when a parent joins the set later (e.g. a
/// rundown event arrives after its child's), the whole known descendant
/// tree cascades in. This closes the pre-existing gap where children of
/// an already-running matched process were silently untracked because
/// rundown events were never consumed.
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
    /// already-seen children.
    /// </summary>
    private readonly ConcurrentDictionary<int, (int ParentPid, string ImageName)> _seen = new();

    /// <summary>
    /// Pipe-separated list of image file names (basenames, with or without
    /// ".exe"; '*'/'?' wildcards allowed). Case-insensitive.
    /// Example: "AcroCEF.exe|AdobeCollabSync.exe" or "Acro*".
    /// </summary>
    public ProcessTracker(string processPattern)
    {
        (_exactNames, _wildcardPatterns) = ParsePattern(processPattern);
        SeedFromRunningProcesses();
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

    /// <summary>
    /// Image filename (just the basename, e.g. "AcroCEF.exe") of the
    /// tracked PID, or empty if not tracked. Used by the capture path to
    /// stamp every recorded access with its source image.
    /// </summary>
    public string ImageNameFor(int pid)
        => _tracked.TryGetValue(pid, out var p) ? p.ImageName : string.Empty;

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
    /// filled in by the DCStart events (which the capture now consumes)
    /// via the cascade above.
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
                }
            }
            catch { /* access to a particular process can be denied; skip */ }
            finally { try { p.Dispose(); } catch { } }
        }
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

            if (name.IndexOf('*') >= 0 || name.IndexOf('?') >= 0)
            {
                // Wildcard entry → anchored, case-insensitive regex.
                // "Acro*" matches "Acrobat.exe" without needing ".exe"
                // appended (the trailing * covers it).
                var rx = "^" + Regex.Escape(name).Replace(@"\*", ".*").Replace(@"\?", ".") + "$";
                try { wildcards.Add(new Regex(rx, RegexOptions.IgnoreCase | RegexOptions.Compiled)); }
                catch { /* unparseable pattern segment — skip */ }
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
