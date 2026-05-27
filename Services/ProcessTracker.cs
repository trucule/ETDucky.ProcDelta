using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Maintains the live set of "tracked" process IDs based on a name pattern.
/// A PID joins the set when its image filename matches the pattern. A PID
/// also joins when its parent PID is already in the set (so a service that
/// spawns children — like Acrobat.exe → AcroCEF.exe → AdobeCollabSync.exe —
/// is followed automatically). A PID leaves the set when the process exits.
///
/// The capture loop calls <see cref="OnProcessStart"/> for every kernel
/// ProcessStart event and <see cref="OnProcessStop"/> for every Stop, and
/// queries <see cref="IsTracked"/> to decide whether to record subsequent
/// registry / file / network accesses by that PID.
///
/// Thread-safe: callbacks come in from the ETW reader thread; the UI
/// thread may query <see cref="TrackedCount"/> for status.
/// </summary>
public sealed class ProcessTracker
{
    private readonly HashSet<string> _patternImageNames;
    private readonly ConcurrentDictionary<int, TrackedProcess> _tracked = new();

    /// <summary>
    /// Pipe-separated list of image file names (basenames, with or without
    /// ".exe"). Case-insensitive. Example: "AcroCEF.exe|AdobeCollabSync.exe"
    /// or just "outlook" for a single app.
    /// </summary>
    public ProcessTracker(string processPattern)
    {
        _patternImageNames = ParsePattern(processPattern);
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
    /// Register a new process. Joins the tracked set if its image matches
    /// the pattern or its parent is already tracked.
    /// </summary>
    public void OnProcessStart(int pid, int parentPid, string imagePath)
    {
        if (pid <= 0) return;
        var basename = Path.GetFileName(imagePath ?? string.Empty);
        if (string.IsNullOrEmpty(basename)) return;

        var matchedByName = _patternImageNames.Contains(basename);
        var matchedByParent = parentPid > 0 && _tracked.ContainsKey(parentPid);
        if (!matchedByName && !matchedByParent) return;

        _tracked[pid] = new TrackedProcess(pid, parentPid, basename, DateTime.UtcNow, matchedByName);
    }

    /// <summary>Remove a PID from the tracked set on process exit.</summary>
    public void OnProcessStop(int pid)
        => _tracked.TryRemove(pid, out _);

    /// <summary>
    /// Seed the tracker with already-running processes that match the
    /// pattern at construction time. The TraceEvent kernel session's
    /// rundown events would surface running processes too, but seeding
    /// here means the first accesses by an already-running matched
    /// process aren't dropped while we wait for rundown.
    /// </summary>
    private void SeedFromRunningProcesses()
    {
        Process[] all;
        try { all = Process.GetProcesses(); }
        catch { return; }

        try
        {
            foreach (var p in all)
            {
                try
                {
                    var basename = p.ProcessName + ".exe";
                    if (_patternImageNames.Contains(basename))
                    {
                        _tracked[p.Id] = new TrackedProcess(p.Id, 0, basename, DateTime.UtcNow, true);
                    }
                }
                catch { /* access to a particular process can be denied; skip */ }
                finally { try { p.Dispose(); } catch { } }
            }
        }
        finally
        {
            // Process[] from GetProcesses doesn't own the disposable
            // collection itself; individual Dispose() inside the loop is
            // sufficient.
        }

        // Second pass: add children whose parent is now in the tracked set.
        // Approximation — full process-tree reconstruction at seed time
        // would require WMI or a TH32CS_SNAPPROCESS walk. The rundown
        // events from EnableKernelProvider fill in any gaps.
    }

    private static HashSet<string> ParsePattern(string pattern)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(pattern)) return set;
        foreach (var raw in pattern.Split('|', StringSplitOptions.RemoveEmptyEntries))
        {
            var name = raw.Trim();
            if (name.Length == 0) continue;
            if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) name += ".exe";
            set.Add(name);
        }
        return set;
    }

    private sealed record TrackedProcess(
        int Pid,
        int ParentPid,
        string ImageName,
        DateTime FirstSeenUtc,
        bool MatchedByName);
}
