using System;
using System.Collections.Generic;

namespace ETDucky.ProcDelta.Models;

/// <summary>
/// In-memory state of an in-flight or recently-completed capture. Holds the
/// raw event list the recorder will aggregate into a <see cref="Baseline"/>
/// (record mode) or that the diff engine will compare against an existing
/// baseline (compare mode).
///
/// Not serialized to disk — baselines are the durable artifact.
/// </summary>
public sealed class CaptureSession
{
    public string ProcessPattern { get; init; } = string.Empty;

    /// <summary>What the operator told the tool they were about to do.</summary>
    public string ActionDescription { get; set; } = string.Empty;

    public DateTime StartedAtUtc { get; init; } = DateTime.UtcNow;
    public DateTime? StoppedAtUtc { get; set; }

    /// <summary>
    /// All observed accesses, in arrival order. Mutable during capture;
    /// snapshot the count via lock when reading from another thread.
    /// </summary>
    public List<EnvironmentalAccess> Accesses { get; } = new();

    /// <summary>
    /// PIDs that matched the pattern at some point during the capture.
    /// Useful for the post-run summary ("captured 3 distinct processes
    /// matching AdobeCollabSync.exe over 12s").
    /// </summary>
    public HashSet<int> MatchedPids { get; } = new();

    public TimeSpan Duration =>
        (StoppedAtUtc ?? DateTime.UtcNow) - StartedAtUtc;
}
