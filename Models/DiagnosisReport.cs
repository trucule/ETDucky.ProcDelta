using System;
using System.Collections.Generic;

namespace ETDucky.ProcDelta.Models;

/// <summary>
/// Output of the diff engine. A ranked list of <see cref="Candidate"/>s
/// where each candidate is one environmental access that disagreed between
/// the baseline and the live capture, enriched with what the live machine
/// currently shows at that target.
///
/// The user-facing surface (the Report tab + Markdown export) is just a
/// rendering of this object.
/// </summary>
public sealed class DiagnosisReport
{
    public string BaselineSource { get; init; } = string.Empty; // path or origin
    public string AppName { get; init; } = string.Empty;
    public string ProcessPattern { get; init; } = string.Empty;
    public DateTime GeneratedAtUtc { get; init; } = DateTime.UtcNow;
    public string CaptureHost { get; init; } = string.Empty;
    public string BaselineHost { get; init; } = string.Empty;

    /// <summary>How long the live capture ran for.</summary>
    public TimeSpan CaptureDuration { get; init; }

    /// <summary>How many distinct (kind, target, op) accesses were observed live.</summary>
    public int CaptureAccessCount { get; init; }

    /// <summary>Ordered worst-first.</summary>
    public List<Candidate> Candidates { get; init; } = new();

    public sealed class Candidate
    {
        public Severity Severity { get; init; }
        public Classification Classification { get; init; }
        public AccessKind Kind { get; init; }
        public string Target { get; init; } = string.Empty;
        public string Operation { get; init; } = string.Empty;
        public string Detail { get; init; } = string.Empty;

        /// <summary>What the baseline recorded for this access.</summary>
        public string BaselineResult { get; init; } = string.Empty;

        /// <summary>What the live capture observed.</summary>
        public string CaptureResult { get; init; } = string.Empty;

        /// <summary>
        /// What the LiveStateInspector found when it re-read the target
        /// during report generation. Plain-language sentence.
        /// </summary>
        public string LiveState { get; init; } = string.Empty;

        /// <summary>
        /// True when the access happened in the final second of capture
        /// before the tracked process tree exited. Strong signal that this
        /// access is causally related to the failure.
        /// </summary>
        public bool NearExit { get; init; }
    }

    public enum Severity
    {
        High = 0,    // SUCCESS in baseline → failure now. Causal candidate.
        Medium = 1,  // Value drift or missing dependency.
        Low = 2,     // Novel failure not present in baseline; may be unrelated.
        Info = 3,    // Diagnostic context; not a candidate per se.
    }

    public enum Classification
    {
        Regression,         // baseline SUCCESS, live non-SUCCESS
        ValueDrift,         // value present in both, hash differs
        MissingDependency,  // baseline present, live missing entirely
        NovelFailure,       // not in baseline, live failed
    }
}
