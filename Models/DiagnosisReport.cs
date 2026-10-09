namespace ETDucky.ProcDelta.Models;

/// <summary>
/// Output of the diff engine. A ranked list of <see cref="Candidate"/>s
/// where each candidate is one environmental access that disagreed between
/// the baseline and the live capture, enriched with what the live machine
/// currently shows at that target, plus enough header context for a reader
/// to judge whether the two runs are comparable at all.
///
/// The user-facing surface (the Report tab + Markdown export) is just a
/// rendering of this object.
/// </summary>
public sealed class DiagnosisReport
{
    public string BaselineSource { get; init; } = string.Empty; // path or origin
    public string AppName { get; init; } = string.Empty;
    public string ProcessPattern { get; init; } = string.Empty;
    public string ActionDescription { get; init; } = string.Empty;
    public DateTime GeneratedAtUtc { get; init; } = DateTime.UtcNow;
    public string CaptureHost { get; init; } = string.Empty;
    public string BaselineHost { get; init; } = string.Empty;

    /// <summary>App image path and file version on each side, when known.</summary>
    public string BaselineAppImage { get; init; } = string.Empty;
    public string BaselineAppVersion { get; init; } = string.Empty;
    public string CaptureAppImage { get; init; } = string.Empty;
    public string CaptureAppVersion { get; init; } = string.Empty;

    /// <summary>Windows build on each side, when known.</summary>
    public string BaselineOsBuild { get; init; } = string.Empty;
    public string CaptureOsBuild { get; init; } = string.Empty;

    /// <summary>How long each capture ran for (wall clock).</summary>
    public TimeSpan BaselineDuration { get; init; }
    public TimeSpan CaptureDuration { get; init; }

    /// <summary>Span of tracked activity on each side (first tracked access to last).</summary>
    public TimeSpan BaselineActivity { get; init; }
    public TimeSpan CaptureActivity { get; init; }

    /// <summary>How many distinct (kind, target, op) accesses were observed live.</summary>
    public int CaptureAccessCount { get; init; }

    /// <summary>How many entries the baseline holds, and how many of them this run also made.</summary>
    public int BaselineEntryCount { get; init; }
    public int MatchedEntryCount { get; init; }

    /// <summary>MatchedEntryCount / BaselineEntryCount, 0..1. Below <see cref="LowCoverageThreshold"/> the runs are probably not comparable.</summary>
    public double Coverage => BaselineEntryCount == 0 ? 0 : (double)MatchedEntryCount / BaselineEntryCount;
    public const double LowCoverageThreshold = 0.5;

    /// <summary>
    /// Baseline entries first seen after the point this run reached, which
    /// were therefore not evaluated as missing dependencies. Non-zero means
    /// the live run was shorter than the baseline.
    /// </summary>
    public int SkippedAfterReach { get; init; }

    /// <summary>True when a root (name-matched) process exited during the live capture, which anchors NearExit.</summary>
    public bool RootExitObserved { get; init; }

    /// <summary>Whether the operator allowed TCP probes and network-path checks during enrichment.</summary>
    public bool NetworkProbed { get; init; }

    /// <summary>Whether registry value content was rendered into LiveState lines.</summary>
    public bool RegistryValuesShown { get; init; }

    /// <summary>False for an offline diff of two baselines: no live state was inspected.</summary>
    public bool LiveStateInspected { get; init; } = true;

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

        /// <summary>What the baseline recorded for this access, per result.</summary>
        public Dictionary<string, int> BaselineResults { get; init; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>What the live capture observed, per result.</summary>
        public Dictionary<string, int> CaptureResults { get; init; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Rendered summary of the baseline side ("SUCCESS x12" or "(not in baseline)").</summary>
        public string BaselineResult { get; init; } = string.Empty;

        /// <summary>Rendered summary of the live side.</summary>
        public string CaptureResult { get; init; } = string.Empty;

        /// <summary>Process images that made the access (live side when observed, otherwise baseline side).</summary>
        public List<string> Images { get; init; } = new();

        /// <summary>
        /// What the LiveStateInspector found when it re-read the target
        /// during report generation. Plain-language sentence.
        /// </summary>
        public string LiveState { get; init; } = string.Empty;

        /// <summary>
        /// True when the access happened within two seconds before a root
        /// process of the tracked tree exited. Strong signal that this access
        /// is causally related to the failure. Never set when no root process
        /// exited during the capture.
        /// </summary>
        public bool NearExit { get; init; }

        /// <summary>Milliseconds into the baseline's tracked activity at which this access first appeared; -1 if unknown.</summary>
        public long BaselineFirstSeenMs { get; init; } = -1;
    }

    public enum Severity
    {
        High = 0,    // Succeeded in baseline, never succeeded now. Causal candidate.
        Medium = 1,  // Value drift or missing dependency.
        Low = 2,     // Novel failure not present in baseline; may be unrelated.
        Info = 3,    // Diagnostic context; not a candidate per se.
    }

    public enum Classification
    {
        Regression,         // baseline ever succeeded, live never succeeded
        ValueDrift,         // value present in both, hash differs
        MissingDependency,  // baseline present, live missing entirely
        NovelFailure,       // not in baseline, live never succeeded
    }
}
