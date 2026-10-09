namespace ETDucky.ProcDelta.Models;

/// <summary>
/// Serializable record of every environmental access a tracked application
/// made during a "known good" run. Used as the reference state when
/// diagnosing a failing run on a different machine.
///
/// Aggregated, not raw: each unique (Kind, Target, Operation, Detail)
/// appears once with per-result counts and timing offsets. Original raw
/// events are dropped after aggregation so the JSON stays small (typically
/// 50-200 KB) and portable.
///
/// Schema history:
///   1  Result + AccessCount only. Loaded and upgraded in memory by
///      <see cref="Services.BaselineLoader"/>; never written any more.
///   2  Adds per-result counts, first/last-seen offsets, the images that
///      made each access, and app version / OS build metadata.
/// </summary>
public sealed class Baseline
{
    public const int CurrentSchemaVersion = 2;

    /// <summary>
    /// Schema version of the on-disk format. BaselineLoader refuses to load
    /// anything other than a recognised version with a friendly error rather
    /// than silently mis-parsing.
    /// </summary>
    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    /// <summary>Friendly name for the application ("Adobe Acrobat"). Free-form.</summary>
    public string AppName { get; init; } = string.Empty;

    /// <summary>
    /// The process-name pattern that was tracked. Either a single executable
    /// name or a pipe-separated list ("Acrobat.exe|AcroCEF.exe").
    /// </summary>
    public string ProcessPattern { get; init; } = string.Empty;

    /// <summary>What the recorder did during the capture. Reproduced in the report.</summary>
    public string ActionDescription { get; init; } = string.Empty;

    /// <summary>UTC time the recording started.</summary>
    public DateTime RecordedAtUtc { get; init; }

    /// <summary>Hostname of the machine the recording was made on.</summary>
    public string RecordedOn { get; init; } = string.Empty;

    /// <summary>Username of the operator. Empty unless the operator opted in.</summary>
    public string RecordedBy { get; init; } = string.Empty;

    /// <summary>Wall-clock duration of the recording.</summary>
    public TimeSpan Duration { get; init; }

    /// <summary>
    /// v2. Tokenised path of the first name-matched process image and its
    /// file version. Version drift between two machines is the first
    /// question anyone asks; this puts the answer in the report header.
    /// </summary>
    public string AppImagePath { get; init; } = string.Empty;
    public string AppVersion { get; init; } = string.Empty;

    /// <summary>v2. Windows build of the recording host, e.g. "10.0.26100.1234".</summary>
    public string OsBuild { get; init; } = string.Empty;

    /// <summary>
    /// v2. Seconds from the first tracked access to the last one. Entry
    /// offsets are relative to that first access, not to the operator's
    /// Start click, so two recordings line up regardless of how long the
    /// operator waited before launching the app.
    /// </summary>
    public double TrackedActivitySeconds { get; init; }

    /// <summary>
    /// Every unique (Kind, Target, Operation, Detail) observed during the
    /// recording. Ordered by category then target for diff-friendly JSON.
    /// </summary>
    public List<Entry> Entries { get; init; } = new();

    /// <summary>One aggregated row in the baseline.</summary>
    public sealed class Entry
    {
        public AccessKind Kind { get; init; }
        public string Target { get; init; } = string.Empty;
        public string Operation { get; init; } = string.Empty;
        public string Detail { get; init; } = string.Empty;

        /// <summary>
        /// The most recent result. Kept for readability; classification uses
        /// <see cref="Results"/>, which cannot flip on event ordering.
        /// </summary>
        public string Result { get; init; } = string.Empty;

        /// <summary>How many times the access fired during the run.</summary>
        public int AccessCount { get; init; }

        /// <summary>v2. Count per distinct result string ("SUCCESS": 12, "OBJECT_NAME_NOT_FOUND": 1).</summary>
        public Dictionary<string, int> Results { get; init; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// v2. Milliseconds from the recording's first tracked access to this
        /// entry's first occurrence. -1 when unknown (upgraded v1 baselines).
        /// </summary>
        public long FirstSeenOffsetMs { get; init; } = -1;

        /// <summary>v2. Milliseconds from the first tracked access to this entry's last occurrence; -1 when unknown.</summary>
        public long LastSeenOffsetMs { get; init; } = -1;

        /// <summary>v2. Image file names of the processes that made this access ("AcroCEF.exe").</summary>
        public List<string> Images { get; init; } = new();

        /// <summary>
        /// For registry QueryValue / SetValue with a captured value: "sha256:"
        /// plus lowercase hex of the raw value bytes. The value itself is
        /// deliberately not stored.
        /// </summary>
        public string? ValueHash { get; init; }

        /// <summary>For registry values: the REG_* type name.</summary>
        public string? ValueType { get; init; }
    }
}
