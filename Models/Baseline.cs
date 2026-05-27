using System;
using System.Collections.Generic;

namespace ETDucky.ProcDelta.Models;

/// <summary>
/// Serializable record of every environmental access a tracked application
/// made during a "known good" run. Used as the reference state when
/// diagnosing a failing run on a different machine.
///
/// Aggregated, not raw: each unique (Target, Operation, Detail) triple
/// appears once with an access count and the most recent result. Original
/// raw events are dropped after aggregation so the JSON stays small
/// (typically 50-200 KB) and portable.
/// </summary>
public sealed class Baseline
{
    /// <summary>
    /// Schema version of the on-disk format. Increment whenever the shape
    /// of <see cref="Entry"/> or this class changes in a breaking way.
    /// BaselineLoader refuses to load anything other than a recognised
    /// version with a friendly error rather than silently mis-parsing.
    /// </summary>
    public int SchemaVersion { get; init; } = 1;

    /// <summary>
    /// Friendly name for the application this baseline describes
    /// ("Adobe Acrobat", "Outlook", "Teams"). Free-form.
    /// </summary>
    public string AppName { get; init; } = string.Empty;

    /// <summary>
    /// The process-name pattern that was tracked. Either a single
    /// executable name or a pipe-separated list
    /// ("Acrobat.exe|AcroCEF.exe|AdobeCollabSync.exe").
    /// </summary>
    public string ProcessPattern { get; init; } = string.Empty;

    /// <summary>
    /// What the recorder did during the capture. Free-form prose
    /// ("Launched Acrobat, signed in to Document Cloud, synced one PDF").
    /// Reproduced verbatim in the diagnosis report.
    /// </summary>
    public string ActionDescription { get; init; } = string.Empty;

    /// <summary>UTC time the recording started.</summary>
    public DateTime RecordedAtUtc { get; init; }

    /// <summary>Hostname of the machine the recording was made on.</summary>
    public string RecordedOn { get; init; } = string.Empty;

    /// <summary>Username of the operator who made the recording.</summary>
    public string RecordedBy { get; init; } = string.Empty;

    /// <summary>Wall-clock duration of the recording.</summary>
    public TimeSpan Duration { get; init; }

    /// <summary>
    /// Every unique (Target, Operation, Detail) triple observed during the
    /// recording, with its most recent result and the number of times it
    /// fired. Ordered by category then target for diff-friendly JSON.
    /// </summary>
    public List<Entry> Entries { get; init; } = new();

    /// <summary>One aggregated row in the baseline.</summary>
    public sealed class Entry
    {
        public AccessKind Kind { get; init; }
        public string Target { get; init; } = string.Empty;
        public string Operation { get; init; } = string.Empty;
        public string Detail { get; init; } = string.Empty;
        public string Result { get; init; } = string.Empty;

        /// <summary>How many times the access fired during the run.</summary>
        public int AccessCount { get; init; }

        /// <summary>
        /// For registry SetValue with a captured value: hex SHA-256 of the
        /// raw value bytes. The value itself is deliberately not stored —
        /// the hash is enough to detect drift between machines without
        /// shipping potentially-sensitive content.
        /// </summary>
        public string? ValueHash { get; init; }

        /// <summary>
        /// For registry SetValue: the value's REG_* type name. Drift on
        /// type alone is sometimes meaningful (REG_SZ → REG_EXPAND_SZ).
        /// </summary>
        public string? ValueType { get; init; }
    }
}
