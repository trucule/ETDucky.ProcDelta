using System;

namespace ETDucky.ProcDelta.Models;

/// <summary>
/// One observed environmental access made by a tracked process during a
/// capture. Polymorphic over the access category — registry, file, network,
/// process — via the discriminator <see cref="Kind"/>. Pure DTO; the
/// recorder and diff engine both work against this single shape.
///
/// Fields are intentionally string-typed (rather than typed accessors per
/// kind) so the JSON serialization stays uniform and old baselines remain
/// readable when new kinds are added.
/// </summary>
public sealed class EnvironmentalAccess
{
    public AccessKind Kind { get; init; }

    /// <summary>
    /// The thing being accessed. Registry: full key path
    /// (HKEY_..\\Software\\…). File: full path with profile-relative segments
    /// already normalized. Network: "host:port". Process: image file path.
    /// </summary>
    public string Target { get; init; } = string.Empty;

    /// <summary>
    /// The operation. Registry: QueryValue / SetValue / OpenKey / CreateKey /
    /// DeleteKey / DeleteValue. File: Create / Read / Write / Delete /
    /// SetInfo. Network: Connect / Send / Recv. Process: Start / Stop.
    /// </summary>
    public string Operation { get; init; } = string.Empty;

    /// <summary>
    /// "SUCCESS" or a Win32/NTSTATUS symbolic name when known. The diff
    /// engine compares this string between baseline and live capture, so
    /// consistency matters more than fidelity — anything non-"SUCCESS" is
    /// treated as a failure regardless of the exact code.
    /// </summary>
    public string Result { get; init; } = string.Empty;

    /// <summary>
    /// For registry QueryValue / SetValue: the value name within the key
    /// (or empty for the default value). For file Create: a brief reason
    /// such as "for-write" / "for-read". Empty otherwise.
    /// </summary>
    public string Detail { get; init; } = string.Empty;

    /// <summary>
    /// PID that made the access. Not persisted in baselines (PIDs are
    /// host- and run-specific) but kept on the raw event for attribution
    /// during capture.
    /// </summary>
    public int ProcessId { get; init; }

    /// <summary>
    /// Image file of the process that made the access. Persisted because
    /// it's useful in the diff report ("the child process spawned by the
    /// service is the one that failed").
    /// </summary>
    public string ProcessImage { get; init; } = string.Empty;

    /// <summary>UTC timestamp of the access.</summary>
    public DateTime TimestampUtc { get; init; }
}

/// <summary>Discriminator for <see cref="EnvironmentalAccess.Kind"/>.</summary>
public enum AccessKind
{
    Unknown = 0,
    Registry = 1,
    File = 2,
    Network = 3,
    Process = 4,
}
