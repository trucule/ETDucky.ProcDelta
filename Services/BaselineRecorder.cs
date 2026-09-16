using ETDucky.ProcDelta.Models;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Converts a <see cref="CaptureSession"/>'s aggregated accesses into the
/// <see cref="Baseline"/> shape that ships to disk. The session aggregates
/// incrementally during capture (by Kind, Target, Operation, Detail with
/// an access count and last-wins result), so Build is a straight mapping
/// plus registry-hash attachment — no million-row GroupBy at save time.
///
/// Registry value hashes captured by <see cref="RegistryValueCache"/>
/// during the run are attached to matching entries here.
///
/// Pure function over a thread-safe snapshot of the inputs — safe to call
/// even if a capture were still appending.
/// </summary>
public static class BaselineRecorder
{
    public static Baseline Build(
        CaptureSession session,
        string appName,
        string processPattern,
        string actionDescription,
        RegistryValueCache? registryValues = null)
    {
        var entries = session.SnapshotAggregates()
            .Select(a =>
            {
                HashedValue? hashed = null;
                if (registryValues is not null
                    && a.Kind == AccessKind.Registry
                    && (a.Operation == "QueryValue" || a.Operation == "SetValue")
                    && !string.IsNullOrEmpty(a.Detail))
                {
                    hashed = registryValues.Get(a.Target, a.Detail);
                }

                return new Baseline.Entry
                {
                    Kind = a.Kind,
                    Target = a.Target,
                    Operation = a.Operation,
                    Detail = a.Detail,
                    Result = a.LastResult,
                    AccessCount = a.Count,
                    ValueHash = hashed?.Hash,
                    ValueType = hashed?.TypeName,
                };
            })
            .OrderBy(e => e.Kind)
            .ThenBy(e => e.Target, StringComparer.OrdinalIgnoreCase)
            .ThenBy(e => e.Operation, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new Baseline
        {
            SchemaVersion = 1,
            AppName = appName,
            ProcessPattern = processPattern,
            ActionDescription = actionDescription,
            RecordedAtUtc = session.StartedAtUtc,
            RecordedOn = Environment.MachineName,
            RecordedBy = Environment.UserName,
            Duration = session.Duration,
            Entries = entries,
        };
    }
}
