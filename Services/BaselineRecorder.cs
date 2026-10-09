using ETDucky.ProcDelta.Models;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Converts a <see cref="CaptureSession"/>'s aggregated accesses into the
/// <see cref="Baseline"/> shape that ships to disk. The session aggregates
/// incrementally during capture, so Build is a straight mapping plus
/// registry-hash attachment.
///
/// Entry offsets are measured from the session's first tracked access, not
/// from the operator's Start click, so two recordings line up regardless
/// of how long the operator waited before launching the app.
///
/// Pure function over a thread-safe snapshot of the inputs; safe to call
/// even if a capture were still appending.
/// </summary>
public static class BaselineRecorder
{
    public static Baseline Build(
        CaptureSession session,
        string appName,
        string processPattern,
        string actionDescription,
        RegistryValueCache? registryValues = null,
        bool includeOperator = false)
    {
        var origin = session.FirstEventUtc;

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
                    Results = new Dictionary<string, int>(a.Results, StringComparer.OrdinalIgnoreCase),
                    FirstSeenOffsetMs = OffsetMs(origin, a.FirstTimestampUtc),
                    LastSeenOffsetMs = OffsetMs(origin, a.LastTimestampUtc),
                    Images = a.Images.ToList(),
                    ValueHash = hashed?.Hash,
                    ValueType = hashed?.TypeName,
                };
            })
            .OrderBy(e => e.Kind)
            .ThenBy(e => e.Target, StringComparer.OrdinalIgnoreCase)
            .ThenBy(e => e.Operation, StringComparer.OrdinalIgnoreCase)
            .ThenBy(e => e.Detail, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new Baseline
        {
            SchemaVersion = Baseline.CurrentSchemaVersion,
            AppName = appName,
            ProcessPattern = processPattern,
            ActionDescription = actionDescription,
            RecordedAtUtc = session.StartedAtUtc,
            RecordedOn = Environment.MachineName,
            // Off by default: a baseline is a file users are told to share,
            // and the operator's account name is not needed for the diff.
            RecordedBy = includeOperator ? Environment.UserName : string.Empty,
            Duration = session.Duration,
            AppImagePath = session.AppImagePath,
            AppVersion = session.AppVersion,
            OsBuild = HostInfo.OsBuild(),
            TrackedActivitySeconds = session.TrackedActivity.TotalSeconds,
            Entries = entries,
        };
    }

    private static long OffsetMs(DateTime origin, DateTime at)
    {
        var ms = (long)Math.Round((at - origin).TotalMilliseconds);
        return ms < 0 ? 0 : ms;
    }
}
