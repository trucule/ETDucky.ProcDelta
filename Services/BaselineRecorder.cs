using System;
using System.Collections.Generic;
using System.Linq;
using ETDucky.ProcDelta.Models;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Reduces a raw <see cref="CaptureSession"/> (every individual access in
/// arrival order, potentially millions of rows on a chatty app) into the
/// aggregated <see cref="Baseline"/> shape that ships to disk.
///
/// Aggregation key: (Kind, Target, Operation, Detail). Multiple firings of
/// the same key collapse to one row with an <c>AccessCount</c> and the
/// LAST observed <c>Result</c> (last-wins, because the most recent state
/// is what compare-mode wants to match against).
///
/// Registry value hashes captured by <see cref="RegistryValueCache"/>
/// during the run are attached to matching entries here.
///
/// Pure function over the inputs.
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
        var grouped = session.Accesses
            .GroupBy(a => new Key(a.Kind, a.Target, a.Operation, a.Detail))
            .Select(g =>
            {
                var k = g.Key;

                HashedValue? hashed = null;
                if (registryValues is not null
                    && k.Kind == AccessKind.Registry
                    && (k.Operation == "QueryValue" || k.Operation == "SetValue")
                    && !string.IsNullOrEmpty(k.Detail))
                {
                    hashed = registryValues.Get(k.Target, k.Detail);
                }

                return new Baseline.Entry
                {
                    Kind        = k.Kind,
                    Target      = k.Target,
                    Operation   = k.Operation,
                    Detail      = k.Detail,
                    Result      = g.Last().Result,
                    AccessCount = g.Count(),
                    ValueHash   = hashed?.Hash,
                    ValueType   = hashed?.TypeName,
                };
            })
            .OrderBy(e => e.Kind)
            .ThenBy(e => e.Target, StringComparer.OrdinalIgnoreCase)
            .ThenBy(e => e.Operation, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new Baseline
        {
            SchemaVersion     = 1,
            AppName           = appName,
            ProcessPattern    = processPattern,
            ActionDescription = actionDescription,
            RecordedAtUtc     = session.StartedAtUtc,
            RecordedOn        = Environment.MachineName,
            RecordedBy        = Environment.UserName,
            Duration          = session.Duration,
            Entries           = grouped,
        };
    }

    private readonly record struct Key(
        AccessKind Kind,
        string Target,
        string Operation,
        string Detail);
}
