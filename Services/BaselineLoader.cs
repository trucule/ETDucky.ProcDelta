using System.Text.Json;
using System.Text.Json.Serialization;
using ETDucky.ProcDelta.Models;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// JSON load / save for <see cref="Baseline"/>. Schema-versioned: the
/// loader accepts version 1 (upgraded in memory) and version 2, and refuses
/// anything else with a friendly message rather than silently mis-parsing.
/// Saves always write the current version.
///
/// Indented output so a diff of two baselines in a text editor or Git is
/// reviewable by humans without further tooling.
/// </summary>
public static class BaselineLoader
{
    private static readonly JsonSerializerOptions _opts = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Save to disk. Overwrites without prompting.</summary>
    public static void Save(Baseline baseline, string path)
    {
        var json = JsonSerializer.Serialize(baseline, _opts);
        File.WriteAllText(path, json);
    }

    /// <summary>
    /// Load from disk. Returns null and sets <paramref name="error"/> when
    /// the file is missing, malformed, or has an unsupported schema
    /// version. Version 1 files come back upgraded to the current shape.
    /// </summary>
    public static Baseline? TryLoad(string path, out string error)
    {
        error = string.Empty;
        try
        {
            if (!File.Exists(path))
            {
                error = $"File not found: {path}";
                return null;
            }

            return TryParse(File.ReadAllText(path), out error);
        }
        catch (Exception ex)
        {
            error = $"{ex.GetType().Name}: {ex.Message}";
            return null;
        }
    }

    /// <summary>Parse baseline JSON. Same contract as <see cref="TryLoad"/> without the file I/O.</summary>
    public static Baseline? TryParse(string json, out string error)
    {
        error = string.Empty;
        try
        {
            var baseline = JsonSerializer.Deserialize<Baseline>(json, _opts);
            if (baseline is null)
            {
                error = "File parsed to null. Possibly empty or all-comments.";
                return null;
            }

            switch (baseline.SchemaVersion)
            {
                case 1:
                    return DropStorageArtifacts(Upgrade1To2(baseline));
                case Baseline.CurrentSchemaVersion:
                    return DropStorageArtifacts(baseline);
                default:
                    error = $"Unsupported schema version {baseline.SchemaVersion}. This build understands versions 1 and {Baseline.CurrentSchemaVersion}.";
                    return null;
            }
        }
        catch (JsonException jex)
        {
            error = $"Invalid JSON: {jex.Message}";
            return null;
        }
        catch (Exception ex)
        {
            error = $"{ex.GetType().Name}: {ex.Message}";
            return null;
        }
    }

    /// <summary>
    /// A v1 entry carries only the last result and a count. Treat the count
    /// as that result's count; leave offsets unknown (-1) so the diff
    /// engine does not gate on them.
    /// </summary>
    /// <summary>
    /// Baselines recorded before the capture filtered storage-stack
    /// accesses may carry them; a loaded baseline never does, so they can
    /// not surface as missing dependencies against a current run.
    /// </summary>
    private static Baseline DropStorageArtifacts(Baseline baseline)
    {
        baseline.Entries.RemoveAll(e => StorageArtifacts.IsStorageArtifact(e.Kind, e.Target));
        return baseline;
    }

    private static Baseline Upgrade1To2(Baseline v1)
    {
        var entries = new List<Baseline.Entry>(v1.Entries.Count);
        foreach (var e in v1.Entries)
        {
            var results = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in e.Results) results[kv.Key] = kv.Value;
            if (results.Count == 0 && !string.IsNullOrEmpty(e.Result))
                results[e.Result] = Math.Max(1, e.AccessCount);

            entries.Add(new Baseline.Entry
            {
                Kind = e.Kind,
                Target = e.Target,
                Operation = e.Operation,
                Detail = e.Detail,
                Result = e.Result,
                AccessCount = Math.Max(1, e.AccessCount),
                Results = results,
                FirstSeenOffsetMs = -1,
                LastSeenOffsetMs = -1,
                Images = new List<string>(e.Images),
                ValueHash = e.ValueHash,
                ValueType = e.ValueType,
            });
        }

        return new Baseline
        {
            SchemaVersion = Baseline.CurrentSchemaVersion,
            AppName = v1.AppName,
            ProcessPattern = v1.ProcessPattern,
            ActionDescription = v1.ActionDescription,
            RecordedAtUtc = v1.RecordedAtUtc,
            RecordedOn = v1.RecordedOn,
            RecordedBy = v1.RecordedBy,
            Duration = v1.Duration,
            AppImagePath = v1.AppImagePath,
            AppVersion = v1.AppVersion,
            OsBuild = v1.OsBuild,
            TrackedActivitySeconds = v1.TrackedActivitySeconds,
            Entries = entries,
        };
    }
}
