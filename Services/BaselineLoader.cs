using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using ETDucky.ProcDelta.Models;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// JSON load / save for <see cref="Baseline"/>. Schema-versioned: the
/// loader refuses to load anything other than known versions with a
/// friendly message rather than silently mis-parsing.
///
/// Indented output so a diff of two baselines in a text editor or
/// Git is reviewable by humans without further tooling.
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
    /// version.
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

            var json = File.ReadAllText(path);
            var baseline = JsonSerializer.Deserialize<Baseline>(json, _opts);
            if (baseline is null)
            {
                error = "File parsed to null — possibly empty or all-comments.";
                return null;
            }

            if (baseline.SchemaVersion != 1)
            {
                error = $"Unsupported schema version {baseline.SchemaVersion}. This build understands version 1 only.";
                return null;
            }

            return baseline;
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
}
