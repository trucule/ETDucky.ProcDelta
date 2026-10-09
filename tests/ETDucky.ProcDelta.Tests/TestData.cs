using ETDucky.ProcDelta.Models;

namespace ETDucky.ProcDelta.Tests;

/// <summary>Builders shared by the test classes.</summary>
internal static class TestData
{
    /// <summary>A baseline entry with explicit per-result counts; (SUCCESS, 1) when none are given.</summary>
    public static Baseline.Entry Entry(
        AccessKind kind, string target, string operation, string detail, long firstSeenMs,
        params (string Result, int Count)[] results)
    {
        var dict = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (results.Length == 0) dict["SUCCESS"] = 1;
        foreach (var (r, c) in results) dict[r] = c;
        var total = dict.Values.Sum();
        return new Baseline.Entry
        {
            Kind = kind,
            Target = target,
            Operation = operation,
            Detail = detail,
            Result = dict.Keys.First(),
            AccessCount = total,
            Results = dict,
            FirstSeenOffsetMs = firstSeenMs,
            LastSeenOffsetMs = firstSeenMs,
        };
    }

    /// <summary>A successful File Create entry first seen at <paramref name="firstSeenMs"/>.</summary>
    public static Baseline.Entry File(string target, long firstSeenMs = 0)
        => Entry(AccessKind.File, target, "Create", "", firstSeenMs);

    public static Baseline BaselineWith(params Baseline.Entry[] entries) => new()
    {
        AppName = "App",
        ProcessPattern = "app.exe",
        ActionDescription = "launched it",
        RecordedOn = "GOOD-PC",
        Duration = TimeSpan.FromSeconds(60),
        TrackedActivitySeconds = 50,
        Entries = entries.ToList(),
    };

    public static EnvironmentalAccess Access(
        AccessKind kind, string target, string operation, string result, DateTime at,
        string detail = "", string image = "app.exe", int pid = 100) => new()
    {
        Kind = kind,
        Target = target,
        Operation = operation,
        Result = result,
        Detail = detail,
        ProcessId = pid,
        ProcessImage = image,
        TimestampUtc = at,
    };
}
