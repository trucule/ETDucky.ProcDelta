using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
using ETDucky.ProcDelta.Models;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Compares a live <see cref="CaptureSession"/> against a known-good
/// <see cref="Baseline"/> and produces a ranked <see cref="DiagnosisReport"/>
/// of candidate root causes.
///
/// The diff is deterministic. Classification rules are listed in the README
/// and on the <see cref="DiagnosisReport.Classification"/> enum.
/// </summary>
[SupportedOSPlatform("windows")]
public static class DiffEngine
{
    public static DiagnosisReport Compare(
        Baseline baseline,
        CaptureSession capture,
        string baselineSource)
    {
        var byKey = new Dictionary<string, Baseline.Entry>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in baseline.Entries)
        {
            byKey[ComposeKey(e.Kind, e.Target, e.Operation, e.Detail)] = e;
        }

        var liveAggregated = new Dictionary<string, LiveAgg>(StringComparer.OrdinalIgnoreCase);
        foreach (var a in capture.Accesses)
        {
            var k = ComposeKey(a.Kind, PathOrTarget(a), a.Operation, a.Detail);
            if (liveAggregated.TryGetValue(k, out var agg))
            {
                agg.LastResult    = a.Result;
                agg.LastTimestamp = a.TimestampUtc;
                agg.Count++;
            }
            else
            {
                liveAggregated[k] = new LiveAgg
                {
                    Kind          = a.Kind,
                    Target        = PathOrTarget(a),
                    Operation     = a.Operation,
                    Detail        = a.Detail,
                    LastResult    = a.Result,
                    LastTimestamp = a.TimestampUtc,
                    Count         = 1,
                };
            }
        }

        var lastActivity = capture.Accesses.Count > 0
            ? capture.Accesses.Max(a => a.TimestampUtc)
            : capture.StoppedAtUtc ?? capture.StartedAtUtc;

        var nearExitWindow = TimeSpan.FromSeconds(2);

        var candidates = new List<DiagnosisReport.Candidate>();
        foreach (var (key, live) in liveAggregated)
        {
            byKey.TryGetValue(key, out var baselineEntry);

            var classification = Classify(baselineEntry, live);
            if (classification is null) continue;

            var severity = SeverityFor(classification.Value);
            var nearExit = (lastActivity - live.LastTimestamp) <= nearExitWindow;
            var liveState = LiveStateInspector.Inspect(live.Kind, live.Target, live.Detail);

            candidates.Add(new DiagnosisReport.Candidate
            {
                Severity         = severity,
                Classification   = classification.Value,
                Kind             = live.Kind,
                Target           = live.Target,
                Operation        = live.Operation,
                Detail           = live.Detail,
                BaselineResult   = baselineEntry?.Result ?? "(not in baseline)",
                CaptureResult    = live.LastResult,
                LiveState        = liveState,
                NearExit         = nearExit,
            });
        }

        var ordered = candidates
            .OrderBy(c => (int)c.Severity)
            .ThenByDescending(c => c.NearExit)
            .ThenBy(c => c.Target, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new DiagnosisReport
        {
            BaselineSource     = baselineSource,
            AppName            = baseline.AppName,
            ProcessPattern     = baseline.ProcessPattern,
            CaptureHost        = Environment.MachineName,
            BaselineHost       = baseline.RecordedOn,
            CaptureDuration    = capture.Duration,
            CaptureAccessCount = liveAggregated.Count,
            Candidates         = ordered,
        };
    }

    public static string RenderMarkdown(DiagnosisReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# Diagnosis Report — {report.AppName}");
        sb.AppendLine();
        sb.AppendLine($"- **Process pattern:** `{report.ProcessPattern}`");
        sb.AppendLine($"- **Generated:** {report.GeneratedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"- **Capture host:** {report.CaptureHost}  ·  **Baseline host:** {report.BaselineHost}");
        sb.AppendLine($"- **Baseline source:** `{report.BaselineSource}`");
        sb.AppendLine($"- **Capture duration:** {report.CaptureDuration.TotalSeconds:0.0}s, {report.CaptureAccessCount} distinct accesses observed");
        sb.AppendLine();

        if (report.Candidates.Count == 0)
        {
            sb.AppendLine("No environmental differences from the baseline were detected. " +
                          "Either the recorded baseline matches this host exactly (unusual for a failing run) " +
                          "or the failure isn't observable through the captured ETW providers.");
            return sb.ToString();
        }

        var byCategory = report.Candidates.GroupBy(c => c.Severity).OrderBy(g => (int)g.Key);

        foreach (var group in byCategory)
        {
            sb.AppendLine($"## {group.Key} severity ({group.Count()})");
            sb.AppendLine();
            int idx = 1;
            foreach (var c in group)
            {
                sb.AppendLine($"### {idx}. {ClassificationLabel(c.Classification)} — {c.Kind} `{Truncate(c.Target, 80)}`");
                if (c.NearExit) sb.AppendLine("*Fired within 2 seconds of the tracked process tree's final activity (strong causal signal).*");
                sb.AppendLine();
                sb.AppendLine($"- **Operation:** {c.Operation}{(string.IsNullOrEmpty(c.Detail) ? "" : "  ·  detail: `" + c.Detail + "`")}");
                sb.AppendLine($"- **Baseline observed:** `{c.BaselineResult}`");
                sb.AppendLine($"- **This run observed:** `{c.CaptureResult}`");
                sb.AppendLine($"- **Live state now:** {c.LiveState}");
                sb.AppendLine();
                idx++;
            }
        }

        sb.AppendLine("---");
        sb.AppendLine();
        sb.AppendLine("*Generated by ETDucky.ProcDelta. Deterministic diff against an operator-recorded baseline.*");
        return sb.ToString();
    }

    private static string ComposeKey(AccessKind kind, string target, string op, string detail)
        => $"{(int)kind}|{target}|{op}|{detail}";

    private static string PathOrTarget(EnvironmentalAccess a) => a.Target;

    private static DiagnosisReport.Classification? Classify(Baseline.Entry? baseline, LiveAgg live)
    {
        var liveSuccess = string.Equals(live.LastResult, "SUCCESS", StringComparison.OrdinalIgnoreCase);
        var liveSuccessAlt = live.LastResult.StartsWith("ExitCode=0", StringComparison.OrdinalIgnoreCase);

        if (baseline is null)
        {
            if (liveSuccess || liveSuccessAlt) return null;
            return DiagnosisReport.Classification.NovelFailure;
        }

        var baselineSuccess = string.Equals(baseline.Result, "SUCCESS", StringComparison.OrdinalIgnoreCase)
                           || baseline.Result.StartsWith("ExitCode=0", StringComparison.OrdinalIgnoreCase);

        if (baselineSuccess && !liveSuccess && !liveSuccessAlt)
            return DiagnosisReport.Classification.Regression;

        // Value drift detection. Requires a hashed baseline value, the
        // current access to be value-touching, and a re-hashable live
        // value. HashLiveValue returns null when the value is missing /
        // unreadable / a type we don't hash, in which case we suppress.
        if (!string.IsNullOrEmpty(baseline.ValueHash)
            && baseline.Kind == AccessKind.Registry
            && (baseline.Operation == "QueryValue" || baseline.Operation == "SetValue")
            && !string.IsNullOrEmpty(baseline.Detail))
        {
            var live2 = RegistryValueCache.HashLiveValue(baseline.Target, baseline.Detail);
            if (live2 is not null && !string.Equals(live2.Hash, baseline.ValueHash, StringComparison.OrdinalIgnoreCase))
            {
                return DiagnosisReport.Classification.ValueDrift;
            }
        }

        return null;
    }

    private static DiagnosisReport.Severity SeverityFor(DiagnosisReport.Classification cls)
        => cls switch
        {
            DiagnosisReport.Classification.Regression         => DiagnosisReport.Severity.High,
            DiagnosisReport.Classification.MissingDependency  => DiagnosisReport.Severity.Medium,
            DiagnosisReport.Classification.ValueDrift         => DiagnosisReport.Severity.Medium,
            DiagnosisReport.Classification.NovelFailure       => DiagnosisReport.Severity.Low,
            _                                                 => DiagnosisReport.Severity.Info,
        };

    private static string ClassificationLabel(DiagnosisReport.Classification cls)
        => cls switch
        {
            DiagnosisReport.Classification.Regression         => "Regression vs baseline",
            DiagnosisReport.Classification.MissingDependency  => "Missing dependency",
            DiagnosisReport.Classification.ValueDrift         => "Value drift",
            DiagnosisReport.Classification.NovelFailure       => "Novel failure (not in baseline)",
            _                                                 => cls.ToString(),
        };

    private static string Truncate(string s, int n)
        => s.Length <= n ? s : s.Substring(0, n - 1) + "…";

    private sealed class LiveAgg
    {
        public AccessKind Kind { get; set; }
        public string Target { get; set; } = string.Empty;
        public string Operation { get; set; } = string.Empty;
        public string Detail { get; set; } = string.Empty;
        public string LastResult { get; set; } = string.Empty;
        public DateTime LastTimestamp { get; set; }
        public int Count { get; set; }
    }
}
