using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
using System.Threading.Tasks;
using ETDucky.ProcDelta.Models;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Compares a live <see cref="CaptureSession"/> against a known-good
/// <see cref="Baseline"/> and produces a ranked <see cref="DiagnosisReport"/>
/// of candidate root causes.
///
/// The diff runs in BOTH directions:
///   live → baseline: regressions, value drift, novel failures;
///   baseline → live: entries the working machine exercised that this run
///                    never touched at all (missing dependencies) — the
///                    only way an outright-absent access (e.g. a TCP
///                    connect that never succeeded, since the kernel emits
///                    no per-target failure event) can surface.
///
/// Live-state enrichment (registry re-read, file/ACL check, TCP probe) is
/// parallelised — the probes are independent and a serial pass over N
/// unreachable hosts costs N × 3s.
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
            byKey[CaptureSession.ComposeKey(e.Kind, e.Target, e.Operation, e.Detail)] = e;
        }

        var liveAggregates = capture.SnapshotAggregates();
        var liveKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var lastActivity = capture.LastEventUtc;
        var nearExitWindow = TimeSpan.FromSeconds(2);

        // ── Pass 1: live → baseline ─────────────────────────────────────
        var pending = new List<PendingCandidate>();
        foreach (var live in liveAggregates)
        {
            var key = CaptureSession.ComposeKey(live.Kind, live.Target, live.Operation, live.Detail);
            liveKeys.Add(key);

            byKey.TryGetValue(key, out var baselineEntry);

            var classification = Classify(baselineEntry, live);
            if (classification is null) continue;

            pending.Add(new PendingCandidate
            {
                Classification = classification.Value,
                Kind           = live.Kind,
                Target         = live.Target,
                Operation      = live.Operation,
                Detail         = live.Detail,
                BaselineResult = baselineEntry?.Result ?? "(not in baseline)",
                CaptureResult  = live.LastResult,
                NearExit       = (lastActivity - live.LastTimestampUtc) <= nearExitWindow,
            });
        }

        // ── Pass 2: baseline → live (missing dependencies) ──────────────
        // A successful access the working machine made that this run never
        // attempted (or never got far enough to attempt). "Stop" entries
        // are skipped — an unexited process is not a missing dependency.
        foreach (var e in baseline.Entries)
        {
            if (e.Operation == "Stop") continue;
            if (!IsSuccess(e.Result)) continue;

            var key = CaptureSession.ComposeKey(e.Kind, e.Target, e.Operation, e.Detail);
            if (liveKeys.Contains(key)) continue;

            pending.Add(new PendingCandidate
            {
                Classification = DiagnosisReport.Classification.MissingDependency,
                Kind           = e.Kind,
                Target         = e.Target,
                Operation      = e.Operation,
                Detail         = e.Detail,
                BaselineResult = e.Result,
                CaptureResult  = "(not observed in this run)",
                NearExit       = false,
            });
        }

        // ── Enrichment: live state, in parallel ─────────────────────────
        var liveStates = new string[pending.Count];
        Parallel.For(0, pending.Count,
            new ParallelOptions { MaxDegreeOfParallelism = 8 },
            i =>
            {
                var p = pending[i];
                try { liveStates[i] = LiveStateInspector.Inspect(p.Kind, p.Target, p.Detail); }
                catch (Exception ex) { liveStates[i] = $"(live inspection failed: {ex.GetType().Name})"; }
            });

        var candidates = new List<DiagnosisReport.Candidate>(pending.Count);
        for (var i = 0; i < pending.Count; i++)
        {
            var p = pending[i];
            candidates.Add(new DiagnosisReport.Candidate
            {
                Severity       = SeverityFor(p.Classification),
                Classification = p.Classification,
                Kind           = p.Kind,
                Target         = p.Target,
                Operation      = p.Operation,
                Detail         = p.Detail,
                BaselineResult = p.BaselineResult,
                CaptureResult  = p.CaptureResult,
                LiveState      = liveStates[i],
                NearExit       = p.NearExit,
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
            CaptureAccessCount = liveAggregates.Count,
            Candidates         = ordered,
        };
    }

    /// <summary>Markdown rendering, for export / tickets.</summary>
    public static string RenderMarkdown(DiagnosisReport report)
        => Render(report, plain: false);

    /// <summary>
    /// Plain-text rendering for the in-app report panel, which displays
    /// raw text — Markdown syntax characters there are just noise.
    /// </summary>
    public static string RenderPlainText(DiagnosisReport report)
        => Render(report, plain: true);

    private static string Render(DiagnosisReport report, bool plain)
    {
        string B(string s)    => plain ? s : $"**{s}**";
        string Code(string s) => plain ? s : $"`{s}`";

        var sb = new StringBuilder();
        var title = $"Diagnosis Report — {report.AppName}";
        if (plain)
        {
            sb.AppendLine(title);
            sb.AppendLine(new string('=', Math.Min(title.Length, 72)));
        }
        else
        {
            sb.AppendLine($"# {title}");
        }
        sb.AppendLine();
        sb.AppendLine($"- {B("Process pattern:")} {Code(report.ProcessPattern)}");
        sb.AppendLine($"- {B("Generated:")} {report.GeneratedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"- {B("Capture host:")} {report.CaptureHost}  ·  {B("Baseline host:")} {report.BaselineHost}");
        sb.AppendLine($"- {B("Baseline source:")} {Code(report.BaselineSource)}");
        sb.AppendLine($"- {B("Capture duration:")} {report.CaptureDuration.TotalSeconds:0.0}s, {report.CaptureAccessCount} distinct accesses observed");
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
            var heading = $"{group.Key} severity ({group.Count()})";
            if (plain)
            {
                sb.AppendLine(heading);
                sb.AppendLine(new string('-', Math.Min(heading.Length, 72)));
            }
            else
            {
                sb.AppendLine($"## {heading}");
            }
            sb.AppendLine();
            int idx = 1;
            foreach (var c in group)
            {
                var candidateTitle = $"{idx}. {ClassificationLabel(c.Classification)} — {c.Kind} {Code(Truncate(c.Target, 80))}";
                sb.AppendLine(plain ? candidateTitle : $"### {candidateTitle}");
                if (c.NearExit)
                    sb.AppendLine(plain
                        ? "   Fired within 2 seconds of the tracked process tree's final activity (strong causal signal)."
                        : "*Fired within 2 seconds of the tracked process tree's final activity (strong causal signal).*");
                sb.AppendLine();
                sb.AppendLine($"- {B("Operation:")} {c.Operation}{(string.IsNullOrEmpty(c.Detail) ? "" : "  ·  detail: " + Code(c.Detail))}");
                sb.AppendLine($"- {B("Baseline observed:")} {Code(c.BaselineResult)}");
                sb.AppendLine($"- {B("This run observed:")} {Code(c.CaptureResult)}");
                sb.AppendLine($"- {B("Live state now:")} {c.LiveState}");
                sb.AppendLine();
                idx++;
            }
        }

        sb.AppendLine(plain ? new string('-', 40) : "---");
        sb.AppendLine();
        var footer = "Generated by ETDucky.ProcDelta. Deterministic diff against an operator-recorded baseline.";
        sb.AppendLine(plain ? footer : $"*{footer}*");
        return sb.ToString();
    }

    private static bool IsSuccess(string result)
        => string.Equals(result, "SUCCESS", StringComparison.OrdinalIgnoreCase)
        || result.StartsWith("ExitCode=0", StringComparison.OrdinalIgnoreCase);

    private static DiagnosisReport.Classification? Classify(Baseline.Entry? baseline, AggregatedAccess live)
    {
        var liveSuccess = IsSuccess(live.LastResult);

        if (baseline is null)
        {
            if (liveSuccess) return null;
            return DiagnosisReport.Classification.NovelFailure;
        }

        var baselineSuccess = IsSuccess(baseline.Result);

        if (baselineSuccess && !liveSuccess)
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
        => s.Length <= n ? s : s.Substring(0, n) + "…";

    private sealed class PendingCandidate
    {
        public DiagnosisReport.Classification Classification { get; init; }
        public AccessKind Kind { get; init; }
        public string Target { get; init; } = string.Empty;
        public string Operation { get; init; } = string.Empty;
        public string Detail { get; init; } = string.Empty;
        public string BaselineResult { get; init; } = string.Empty;
        public string CaptureResult { get; init; } = string.Empty;
        public bool NearExit { get; init; }
    }
}
