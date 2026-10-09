using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using ETDucky.ProcDelta.Models;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Compares a live <see cref="CaptureSession"/> against a known-good
/// <see cref="Baseline"/> and produces a ranked <see cref="DiagnosisReport"/>
/// of candidate root causes.
///
/// The diff runs in BOTH directions:
///   live to baseline: regressions, value drift, novel failures;
///   baseline to live: entries the working machine exercised that this run
///                     never touched at all (missing dependencies), the
///                     only way an outright-absent access (a TCP connect
///                     that never succeeded, since the kernel emits no
///                     per-target failure event) can surface.
///
/// Classification works on per-result counts, never on whichever result
/// happened to arrive last: "ever succeeded in the baseline, never
/// succeeded here" is a regression; a size probe that failed before the
/// real read succeeded is not.
///
/// The baseline-to-live pass is phase-aware: a baseline access first seen
/// after the point this run reached is not a missing dependency, it is
/// something the run never got to. Those are counted and reported in the
/// header instead of listed.
///
/// Live-state enrichment (registry re-read, file/ACL check, TCP probe) is
/// parallelised and gated by <see cref="InspectOptions"/>.
///
/// The diff is deterministic. Classification rules are listed in the README
/// and on the <see cref="DiagnosisReport.Classification"/> enum.
/// </summary>
[SupportedOSPlatform("windows")]
public static class DiffEngine
{
    public const string OfflineLiveState = "(offline diff, live state not inspected)";

    /// <summary>An access within this window before a root process exit is flagged NearExit.</summary>
    public static readonly TimeSpan NearExitWindow = TimeSpan.FromSeconds(2);

    /// <summary>Slack added to the live run's reach before a baseline access counts as "after the point this run reached".</summary>
    public static readonly TimeSpan ReachGrace = TimeSpan.FromSeconds(2);

    /// <summary>Candidates sharing a parent key, directory or host are rendered as one group from this many members.</summary>
    public const int GroupThreshold = 3;

    private static readonly IReadOnlyDictionary<string, int> NoResults =
        new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

    public static DiagnosisReport Compare(
        Baseline baseline,
        CaptureSession capture,
        string baselineSource,
        InspectOptions? options = null)
        => Compare(baseline, capture, baselineSource, options, ServiceState.Take);

    /// <summary>
    /// <see cref="Compare(Baseline, CaptureSession, string, InspectOptions)"/>
    /// with the service-state probe supplied by the caller.
    /// </summary>
    /// <param name="baseline">The operator-recorded baseline.</param>
    /// <param name="capture">The live run, or a baseline imported into a session for an offline diff.</param>
    /// <param name="baselineSource">Where the baseline came from, for the report header.</param>
    /// <param name="options">Enrichment gates; null means <see cref="InspectOptions.Default"/>.</param>
    /// <param name="serviceState">
    /// How the engine reads a service's state and start type on this host.
    /// The public overload uses the Service Control Manager and the
    /// registry; tests inject an answer. Only consulted when
    /// <see cref="InspectOptions.InspectLive"/> is set.
    /// </param>
    internal static DiagnosisReport Compare(
        Baseline baseline,
        CaptureSession capture,
        string baselineSource,
        InspectOptions? options,
        Func<string, ServiceState.Snapshot> serviceState)
    {
        // A baseline is untrusted input. Without explicit operator consent the
        // enrichment pass makes no network connection and prints no registry
        // value content, whatever targets the file names.
        var inspect = options ?? InspectOptions.Default;

        var byKey = new Dictionary<string, Baseline.Entry>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in baseline.Entries)
        {
            byKey[CaptureSession.ComposeKey(e.Kind, e.Target, e.Operation, e.Detail)] = e;
        }

        var liveAggregates = capture.SnapshotAggregates();
        var liveKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var rootExit = capture.LastRootExitUtc;
        var liveReach = capture.TrackedActivity + ReachGrace;
        var matched = 0;

        // ── Pass 1: live to baseline ────────────────────────────────────
        var pending = new List<PendingCandidate>();
        foreach (var live in liveAggregates)
        {
            var key = CaptureSession.ComposeKey(live.Kind, live.Target, live.Operation, live.Detail);
            liveKeys.Add(key);

            byKey.TryGetValue(key, out var baselineEntry);
            if (baselineEntry is not null) matched++;

            var classification = Classify(baselineEntry, live);
            if (classification is null) continue;

            pending.Add(new PendingCandidate
            {
                Classification = classification.Value,
                Kind = live.Kind,
                Target = live.Target,
                Operation = live.Operation,
                Detail = live.Detail,
                BaselineResults = baselineEntry?.Results ?? NoResults,
                CaptureResults = live.Results,
                Images = live.Images,
                NearExit = IsNearExit(rootExit, live.LastTimestampUtc),
                BaselineFirstSeenMs = baselineEntry?.FirstSeenOffsetMs ?? -1,
            });
        }

        // ── Pass 2: baseline to live (missing dependencies) ─────────────
        // A successful access the working machine made that this run never
        // attempted. "Stop" entries are skipped (an unexited process is not
        // a missing dependency), and so is anything the baseline first saw
        // after the point this run reached.
        //
        // Service lifecycle entries are transitions, recorded system-wide
        // during the window. Only a start can be a dependency. A start the
        // baseline saw is not missing when the service is running now (it
        // was already up, so there was no start to record). When it is not
        // running, the finding is a candidate only if nothing could start
        // it (disabled or not installed); a service that can be started on
        // demand may simply have been started by something unrelated during
        // the baseline window, so that case is informational.
        var skippedAfterReach = 0;
        var servicesAlreadyRunning = new List<string>();
        foreach (var e in baseline.Entries)
        {
            if (e.Operation == "Stop") continue;
            var isService = ServiceState.IsServiceTarget(e.Target);
            if (isService && !ServiceState.IsStartOperation(e.Operation)) continue;
            if (!ResultSemantics.EverSucceeded(e.Results, e.Operation)) continue;

            var key = CaptureSession.ComposeKey(e.Kind, e.Target, e.Operation, e.Detail);
            if (liveKeys.Contains(key)) continue;

            if (e.FirstSeenOffsetMs >= 0 && TimeSpan.FromMilliseconds(e.FirstSeenOffsetMs) > liveReach)
            {
                skippedAfterReach++;
                continue;
            }

            DiagnosisReport.Severity? severityOverride = null;
            if (isService && inspect.InspectLive)
            {
                var name = ServiceState.NameOf(e.Target);
                var snapshot = serviceState(name);
                if (snapshot.Status == ServiceState.Status.Running)
                {
                    if (!servicesAlreadyRunning.Contains(name, StringComparer.OrdinalIgnoreCase))
                        servicesAlreadyRunning.Add(name);
                    continue;
                }
                if (!snapshot.CannotStart) severityOverride = DiagnosisReport.Severity.Info;
            }

            pending.Add(new PendingCandidate
            {
                Classification = DiagnosisReport.Classification.MissingDependency,
                SeverityOverride = severityOverride,
                Kind = e.Kind,
                Target = e.Target,
                Operation = e.Operation,
                Detail = e.Detail,
                BaselineResults = e.Results,
                CaptureResults = NoResults,
                Images = e.Images,
                NearExit = false,
                BaselineFirstSeenMs = e.FirstSeenOffsetMs,
            });
        }

        // ── Enrichment: live state, in parallel ─────────────────────────
        var liveStates = new string[pending.Count];
        if (inspect.InspectLive)
        {
            Parallel.For(0, pending.Count,
                new ParallelOptions { MaxDegreeOfParallelism = 8 },
                i =>
                {
                    var p = pending[i];
                    try { liveStates[i] = LiveStateInspector.Inspect(p.Kind, p.Target, p.Detail, inspect); }
                    catch (Exception ex) { liveStates[i] = $"(live inspection failed: {ex.GetType().Name})"; }
                });
        }
        else
        {
            for (var i = 0; i < liveStates.Length; i++) liveStates[i] = OfflineLiveState;
        }

        var candidates = new List<DiagnosisReport.Candidate>(pending.Count);
        for (var i = 0; i < pending.Count; i++)
        {
            var p = pending[i];
            candidates.Add(new DiagnosisReport.Candidate
            {
                Severity = p.SeverityOverride ?? SeverityFor(p.Classification),
                Classification = p.Classification,
                Kind = p.Kind,
                Target = p.Target,
                Operation = p.Operation,
                Detail = p.Detail,
                BaselineResults = new Dictionary<string, int>(p.BaselineResults, StringComparer.OrdinalIgnoreCase),
                CaptureResults = new Dictionary<string, int>(p.CaptureResults, StringComparer.OrdinalIgnoreCase),
                BaselineResult = p.BaselineResults.Count == 0 ? "(not in baseline)" : ResultSemantics.Describe(p.BaselineResults),
                CaptureResult = p.CaptureResults.Count == 0 ? "(not observed in this run)" : ResultSemantics.Describe(p.CaptureResults),
                Images = p.Images.ToList(),
                LiveState = liveStates[i],
                NearExit = p.NearExit,
                BaselineFirstSeenMs = p.BaselineFirstSeenMs,
            });
        }

        var ordered = candidates
            .OrderBy(c => (int)c.Severity)
            .ThenByDescending(c => c.NearExit)
            .ThenBy(c => c.Target, StringComparer.OrdinalIgnoreCase)
            .ThenBy(c => c.Detail, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new DiagnosisReport
        {
            BaselineSource = baselineSource,
            AppName = baseline.AppName,
            ProcessPattern = baseline.ProcessPattern,
            ActionDescription = baseline.ActionDescription,
            CaptureHost = Environment.MachineName,
            BaselineHost = baseline.RecordedOn,
            BaselineAppImage = baseline.AppImagePath,
            BaselineAppVersion = baseline.AppVersion,
            CaptureAppImage = capture.AppImagePath,
            CaptureAppVersion = capture.AppVersion,
            BaselineOsBuild = baseline.OsBuild,
            CaptureOsBuild = inspect.InspectLive ? HostInfo.OsBuild() : string.Empty,
            BaselineDuration = baseline.Duration,
            CaptureDuration = capture.Duration,
            BaselineActivity = TimeSpan.FromSeconds(baseline.TrackedActivitySeconds),
            CaptureActivity = capture.TrackedActivity,
            CaptureAccessCount = liveAggregates.Count,
            BaselineEntryCount = baseline.Entries.Count,
            MatchedEntryCount = matched,
            SkippedAfterReach = skippedAfterReach,
            ServicesAlreadyRunning = servicesAlreadyRunning,
            RootExitObserved = rootExit.HasValue,
            NetworkProbed = inspect.AllowNetwork,
            RegistryValuesShown = inspect.ShowRegistryValues,
            LiveStateInspected = inspect.InspectLive,
            Candidates = ordered,
        };
    }

    /// <summary>
    /// Diff two baselines without any live inspection: the second baseline
    /// stands in for the live capture. Lets an operator record on both
    /// machines and compare anywhere.
    /// </summary>
    public static DiagnosisReport CompareBaselines(Baseline reference, Baseline against, string referenceSource)
    {
        var session = new CaptureSession
        {
            ProcessPattern = against.ProcessPattern,
            ActionDescription = against.ActionDescription,
            StartedAtUtc = against.RecordedAtUtc,
        };
        session.ImportBaseline(against);

        var report = Compare(reference, session, referenceSource, new InspectOptions(InspectLive: false));
        return new DiagnosisReport
        {
            BaselineSource = report.BaselineSource,
            AppName = report.AppName,
            ProcessPattern = report.ProcessPattern,
            ActionDescription = report.ActionDescription,
            GeneratedAtUtc = report.GeneratedAtUtc,
            CaptureHost = against.RecordedOn,
            BaselineHost = report.BaselineHost,
            BaselineAppImage = report.BaselineAppImage,
            BaselineAppVersion = report.BaselineAppVersion,
            CaptureAppImage = against.AppImagePath,
            CaptureAppVersion = against.AppVersion,
            BaselineOsBuild = report.BaselineOsBuild,
            CaptureOsBuild = against.OsBuild,
            BaselineDuration = report.BaselineDuration,
            CaptureDuration = against.Duration,
            BaselineActivity = report.BaselineActivity,
            CaptureActivity = TimeSpan.FromSeconds(against.TrackedActivitySeconds),
            CaptureAccessCount = report.CaptureAccessCount,
            BaselineEntryCount = report.BaselineEntryCount,
            MatchedEntryCount = report.MatchedEntryCount,
            SkippedAfterReach = report.SkippedAfterReach,
            ServicesAlreadyRunning = report.ServicesAlreadyRunning,
            RootExitObserved = false,
            NetworkProbed = false,
            RegistryValuesShown = false,
            LiveStateInspected = false,
            Candidates = report.Candidates,
        };
    }

    /// <summary>Markdown rendering, for export / tickets.</summary>
    public static string RenderMarkdown(DiagnosisReport report)
        => Render(report, plain: false);

    /// <summary>
    /// Plain-text rendering for the in-app report panel, which displays
    /// raw text; Markdown syntax characters there are just noise.
    /// </summary>
    public static string RenderPlainText(DiagnosisReport report)
        => Render(report, plain: true);

    private static string Render(DiagnosisReport report, bool plain)
    {
        string B(string s) => plain ? s : $"**{s}**";
        string Code(string s) => plain ? s : $"`{s}`";
        string Em(string s) => plain ? s : $"*{s}*";

        var sb = new StringBuilder();
        var title = $"Diagnosis Report: {report.AppName}";
        if (plain)
        {
            sb.AppendLine(title);
            sb.AppendLine(new string('=', Math.Min(title.Length, 72)));
        }
        else
        {
            sb.AppendLine(CultureInfo.InvariantCulture, $"# {title}");
        }
        sb.AppendLine();

        sb.AppendLine(CultureInfo.InvariantCulture, $"- {B("Process pattern:")} {Code(report.ProcessPattern)}");
        if (!string.IsNullOrWhiteSpace(report.ActionDescription))
            sb.AppendLine(CultureInfo.InvariantCulture, $"- {B("Action:")} \"{report.ActionDescription}\"");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- {B("Generated:")} {report.GeneratedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- {B("Capture host:")} {report.CaptureHost}{BuildSuffix(report.CaptureOsBuild)}; {B("Baseline host:")} {report.BaselineHost}{BuildSuffix(report.BaselineOsBuild)}");

        var image = !string.IsNullOrEmpty(report.CaptureAppImage) ? report.CaptureAppImage : report.BaselineAppImage;
        if (!string.IsNullOrEmpty(image))
            sb.AppendLine(CultureInfo.InvariantCulture, $"- {B("App image:")} {Code(image)}");
        if (!string.IsNullOrEmpty(report.BaselineAppVersion) || !string.IsNullOrEmpty(report.CaptureAppVersion))
        {
            var bv = string.IsNullOrEmpty(report.BaselineAppVersion) ? "(unknown)" : report.BaselineAppVersion;
            var cv = string.IsNullOrEmpty(report.CaptureAppVersion) ? "(unknown)" : report.CaptureAppVersion;
            var differs = !string.IsNullOrEmpty(report.BaselineAppVersion)
                       && !string.IsNullOrEmpty(report.CaptureAppVersion)
                       && !string.Equals(report.BaselineAppVersion, report.CaptureAppVersion, StringComparison.OrdinalIgnoreCase);
            sb.AppendLine(CultureInfo.InvariantCulture, $"- {B("App version:")} baseline {bv}; this run {cv}{(differs ? "; " + B("DIFFERS") : string.Empty)}");
        }

        sb.AppendLine(CultureInfo.InvariantCulture, $"- {B("Baseline source:")} {Code(report.BaselineSource)}");
        sb.AppendLine(CultureInfo.InvariantCulture,
            $"- {B("Durations:")} baseline {report.BaselineDuration.TotalSeconds:0.0}s captured, {report.BaselineActivity.TotalSeconds:0.0}s of tracked activity; this run {report.CaptureDuration.TotalSeconds:0.0}s captured, {report.CaptureActivity.TotalSeconds:0.0}s of tracked activity, {report.CaptureAccessCount} distinct accesses");

        var pct = (int)Math.Round(report.Coverage * 100);
        sb.AppendLine(CultureInfo.InvariantCulture,
            $"- {B("Coverage:")} {report.MatchedEntryCount:N0} of {report.BaselineEntryCount:N0} baseline accesses ({pct}%) were also made in this run.");
        if (report.BaselineEntryCount > 0 && report.Coverage < DiagnosisReport.LowCoverageThreshold)
            sb.AppendLine(CultureInfo.InvariantCulture, $"  {B("Low coverage:")} the runs may not be comparable (different action, app version or duration).");
        if (report.SkippedAfterReach > 0)
            sb.AppendLine(CultureInfo.InvariantCulture,
                $"- {B("Not evaluated:")} {report.SkippedAfterReach:N0} baseline accesses were first seen after the point this run reached ({report.CaptureActivity.TotalSeconds:0.0}s of activity) and are not listed as missing.");
        if (report.ServicesAlreadyRunning.Count > 0)
            sb.AppendLine(CultureInfo.InvariantCulture,
                $"- {B("Services already running:")} {string.Join(", ", report.ServicesAlreadyRunning)}. The baseline recorded a start for each; this host had them running before the action, so no start was needed and they are not listed as missing.");

        sb.AppendLine(CultureInfo.InvariantCulture,
            $"- {B("Near-exit marking:")} {(report.RootExitObserved ? "a tracked root process exited during this run; accesses in its final 2 seconds are marked" : "no tracked root process exited during this run; nothing is marked near-exit")}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- {B("Network probing:")} {(report.NetworkProbed ? "enabled (TCP probes and network paths were checked)" : "disabled (TCP probes and network paths were skipped)")}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- {B("Registry values:")} {(report.RegistryValuesShown ? "shown" : "hidden (type, size and SHA-256 only)")}");
        if (!report.LiveStateInspected)
            sb.AppendLine(CultureInfo.InvariantCulture, $"- {B("Live state:")} not inspected (offline diff of two baselines)");
        sb.AppendLine();

        if (report.Candidates.Count == 0)
        {
            sb.AppendLine("No environmental differences from the baseline were detected. " +
                          "Either the recorded baseline matches this host exactly (unusual for a failing run) " +
                          "or the failure isn't observable through the captured ETW providers.");
            return sb.ToString();
        }

        var bySeverity = report.Candidates.GroupBy(c => c.Severity).OrderBy(g => (int)g.Key);

        foreach (var severity in bySeverity)
        {
            var heading = severity.Key == DiagnosisReport.Severity.Info
                ? $"Informational ({severity.Count()})"
                : $"{severity.Key} severity ({severity.Count()})";
            if (plain)
            {
                sb.AppendLine(heading);
                sb.AppendLine(new string('-', Math.Min(heading.Length, 72)));
            }
            else
            {
                sb.AppendLine(CultureInfo.InvariantCulture, $"## {heading}");
            }
            sb.AppendLine();

            var idx = 1;
            foreach (var group in GroupCandidates(severity))
            {
                if (group.Count >= GroupThreshold)
                {
                    RenderGroup(sb, plain, idx, group, Code, Em);
                }
                else
                {
                    foreach (var c in group) RenderCandidate(sb, plain, idx, c, B, Code, Em);
                }
                idx++;
            }
        }

        sb.AppendLine(plain ? new string('-', 40) : "---");
        sb.AppendLine();
        var footer = "Generated by ETDucky.ProcDelta. Deterministic diff against an operator-recorded baseline.";
        sb.AppendLine(plain ? footer : $"*{footer}*");
        return sb.ToString();
    }

    private static string BuildSuffix(string build)
        => string.IsNullOrEmpty(build) ? string.Empty : $" (build {build})";

    /// <summary>
    /// Candidates in rendering order, bucketed by (classification, kind,
    /// parent). Order of first appearance is kept so severity-then-target
    /// ordering survives grouping.
    /// </summary>
    internal static List<List<DiagnosisReport.Candidate>> GroupCandidates(IEnumerable<DiagnosisReport.Candidate> candidates)
    {
        var order = new List<string>();
        var groups = new Dictionary<string, List<DiagnosisReport.Candidate>>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in candidates)
        {
            var key = $"{(int)c.Classification}|{(int)c.Kind}|{GroupKey(c)}";
            if (!groups.TryGetValue(key, out var list))
            {
                list = new List<DiagnosisReport.Candidate>();
                groups[key] = list;
                order.Add(key);
            }
            list.Add(c);
        }
        return order.Select(k => groups[k]).ToList();
    }

    /// <summary>
    /// The "parent" a candidate is grouped under: the key for a registry
    /// value, the parent key for a key-only access, the directory for a
    /// file or image, the host for a network endpoint.
    /// </summary>
    internal static string GroupKey(DiagnosisReport.Candidate c)
    {
        switch (c.Kind)
        {
            case AccessKind.Registry:
                return string.IsNullOrEmpty(c.Detail) ? ParentPath(c.Target) : c.Target;
            case AccessKind.File:
            case AccessKind.Process:
                return ParentPath(c.Target);
            case AccessKind.Network:
                if (c.Target.Contains("://", StringComparison.Ordinal))
                    return Uri.TryCreate(c.Target, UriKind.Absolute, out var uri) ? uri.Host : c.Target;
                var split = c.Target.LastIndexOf(':');
                return split > 0 ? c.Target.Substring(0, split) : c.Target;
            default:
                return c.Target;
        }
    }

    private static string ParentPath(string target)
    {
        var sep = target.LastIndexOf('\\');
        return sep > 0 ? target.Substring(0, sep) : target;
    }

    private static string LeafName(DiagnosisReport.Candidate c)
    {
        if (c.Kind == AccessKind.Registry && !string.IsNullOrEmpty(c.Detail)) return c.Detail;
        var sep = c.Target.LastIndexOf('\\');
        return sep >= 0 && sep < c.Target.Length - 1 ? c.Target.Substring(sep + 1) : c.Target;
    }

    private static void RenderGroup(
        StringBuilder sb, bool plain, int idx, List<DiagnosisReport.Candidate> group,
        Func<string, string> Code, Func<string, string> Em)
    {
        var first = group[0];
        var parent = GroupKey(first);
        var unit = first.Kind == AccessKind.Registry && !string.IsNullOrEmpty(first.Detail) ? "values"
                 : first.Kind == AccessKind.Network ? "endpoints"
                 : "entries";
        var title = $"{idx}. {ClassificationLabel(first.Classification)}: {first.Kind} {Code(Truncate(parent, 80))} ({group.Count} {unit})";
        sb.AppendLine(plain ? title : $"### {title}");
        if (group.Any(c => c.NearExit))
            sb.AppendLine(Em("Includes accesses within 2 seconds of a tracked root process exiting."));
        sb.AppendLine();
        foreach (var c in group.OrderBy(LeafName, StringComparer.OrdinalIgnoreCase))
        {
            var marker = c.NearExit ? " [near exit]" : string.Empty;
            sb.AppendLine(CultureInfo.InvariantCulture,
                $"- {Code(Truncate(LeafName(c), 60))} {c.Operation}{marker}; baseline {c.BaselineResult}; this run {c.CaptureResult}; live: {c.LiveState}");
        }
        sb.AppendLine();
    }

    private static void RenderCandidate(
        StringBuilder sb, bool plain, int idx, DiagnosisReport.Candidate c,
        Func<string, string> B, Func<string, string> Code, Func<string, string> Em)
    {
        var candidateTitle = $"{idx}. {ClassificationLabel(c.Classification)}: {c.Kind} {Code(Truncate(c.Target, 80))}";
        sb.AppendLine(plain ? candidateTitle : $"### {candidateTitle}");
        if (c.NearExit)
            sb.AppendLine(Em("Fired within 2 seconds of a tracked root process exiting (strong causal signal)."));
        if (c.Severity == DiagnosisReport.Severity.Info && ServiceState.IsServiceTarget(c.Target))
            sb.AppendLine(Em("Service starts are recorded system-wide during the capture window, so this start may have been unrelated to the application. The service can be started on demand on this host."));
        sb.AppendLine();
        sb.AppendLine(CultureInfo.InvariantCulture, $"- {B("Operation:")} {c.Operation}{(string.IsNullOrEmpty(c.Detail) ? "" : "; detail: " + Code(c.Detail))}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- {B("Baseline observed:")} {Code(c.BaselineResult)}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- {B("This run observed:")} {Code(c.CaptureResult)}");
        if (c.Images.Count > 0)
            sb.AppendLine(CultureInfo.InvariantCulture, $"- {B("Made by:")} {string.Join(", ", c.Images)}");
        if (c.BaselineFirstSeenMs >= 0)
            sb.AppendLine(CultureInfo.InvariantCulture, $"- {B("First seen in baseline:")} {c.BaselineFirstSeenMs / 1000.0:0.0}s into tracked activity");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- {B("Live state now:")} {c.LiveState}");
        sb.AppendLine();
    }

    private static bool IsNearExit(DateTime? rootExit, DateTime lastAccess)
    {
        if (rootExit is null) return false;
        var delta = rootExit.Value - lastAccess;
        return delta >= TimeSpan.Zero && delta <= NearExitWindow;
    }

    private static DiagnosisReport.Classification? Classify(Baseline.Entry? baseline, AggregatedAccess live)
    {
        var liveSucceeded = ResultSemantics.EverSucceeded(live.Results, live.Operation);

        if (baseline is null)
        {
            return liveSucceeded ? null : DiagnosisReport.Classification.NovelFailure;
        }

        var baselineSucceeded = ResultSemantics.EverSucceeded(baseline.Results, baseline.Operation);

        if (baselineSucceeded && !liveSucceeded)
            return DiagnosisReport.Classification.Regression;

        // Failed on both sides: a stable failure the app tolerates. Or the
        // baseline never succeeded and this run did: not a problem.
        if (!liveSucceeded) return null;

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
            DiagnosisReport.Classification.Regression => DiagnosisReport.Severity.High,
            DiagnosisReport.Classification.MissingDependency => DiagnosisReport.Severity.Medium,
            DiagnosisReport.Classification.ValueDrift => DiagnosisReport.Severity.Medium,
            DiagnosisReport.Classification.NovelFailure => DiagnosisReport.Severity.Low,
            _ => DiagnosisReport.Severity.Info,
        };

    private static string ClassificationLabel(DiagnosisReport.Classification cls)
        => cls switch
        {
            DiagnosisReport.Classification.Regression => "Regression vs baseline",
            DiagnosisReport.Classification.MissingDependency => "Missing dependency",
            DiagnosisReport.Classification.ValueDrift => "Value drift",
            DiagnosisReport.Classification.NovelFailure => "Novel failure (not in baseline)",
            _ => cls.ToString(),
        };

    private static string Truncate(string s, int n)
        => s.Length <= n ? s : string.Concat(s.AsSpan(0, n), "...");

    private sealed class PendingCandidate
    {
        public DiagnosisReport.Classification Classification { get; init; }
        public AccessKind Kind { get; init; }
        public string Target { get; init; } = string.Empty;
        public string Operation { get; init; } = string.Empty;
        public string Detail { get; init; } = string.Empty;
        public IReadOnlyDictionary<string, int> BaselineResults { get; init; } = NoResults;
        public IReadOnlyDictionary<string, int> CaptureResults { get; init; } = NoResults;
        public IReadOnlyList<string> Images { get; init; } = Array.Empty<string>();
        public bool NearExit { get; init; }
        public long BaselineFirstSeenMs { get; init; } = -1;
        public DiagnosisReport.Severity? SeverityOverride { get; init; }
    }
}
