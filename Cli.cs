using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using ETDucky.ProcDelta.Models;
using ETDucky.ProcDelta.Services;

namespace ETDucky.ProcDelta;

/// <summary>
/// Parsed command line: a verb, "--name value" options and "--flag" switches.
/// Pure, so it is testable without a console.
/// </summary>
public sealed class CliOptions
{
    public string Verb { get; private set; } = string.Empty;
    public Dictionary<string, string> Values { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> Flags { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> Errors { get; } = new();

    public static CliOptions Parse(string[] args)
    {
        var o = new CliOptions();
        if (args.Length == 0) return o;
        o.Verb = args[0].Trim().ToLowerInvariant();

        for (var i = 1; i < args.Length; i++)
        {
            var a = args[i];
            if (!a.StartsWith("--", StringComparison.Ordinal))
            {
                o.Errors.Add($"Unexpected argument '{a}'.");
                continue;
            }
            var name = a.Substring(2);
            var eq = name.IndexOf('=');
            if (eq > 0)
            {
                o.Values[name.Substring(0, eq)] = name.Substring(eq + 1);
                continue;
            }
            if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
            {
                o.Values[name] = args[++i];
            }
            else
            {
                o.Flags.Add(name);
            }
        }
        return o;
    }

    public string? Get(string name) => Values.TryGetValue(name, out var v) ? v : null;

    public bool Has(string flag) => Flags.Contains(flag) || Values.ContainsKey(flag);

    public int? GetInt(string name)
        => int.TryParse(Get(name), NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : null;
}

/// <summary>
/// Headless mode. Same capture, recorder and diff engine as the window,
/// driven from a command line so the tool can be pushed through MECM,
/// Intune or an RMM and the JSON collected centrally.
///
/// Verbs:
///   record   capture a baseline on a working machine
///   compare  capture on the broken machine and diff against a baseline
///   diff     diff two saved baselines, no capture, no live inspection
///   replay   build a baseline from a recorded .etl file
///
/// The executable is a GUI-subsystem binary, so a console shell does not
/// wait for it by itself: use "start /wait" from cmd or Start-Process -Wait
/// from PowerShell, or just rely on the exit code from a script host that
/// waits. Output goes to the parent console when there is one.
/// </summary>
public static class Cli
{
    public const int ExitOk = 0;
    public const int ExitUsage = 1;
    public const int ExitFailed = 2;
    public const int ExitFindings = 3;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AttachConsole(int dwProcessId);
    private const int AttachParentProcess = -1;

    private static readonly JsonSerializerOptions ReportJsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public static int Run(string[] args)
    {
        try { AttachConsole(AttachParentProcess); } catch { }

        var o = CliOptions.Parse(args);
        if (o.Errors.Count > 0)
        {
            foreach (var e in o.Errors) Console.Error.WriteLine(e);
            Console.Error.WriteLine();
            PrintUsage();
            return ExitUsage;
        }

        try
        {
            return o.Verb switch
            {
                "record" => RecordAsync(o).GetAwaiter().GetResult(),
                "compare" => CompareAsync(o).GetAwaiter().GetResult(),
                "diff" => Diff(o),
                "replay" => Replay(o),
                "help" or "--help" or "-h" or "/?" => Usage(),
                _ => UsageError($"Unknown command '{o.Verb}'."),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.GetType().Name}: {ex.Message}");
            return ExitFailed;
        }
    }

    private static int Usage()
    {
        PrintUsage();
        return ExitOk;
    }

    private static int UsageError(string message)
    {
        Console.Error.WriteLine(message);
        Console.Error.WriteLine();
        PrintUsage();
        return ExitUsage;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("ETDucky.ProcDelta command line");
        Console.WriteLine();
        Console.WriteLine("  record  --out <file.baseline.json> (--pattern <names> | --launch <exe>) [--duration <sec>]");
        Console.WriteLine("          [--app <name>] [--action <text>] [--include-user] [--timeout <sec>]");
        Console.WriteLine("  compare --baseline <file> --report <file.md> [--pattern <names> | --launch <exe>] [--duration <sec>]");
        Console.WriteLine("          [--json <file>] [--probe-network] [--show-values] [--fail-on-findings] [--timeout <sec>]");
        Console.WriteLine("  diff    --baseline <file> --against <file.baseline.json> --report <file.md> [--json <file>] [--fail-on-findings]");
        Console.WriteLine("  replay  --etl <trace.etl> --pattern <names> --out <file.baseline.json> [--app <name>] [--action <text>]");
        Console.WriteLine();
        Console.WriteLine("  --pattern   process names to track, '|' separated, '*' and '?' allowed (Acrobat.exe|AcroCEF.exe)");
        Console.WriteLine("  --launch    start this executable after the capture is up and track its process tree;");
        Console.WriteLine("              with no --duration the capture ends when the tree has exited");
        Console.WriteLine("  --args      arguments for --launch (the app then inherits this tool's elevation)");
        Console.WriteLine("  --duration  seconds to capture; required unless --launch is given");
        Console.WriteLine("  --timeout   upper bound in seconds when waiting for a launched tree to exit (default 600)");
        Console.WriteLine();
        Console.WriteLine("Exit codes: 0 ok, 1 usage, 2 failed, 3 findings (compare/diff with --fail-on-findings).");
        Console.WriteLine("Administrator is required for record and compare. Nothing leaves the machine unless --probe-network is given.");
    }

    // ── record ───────────────────────────────────────────────────────────

    private static async Task<int> RecordAsync(CliOptions o)
    {
        var outPath = o.Get("out");
        if (string.IsNullOrWhiteSpace(outPath)) return UsageError("record needs --out.");

        var capture = await CaptureAsync(o, o.Get("action") ?? string.Empty);
        if (capture is null) return ExitFailed;
        using var kernelOwner = capture.Kernel; // disposed after the recorder has read the registry cache

        var pattern = capture.Session.ProcessPattern;
        var baseline = BaselineRecorder.Build(
            capture.Session,
            o.Get("app") ?? Path.GetFileNameWithoutExtension(pattern.Split('|')[0]),
            pattern,
            o.Get("action") ?? string.Empty,
            capture.RegistryValues,
            includeOperator: o.Has("include-user"));

        var findings = BaselineScrubber.FindSensitive(baseline);
        BaselineLoader.Save(baseline, outPath);

        Console.WriteLine($"Saved {baseline.Entries.Count:N0} aggregated accesses to {outPath}");
        Console.WriteLine($"Tracked activity {capture.Session.TrackedActivity.TotalSeconds:0.0}s, {capture.Session.TotalEventCount:N0} events, {capture.EventsLost:N0} dropped by ETW.");
        Console.WriteLine($"User-mode providers delivered: {capture.Delivered}");
        if (findings.Count > 0)
            Console.WriteLine($"Review before sharing: {findings.Count} entries name people, servers or customer paths (run the window's Save for the list).");
        if (capture.EventsLost > 0)
            Console.WriteLine("Warning: events were dropped; the baseline is incomplete. Re-record on a quieter host.");
        return ExitOk;
    }

    // ── compare ──────────────────────────────────────────────────────────

    private static async Task<int> CompareAsync(CliOptions o)
    {
        var baselinePath = o.Get("baseline");
        var reportPath = o.Get("report");
        if (string.IsNullOrWhiteSpace(baselinePath) || string.IsNullOrWhiteSpace(reportPath))
            return UsageError("compare needs --baseline and --report.");

        var baseline = BaselineLoader.TryLoad(baselinePath, out var error);
        if (baseline is null) { Console.Error.WriteLine(error); return ExitFailed; }

        if (o.Get("pattern") is null && o.Get("launch") is null)
            o.Values["pattern"] = baseline.ProcessPattern;

        var capture = await CaptureAsync(o, baseline.ActionDescription);
        if (capture is null) return ExitFailed;
        using var kernelOwner = capture.Kernel; // disposed after the recorder has read the registry cache

        var options = new InspectOptions(
            AllowNetwork: o.Has("probe-network"),
            ShowRegistryValues: o.Has("show-values"));
        var report = DiffEngine.Compare(baseline, capture.Session, baselinePath, options);
        return WriteReport(report, reportPath, o);
    }

    // ── diff (offline) ───────────────────────────────────────────────────

    private static int Diff(CliOptions o)
    {
        var baselinePath = o.Get("baseline");
        var againstPath = o.Get("against");
        var reportPath = o.Get("report");
        if (string.IsNullOrWhiteSpace(baselinePath) || string.IsNullOrWhiteSpace(againstPath) || string.IsNullOrWhiteSpace(reportPath))
            return UsageError("diff needs --baseline, --against and --report.");

        var reference = BaselineLoader.TryLoad(baselinePath, out var e1);
        if (reference is null) { Console.Error.WriteLine(e1); return ExitFailed; }
        var against = BaselineLoader.TryLoad(againstPath, out var e2);
        if (against is null) { Console.Error.WriteLine(e2); return ExitFailed; }

        var report = DiffEngine.CompareBaselines(reference, against, baselinePath);
        return WriteReport(report, reportPath, o);
    }

    // ── replay ───────────────────────────────────────────────────────────

    private static int Replay(CliOptions o)
    {
        var etl = o.Get("etl");
        var pattern = o.Get("pattern");
        var outPath = o.Get("out");
        if (string.IsNullOrWhiteSpace(etl) || string.IsNullOrWhiteSpace(pattern) || string.IsNullOrWhiteSpace(outPath))
            return UsageError("replay needs --etl, --pattern and --out.");
        if (!File.Exists(etl)) { Console.Error.WriteLine($"Not found: {etl}"); return ExitFailed; }

        var session = EnvironmentalCapture.Replay(etl, pattern, o.Get("action") ?? string.Empty);
        var baseline = BaselineRecorder.Build(
            session,
            o.Get("app") ?? Path.GetFileNameWithoutExtension(pattern.Split('|')[0]),
            pattern,
            o.Get("action") ?? string.Empty,
            registryValues: null,
            includeOperator: false);
        BaselineLoader.Save(baseline, outPath);
        Console.WriteLine($"Replayed {etl}: {session.TotalEventCount:N0} tracked events, {baseline.Entries.Count:N0} aggregated accesses saved to {outPath}");
        return ExitOk;
    }

    // ── shared ───────────────────────────────────────────────────────────

    private static int WriteReport(DiagnosisReport report, string reportPath, CliOptions o)
    {
        var text = reportPath.EndsWith(".txt", StringComparison.OrdinalIgnoreCase)
            ? DiffEngine.RenderPlainText(report)
            : DiffEngine.RenderMarkdown(report);
        File.WriteAllText(reportPath, text);

        var jsonPath = o.Get("json");
        if (!string.IsNullOrWhiteSpace(jsonPath))
        {
            File.WriteAllText(jsonPath, JsonSerializer.Serialize(report, ReportJsonOptions));
        }

        var n = report.Candidates.Count;
        Console.WriteLine($"{n} candidate(s). Coverage {Math.Round(report.Coverage * 100)}%. Report written to {reportPath}");
        if (report.BaselineEntryCount > 0 && report.Coverage < DiagnosisReport.LowCoverageThreshold)
            Console.WriteLine("Low coverage: the runs may not be comparable.");
        return n > 0 && o.Has("fail-on-findings") ? ExitFindings : ExitOk;
    }

    private sealed class CaptureOutcome
    {
        public CaptureSession Session { get; init; } = null!;
        /// <summary>Owned by the caller, which disposes it after the recorder has read the registry cache.</summary>
        public EnvironmentalCapture Kernel { get; init; } = null!;
        public RegistryValueCache? RegistryValues { get; init; }
        public int EventsLost { get; init; }
        public string Delivered { get; init; } = string.Empty;
    }

    /// <summary>
    /// Run one capture window: start both sessions, optionally launch the
    /// target, wait for --duration or for the launched tree to exit, stop.
    /// </summary>
    private static async Task<CaptureOutcome?> CaptureAsync(CliOptions o, string actionDescription)
    {
        var launch = o.Get("launch");
        var pattern = o.Get("pattern");
        var duration = o.GetInt("duration");
        var timeout = o.GetInt("timeout") ?? 600;

        if (string.IsNullOrWhiteSpace(pattern) && string.IsNullOrWhiteSpace(launch))
        {
            UsageError("Give --pattern or --launch.");
            return null;
        }
        if (string.IsNullOrWhiteSpace(launch) && duration is null)
        {
            UsageError("Give --duration, or --launch so the capture can end when the app exits.");
            return null;
        }
        if (string.IsNullOrWhiteSpace(pattern)) pattern = ProcessLauncher.PatternFor(launch!);

        EnvironmentalCapture.CleanupOrphanedSessions();

        var tracker = new ProcessTracker(pattern);
        var session = new CaptureSession { ProcessPattern = pattern, ActionDescription = actionDescription };
        var kernel = new EnvironmentalCapture(tracker, session);
        AppRuntimeCapture? app = null;

        var faulted = string.Empty;
        kernel.Faulted += m => faulted = m;

        try
        {
            kernel.Start();
        }
        catch (UnauthorizedAccessException)
        {
            Console.Error.WriteLine("Access denied. record and compare must run as Administrator.");
            kernel.Dispose();
            return null;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Could not start the kernel session: {ex.GetType().Name}: {ex.Message}");
            kernel.Dispose();
            return null;
        }

        try
        {
            app = new AppRuntimeCapture(tracker, session);
            app.Start();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"App-runtime capture unavailable, continuing kernel-only: {ex.Message}");
            app = null;
        }

        Console.WriteLine($"Capturing pattern '{pattern}'...");
        if (!string.IsNullOrWhiteSpace(launch))
        {
            await Task.Delay(500); // let both sessions settle before the target starts
            var result = ProcessLauncher.Launch(launch!, o.Get("args"));
            Console.WriteLine(result.Note);
            if (!result.Started)
            {
                await kernel.StopAsync();
                if (app is not null) await app.StopAsync();
                app?.Dispose();
                kernel.Dispose();
                return null;
            }
        }

        var started = DateTime.UtcNow;
        var sawTree = tracker.TrackedCount > 0;
        while (true)
        {
            await Task.Delay(250);
            if (faulted.Length > 0) { Console.Error.WriteLine("Capture stopped: " + faulted); break; }

            var elapsed = DateTime.UtcNow - started;
            if (duration is int d && elapsed >= TimeSpan.FromSeconds(d)) break;
            if (duration is null)
            {
                if (tracker.TrackedCount > 0) sawTree = true;
                else if (sawTree)
                {
                    await Task.Delay(2000); // grace for trailing events
                    break;
                }
                if (elapsed >= TimeSpan.FromSeconds(timeout))
                {
                    Console.WriteLine($"Timeout after {timeout}s; stopping the capture.");
                    break;
                }
            }
        }

        await kernel.StopAsync();
        if (app is not null) await app.StopAsync();

        var outcome = new CaptureOutcome
        {
            Session = session,
            Kernel = kernel,
            RegistryValues = kernel.RegistryValues,
            EventsLost = kernel.EventsLost,
            Delivered = app?.DeliveredSummary ?? "(app-runtime capture unavailable)",
        };
        app?.Dispose();
        return outcome;
    }
}
