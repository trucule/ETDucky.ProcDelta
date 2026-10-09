using ETDucky.ProcDelta.Models;
using ETDucky.ProcDelta.Services;
using Xunit;

namespace ETDucky.ProcDelta.Tests;

/// <summary>
/// Classification on per-result counts, phase-aware missing dependencies,
/// coverage, process-exit anchoring and grouping. Everything here runs
/// with live inspection off, so nothing on the test host is read.
/// </summary>
public class DiffEngineClassificationTests
{
    private static readonly DateTime T0 = new(2026, 10, 9, 12, 0, 0, DateTimeKind.Utc);
    private static readonly InspectOptions Offline = new(InspectLive: false);

    private static CaptureSession Session(params EnvironmentalAccess[] accesses)
    {
        var s = new CaptureSession { ProcessPattern = "app.exe", StartedAtUtc = T0 };
        foreach (var a in accesses) s.Append(a);
        s.StoppedAtUtc = T0.AddSeconds(60);
        return s;
    }

    private static EnvironmentalAccess File(string target, string result, double atSeconds, string image = "app.exe")
        => TestData.Access(AccessKind.File, target, "Create", result, T0.AddSeconds(atSeconds), image: image);

    [Fact]
    public void Regression_means_ever_succeeded_in_baseline_and_never_here()
    {
        var baseline = TestData.BaselineWith(TestData.Entry(AccessKind.File, @"<WINDOWS>\x.dll", "Create", "", 0, ("SUCCESS", 5), ("SHARING_VIOLATION", 1)));
        var live = Session(File(@"<WINDOWS>\x.dll", "ACCESS_DENIED", 1), File(@"<WINDOWS>\x.dll", "ACCESS_DENIED", 2));

        var report = DiffEngine.Compare(baseline, live, "t", Offline);

        var c = Assert.Single(report.Candidates);
        Assert.Equal(DiagnosisReport.Classification.Regression, c.Classification);
        Assert.Equal(DiagnosisReport.Severity.High, c.Severity);
        Assert.Equal(2, c.CaptureResults["ACCESS_DENIED"]);
        Assert.Equal("SUCCESS x5, SHARING_VIOLATION", c.BaselineResult);
        Assert.Equal("ACCESS_DENIED x2", c.CaptureResult);
        Assert.Equal(DiffEngine.OfflineLiveState, c.LiveState);
    }

    [Fact]
    public void A_transient_failure_followed_by_success_is_not_a_regression()
    {
        // Last-wins classification used to flip this on event order.
        var baseline = TestData.BaselineWith(TestData.File(@"<WINDOWS>\x.dll"));
        var live = Session(File(@"<WINDOWS>\x.dll", "SUCCESS", 1), File(@"<WINDOWS>\x.dll", "SHARING_VIOLATION", 2));

        Assert.Empty(DiffEngine.Compare(baseline, live, "t", Offline).Candidates);
    }

    [Fact]
    public void Registry_size_probe_counts_as_success()
    {
        var baseline = TestData.BaselineWith(TestData.Entry(AccessKind.Registry, @"HKEY_LOCAL_MACHINE\SOFTWARE\Vendor", "QueryValue", "Path", 0, ("SUCCESS", 1)));
        var live = Session(TestData.Access(AccessKind.Registry, @"HKEY_LOCAL_MACHINE\SOFTWARE\Vendor", "QueryValue", "BUFFER_OVERFLOW", T0.AddSeconds(1), detail: "Path"));

        Assert.Empty(DiffEngine.Compare(baseline, live, "t", Offline).Candidates);
    }

    [Fact]
    public void Failed_on_both_sides_is_suppressed_and_novel_failures_are_low()
    {
        var baseline = TestData.BaselineWith(TestData.Entry(AccessKind.File, @"<WINDOWS>\opt.ini", "Create", "", 0, ("OBJECT_NAME_NOT_FOUND", 2)));
        var live = Session(
            File(@"<WINDOWS>\opt.ini", "OBJECT_NAME_NOT_FOUND", 1),
            File(@"<WINDOWS>\new.ini", "OBJECT_NAME_NOT_FOUND", 2),
            File(@"<WINDOWS>\fine.ini", "SUCCESS", 3));

        var report = DiffEngine.Compare(baseline, live, "t", Offline);

        var c = Assert.Single(report.Candidates);
        Assert.Equal(DiagnosisReport.Classification.NovelFailure, c.Classification);
        Assert.Equal(@"<WINDOWS>\new.ini", c.Target);
        Assert.Equal("(not in baseline)", c.BaselineResult);
    }

    [Fact]
    public void Missing_dependencies_respect_how_far_the_live_run_got()
    {
        var baseline = TestData.BaselineWith(
            TestData.File(@"<WINDOWS>\early.dll", firstSeenMs: 1_000),
            TestData.File(@"<WINDOWS>\mid.dll", firstSeenMs: 9_000),
            TestData.File(@"<WINDOWS>\late.dll", firstSeenMs: 30_000),
            TestData.Entry(AccessKind.Process, "app.exe", "Stop", "", 40_000, ("ExitCode=0", 1)));
        // Live run only reached 8 seconds of activity: early must be missing,
        // mid is within the 2s grace, late is after the reach.
        var live = Session(File(@"<WINDOWS>\something-else.dll", "SUCCESS", 0), File(@"<WINDOWS>\other.dll", "SUCCESS", 8));

        var report = DiffEngine.Compare(baseline, live, "t", Offline);

        var targets = report.Candidates.Select(c => c.Target).ToList();
        Assert.Contains(@"<WINDOWS>\early.dll", targets);
        Assert.Contains(@"<WINDOWS>\mid.dll", targets);
        Assert.DoesNotContain(@"<WINDOWS>\late.dll", targets);
        Assert.DoesNotContain("app.exe", targets);
        Assert.Equal(1, report.SkippedAfterReach);
        Assert.All(report.Candidates, c => Assert.Equal(DiagnosisReport.Classification.MissingDependency, c.Classification));
        Assert.Equal(1_000, report.Candidates.Single(c => c.Target.EndsWith("early.dll", StringComparison.Ordinal)).BaselineFirstSeenMs);
    }

    [Fact]
    public void Upgraded_v1_entries_without_offsets_are_never_gated()
    {
        var baseline = TestData.BaselineWith(TestData.File(@"<WINDOWS>\late.dll", firstSeenMs: -1));
        var live = Session(File(@"<WINDOWS>\other.dll", "SUCCESS", 0));

        var report = DiffEngine.Compare(baseline, live, "t", Offline);
        Assert.Single(report.Candidates);
        Assert.Equal(0, report.SkippedAfterReach);
    }

    [Fact]
    public void Coverage_counts_baseline_entries_this_run_also_made()
    {
        var baseline = TestData.BaselineWith(
            TestData.File(@"<WINDOWS>\a.dll"), TestData.File(@"<WINDOWS>\b.dll"),
            TestData.File(@"<WINDOWS>\c.dll"), TestData.File(@"<WINDOWS>\d.dll"));
        var live = Session(File(@"<WINDOWS>\a.dll", "SUCCESS", 1), File(@"<WINDOWS>\b.dll", "SUCCESS", 1), File(@"<WINDOWS>\c.dll", "SUCCESS", 1));

        var report = DiffEngine.Compare(baseline, live, "t", Offline);
        Assert.Equal(4, report.BaselineEntryCount);
        Assert.Equal(3, report.MatchedEntryCount);
        Assert.Equal(0.75, report.Coverage, 3);
        Assert.Contains("3 of 4 baseline accesses (75%)", DiffEngine.RenderPlainText(report));
        Assert.DoesNotContain("Low coverage", DiffEngine.RenderPlainText(report));

        var poor = DiffEngine.Compare(baseline, Session(File(@"<WINDOWS>\a.dll", "SUCCESS", 1)), "t", Offline);
        Assert.Contains("Low coverage", DiffEngine.RenderPlainText(poor));
    }

    [Fact]
    public void NearExit_is_only_claimed_when_a_root_process_exited()
    {
        var baseline = TestData.BaselineWith(TestData.File(@"<WINDOWS>\x.dll"));

        var noExit = Session(File(@"<WINDOWS>\x.dll", "ACCESS_DENIED", 10));
        var r1 = DiffEngine.Compare(baseline, noExit, "t", Offline);
        Assert.False(r1.RootExitObserved);
        Assert.False(Assert.Single(r1.Candidates).NearExit);
        Assert.Contains("no tracked root process exited", DiffEngine.RenderPlainText(r1));

        var withExit = Session(File(@"<WINDOWS>\x.dll", "ACCESS_DENIED", 10));
        withExit.NoteRootExit(T0.AddSeconds(11));
        var r2 = DiffEngine.Compare(baseline, withExit, "t", Offline);
        Assert.True(r2.RootExitObserved);
        Assert.True(Assert.Single(r2.Candidates).NearExit);

        var longBefore = Session(File(@"<WINDOWS>\x.dll", "ACCESS_DENIED", 10));
        longBefore.NoteRootExit(T0.AddSeconds(30));
        Assert.False(Assert.Single(DiffEngine.Compare(baseline, longBefore, "t", Offline).Candidates).NearExit);
    }

    [Fact]
    public void Three_or_more_candidates_under_one_key_render_as_a_group()
    {
        const string key = @"HKEY_LOCAL_MACHINE\SOFTWARE\Vendor";
        var baseline = TestData.BaselineWith(
            TestData.Entry(AccessKind.Registry, key, "QueryValue", "A", 0),
            TestData.Entry(AccessKind.Registry, key, "QueryValue", "B", 0),
            TestData.Entry(AccessKind.Registry, key, "QueryValue", "C", 0),
            TestData.File(@"<WINDOWS>\lonely.dll"));
        var live = Session(File(@"<WINDOWS>\unrelated.dll", "SUCCESS", 0));

        var report = DiffEngine.Compare(baseline, live, "t", Offline);
        Assert.Equal(4, report.Candidates.Count);

        var groups = DiffEngine.GroupCandidates(report.Candidates);
        Assert.Equal(2, groups.Count);
        Assert.Contains(groups, g => g.Count == 3 && g.All(c => c.Target == key));

        var markdown = DiffEngine.RenderMarkdown(report);
        Assert.Contains("(3 values)", markdown);
        Assert.Contains("- `A` QueryValue", markdown);
        Assert.Contains("Missing dependency: File `<WINDOWS>\\lonely.dll`", markdown);
    }

    [Fact]
    public void Candidates_carry_the_images_that_made_the_access()
    {
        var baseline = TestData.BaselineWith(TestData.File(@"<WINDOWS>\x.dll"));
        var live = Session(File(@"<WINDOWS>\x.dll", "ACCESS_DENIED", 1, image: "AcroCEF.exe"), File(@"<WINDOWS>\x.dll", "ACCESS_DENIED", 2, image: "Acrobat.exe"));

        var c = Assert.Single(DiffEngine.Compare(baseline, live, "t", Offline).Candidates);
        Assert.Equal(new[] { "AcroCEF.exe", "Acrobat.exe" }, c.Images);
        Assert.Contains("Made by: AcroCEF.exe, Acrobat.exe", DiffEngine.RenderPlainText(DiffEngine.Compare(baseline, live, "t", Offline)));
    }

    [Fact]
    public void Header_reports_version_drift_and_action()
    {
        var baseline = new Baseline
        {
            AppName = "App", ProcessPattern = "app.exe", ActionDescription = "opened a file",
            AppImagePath = @"<PROGRAMFILES>\Vendor\app.exe", AppVersion = "1.2.3.4", OsBuild = "10.0.26100.1",
            Entries = { TestData.File(@"<WINDOWS>\x.dll") },
        };
        var live = Session(File(@"<WINDOWS>\x.dll", "SUCCESS", 1));
        live.NoteRootImage(@"<PROGRAMFILES>\Vendor\app.exe", "1.2.3.5");

        var text = DiffEngine.RenderPlainText(DiffEngine.Compare(baseline, live, "t", Offline));
        Assert.Contains("Action: \"opened a file\"", text);
        Assert.Contains("App version: baseline 1.2.3.4; this run 1.2.3.5; DIFFERS", text);
        Assert.Contains("Baseline host: GOOD-PC", DiffEngine.RenderPlainText(DiffEngine.Compare(TestData.BaselineWith(), live, "t", Offline)));
    }

    [Fact]
    public void CompareBaselines_diffs_two_files_offline()
    {
        var good = TestData.BaselineWith(
            TestData.File(@"<WINDOWS>\a.dll"),
            TestData.Entry(AccessKind.Network, "login.example.com:443", "Connect", "", 500));
        var broken = TestData.BaselineWith(
            TestData.Entry(AccessKind.File, @"<WINDOWS>\a.dll", "Create", "", 0, ("ACCESS_DENIED", 3)));

        var report = DiffEngine.CompareBaselines(good, broken, "good.baseline.json");

        Assert.False(report.LiveStateInspected);
        Assert.False(report.NetworkProbed);
        Assert.Equal(2, report.Candidates.Count);
        var regression = Assert.Single(report.Candidates, c => c.Classification == DiagnosisReport.Classification.Regression);
        Assert.Equal(@"<WINDOWS>\a.dll", regression.Target);
        var missing = Assert.Single(report.Candidates, c => c.Classification == DiagnosisReport.Classification.MissingDependency);
        Assert.Equal("login.example.com:443", missing.Target);
        Assert.All(report.Candidates, c => Assert.Equal(DiffEngine.OfflineLiveState, c.LiveState));
        Assert.Contains("Live state: not inspected", DiffEngine.RenderPlainText(report));
    }
}
