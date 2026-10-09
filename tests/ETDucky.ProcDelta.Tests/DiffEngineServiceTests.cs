using ETDucky.ProcDelta.Models;
using ETDucky.ProcDelta.Services;
using Xunit;

namespace ETDucky.ProcDelta.Tests;

/// <summary>
/// A service start in the baseline is a transition the baseline happened
/// to see. It is a missing dependency only when the service is not running
/// on this host now; a service that was already up had no start to make.
/// </summary>
public class DiffEngineServiceTests
{
    private const string Provider = "Microsoft-Windows-Services";

    private static Baseline BaselineWithClipSvcStart() => TestData.BaselineWith(
        TestData.Entry(AccessKind.Process, "service:ClipSVC", "ServiceStart", Provider, 2000, ("SUCCESS", 2)),
        TestData.Entry(AccessKind.Process, "service:ClipSVC", "ServiceStop", Provider, 9000));

    private static CaptureSession EmptyRun() => new() { ProcessPattern = "app.exe" };

    [Fact]
    public void A_start_the_baseline_saw_is_satisfied_when_the_service_is_running_now()
    {
        var report = DiffEngine.Compare(BaselineWithClipSvcStart(), EmptyRun(), "unit-test", InspectOptions.Default, _ => ServiceState.Status.Running);

        Assert.Empty(report.Candidates);
        Assert.Equal(new[] { "ClipSVC" }, report.ServicesAlreadyRunning);
        Assert.Contains("Services already running:** ClipSVC.", DiffEngine.RenderMarkdown(report));
        Assert.Contains("Services already running: ClipSVC.", DiffEngine.RenderPlainText(report));
    }

    [Theory]
    [InlineData(ServiceState.Status.Stopped)]
    [InlineData(ServiceState.Status.NotInstalled)]
    [InlineData(ServiceState.Status.Unavailable)]
    public void A_start_the_baseline_saw_is_missing_when_the_service_is_not_running(ServiceState.Status now)
    {
        var report = DiffEngine.Compare(BaselineWithClipSvcStart(), EmptyRun(), "unit-test", InspectOptions.Default, _ => now);

        var c = Assert.Single(report.Candidates);
        Assert.Equal(DiagnosisReport.Classification.MissingDependency, c.Classification);
        Assert.Equal("service:ClipSVC", c.Target);
        Assert.Equal("ServiceStart", c.Operation);
        Assert.StartsWith("Service ClipSVC", c.LiveState, StringComparison.Ordinal);
        Assert.Empty(report.ServicesAlreadyRunning);
    }

    [Fact]
    public void Offline_diffs_do_not_consult_the_service_control_manager()
    {
        var report = DiffEngine.Compare(
            BaselineWithClipSvcStart(), EmptyRun(), "unit-test",
            new InspectOptions(InspectLive: false),
            _ => throw new InvalidOperationException("the SCM must not be consulted offline"));

        var c = Assert.Single(report.Candidates);
        Assert.Equal("service:ClipSVC", c.Target);
        Assert.Equal(DiffEngine.OfflineLiveState, c.LiveState);
        Assert.Empty(report.ServicesAlreadyRunning);
        Assert.DoesNotContain("Services already running", DiffEngine.RenderPlainText(report));
    }

    [Fact]
    public void Stops_and_start_type_changes_are_never_missing_dependencies()
    {
        var baseline = TestData.BaselineWith(
            TestData.Entry(AccessKind.Process, "service:ClipSVC", "ServiceStop", Provider, 9000),
            TestData.Entry(AccessKind.Process, "service:wuauserv", "ServiceStartTypeChanged", Provider, 1000));

        var report = DiffEngine.Compare(baseline, EmptyRun(), "unit-test", InspectOptions.Default, _ => ServiceState.Status.Stopped);

        Assert.Empty(report.Candidates);
        Assert.Empty(report.ServicesAlreadyRunning);
    }

    [Fact]
    public void A_start_that_failed_in_this_run_is_still_a_regression()
    {
        var t0 = new DateTime(2026, 10, 9, 12, 0, 0, DateTimeKind.Utc);
        var live = new CaptureSession { ProcessPattern = "app.exe", StartedAtUtc = t0 };
        live.Append(TestData.Access(AccessKind.Process, "service:ClipSVC", "ServiceStart", "0x80070422", t0.AddSeconds(2), detail: Provider, image: "services.exe"));
        live.StoppedAtUtc = t0.AddSeconds(10);

        var report = DiffEngine.Compare(BaselineWithClipSvcStart(), live, "unit-test", InspectOptions.Default, _ => ServiceState.Status.Running);

        var c = Assert.Single(report.Candidates);
        Assert.Equal(DiagnosisReport.Classification.Regression, c.Classification);
        Assert.Equal("service:ClipSVC", c.Target);
    }
}
