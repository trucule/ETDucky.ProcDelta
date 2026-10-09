using ETDucky.ProcDelta.Models;
using ETDucky.ProcDelta.Services;
using Xunit;

namespace ETDucky.ProcDelta.Tests;

/// <summary>
/// The options reach the enrichment pass and the report says which gates
/// were open, so a reader of an exported report knows why a line says
/// "probing disabled".
/// </summary>
public class DiffEngineGateTests
{
    private static Baseline BaselineWithNetworkDependency() => TestData.BaselineWith(
        TestData.Entry(AccessKind.Network, "127.0.0.1:9", "Connect", "", 0),
        TestData.Entry(AccessKind.File, @"\\127.0.0.1\nonexistent-share\dep.dll", "Create", "", 0));

    [Fact]
    public void Compare_without_options_probes_nothing()
    {
        var report = DiffEngine.Compare(BaselineWithNetworkDependency(), new CaptureSession { ProcessPattern = "app.exe" }, "unit-test");

        Assert.False(report.NetworkProbed);
        Assert.False(report.RegistryValuesShown);
        Assert.True(report.LiveStateInspected);
        Assert.Equal(2, report.Candidates.Count);
        Assert.All(report.Candidates, c => Assert.Equal(DiagnosisReport.Classification.MissingDependency, c.Classification));

        var network = Assert.Single(report.Candidates, c => c.Kind == AccessKind.Network);
        Assert.Equal(LiveStateInspector.NetworkProbingDisabled, network.LiveState);

        var file = Assert.Single(report.Candidates, c => c.Kind == AccessKind.File);
        Assert.StartsWith(LiveStateInspector.NetworkPathDisabled, file.LiveState);
    }

    [Fact]
    public void Report_header_states_the_gate_positions()
    {
        var closed = DiffEngine.Compare(BaselineWithNetworkDependency(), new CaptureSession { ProcessPattern = "app.exe" }, "unit-test");
        var markdown = DiffEngine.RenderMarkdown(closed);
        var plain = DiffEngine.RenderPlainText(closed);

        Assert.Contains("Network probing:** disabled", markdown);
        Assert.Contains("Registry values:** hidden", markdown);
        Assert.Contains("Network probing: disabled", plain);
        Assert.Contains("Registry values: hidden", plain);

        var open = DiffEngine.Compare(
            TestData.BaselineWith(),
            new CaptureSession { ProcessPattern = "app.exe" },
            "unit-test",
            new InspectOptions(AllowNetwork: true, ShowRegistryValues: true));

        Assert.True(open.NetworkProbed);
        Assert.True(open.RegistryValuesShown);
        Assert.Contains("Network probing: enabled", DiffEngine.RenderPlainText(open));
        Assert.Contains("Registry values: shown", DiffEngine.RenderPlainText(open));
    }
}
