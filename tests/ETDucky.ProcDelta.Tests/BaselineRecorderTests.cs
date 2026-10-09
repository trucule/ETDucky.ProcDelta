using System.Text.Json;
using ETDucky.ProcDelta.Models;
using ETDucky.ProcDelta.Services;
using Xunit;

namespace ETDucky.ProcDelta.Tests;

public class BaselineRecorderTests
{
    private static CaptureSession SessionWithOneAccess()
    {
        var session = new CaptureSession { ProcessPattern = "app.exe" };
        session.Append(new EnvironmentalAccess
        {
            Kind = AccessKind.File,
            Target = @"<WINDOWS>\x.dll",
            Operation = "Create",
            Result = "SUCCESS",
            ProcessId = 1,
            ProcessImage = "app.exe",
            TimestampUtc = DateTime.UtcNow,
        });
        return session;
    }

    [Fact]
    public void Username_is_left_empty_unless_the_operator_opts_in()
    {
        var session = SessionWithOneAccess();

        var silent = BaselineRecorder.Build(session, "App", "app.exe", "launched it", null);
        Assert.Equal(string.Empty, silent.RecordedBy);
        Assert.Equal(Environment.MachineName, silent.RecordedOn);
        Assert.Single(silent.Entries);

        var opted = BaselineRecorder.Build(session, "App", "app.exe", "launched it", null, includeOperator: true);
        Assert.Equal(Environment.UserName, opted.RecordedBy);
    }

    [Fact]
    public void Saved_json_carries_an_empty_RecordedBy_by_default_and_round_trips()
    {
        var session = SessionWithOneAccess();
        var baseline = BaselineRecorder.Build(session, "App", "app.exe", "launched it", null);
        var path = Path.Combine(Path.GetTempPath(), $"procdelta-test-{Guid.NewGuid():N}.baseline.json");
        try
        {
            BaselineLoader.Save(baseline, path);

            using (var doc = JsonDocument.Parse(File.ReadAllText(path)))
            {
                Assert.Equal(string.Empty, doc.RootElement.GetProperty("RecordedBy").GetString());
            }

            var loaded = BaselineLoader.TryLoad(path, out var error);
            Assert.NotNull(loaded);
            Assert.Equal(string.Empty, error);
            Assert.Equal(string.Empty, loaded!.RecordedBy);
            Assert.Single(loaded.Entries);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
