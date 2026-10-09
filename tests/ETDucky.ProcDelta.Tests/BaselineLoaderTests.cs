using ETDucky.ProcDelta.Models;
using ETDucky.ProcDelta.Services;
using Xunit;

namespace ETDucky.ProcDelta.Tests;

public class BaselineLoaderTests
{
    private const string V1Json = """
        {
          "SchemaVersion": 1,
          "AppName": "Old App",
          "ProcessPattern": "old.exe",
          "ActionDescription": "ran it",
          "RecordedAtUtc": "2026-07-17T18:00:00Z",
          "RecordedOn": "OLD-PC",
          "RecordedBy": "someone",
          "Duration": "00:00:30",
          "Entries": [
            { "Kind": "Registry", "Target": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Vendor", "Operation": "QueryValue", "Detail": "InstallPath", "Result": "SUCCESS", "AccessCount": 3, "ValueHash": "sha256:abc", "ValueType": "String" },
            { "Kind": "Network", "Target": "203.0.113.10:443", "Operation": "Connect", "Detail": "", "Result": "SUCCESS", "AccessCount": 1 },
            { "Kind": "File", "Target": "<WINDOWS>\\x.dll", "Operation": "Create", "Detail": "", "Result": "OBJECT_NAME_NOT_FOUND", "AccessCount": 2 }
          ]
        }
        """;

    [Fact]
    public void V1_files_load_and_are_upgraded_in_memory()
    {
        var b = BaselineLoader.TryParse(V1Json, out var error);
        Assert.NotNull(b);
        Assert.Equal(string.Empty, error);
        Assert.Equal(Baseline.CurrentSchemaVersion, b!.SchemaVersion);
        Assert.Equal("Old App", b.AppName);
        Assert.Equal(3, b.Entries.Count);

        var reg = b.Entries.Single(e => e.Kind == AccessKind.Registry);
        Assert.Equal(3, reg.Results["SUCCESS"]);
        Assert.Equal(-1, reg.FirstSeenOffsetMs);
        Assert.Equal("sha256:abc", reg.ValueHash);
        Assert.Empty(reg.Images);

        var file = b.Entries.Single(e => e.Kind == AccessKind.File);
        Assert.Equal(2, file.Results["OBJECT_NAME_NOT_FOUND"]);
        Assert.False(ResultSemantics.EverSucceeded(file.Results, file.Operation));
    }

    [Fact]
    public void V2_round_trips_through_json_with_all_new_fields()
    {
        var original = TestData.BaselineWith(
            TestData.Entry(AccessKind.Registry, @"HKEY_LOCAL_MACHINE\SOFTWARE\Vendor", "QueryValue", "InstallPath", 1500,
                ("BUFFER_OVERFLOW", 2), ("SUCCESS", 2)));
        original.Entries[0].Images.Add("app.exe");
        var withMeta = new Baseline
        {
            AppName = original.AppName,
            ProcessPattern = original.ProcessPattern,
            ActionDescription = original.ActionDescription,
            RecordedOn = original.RecordedOn,
            Duration = original.Duration,
            TrackedActivitySeconds = 12.5,
            AppImagePath = @"<PROGRAMFILES>\Vendor\app.exe",
            AppVersion = "1.2.3.4",
            OsBuild = "10.0.26100.1234",
            Entries = original.Entries,
        };

        var path = Path.Combine(Path.GetTempPath(), $"procdelta-test-{Guid.NewGuid():N}.baseline.json");
        try
        {
            BaselineLoader.Save(withMeta, path);
            var loaded = BaselineLoader.TryLoad(path, out var error);
            Assert.NotNull(loaded);
            Assert.Equal(string.Empty, error);
            Assert.Equal(2, loaded!.SchemaVersion);
            Assert.Equal("1.2.3.4", loaded.AppVersion);
            Assert.Equal("10.0.26100.1234", loaded.OsBuild);
            Assert.Equal(12.5, loaded.TrackedActivitySeconds);
            var e = Assert.Single(loaded.Entries);
            Assert.Equal(2, e.Results["BUFFER_OVERFLOW"]);
            Assert.Equal(2, e.Results["SUCCESS"]);
            Assert.Equal(1500, e.FirstSeenOffsetMs);
            Assert.Equal(new[] { "app.exe" }, e.Images);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Storage_stack_entries_are_dropped_when_a_baseline_loads()
    {
        // A baseline recorded before the capture filtered these must not
        // report them as missing dependencies against a current run.
        var recorded = TestData.BaselineWith(
            TestData.File(@"<SYSTEM32>\en-US\app.exe.mui:WofCompressedData"),
            TestData.File(@"<SYSTEM32>\en-US\app.exe.mui"),
            TestData.File(@"<USERPROFILE>\Downloads\setup.exe:Zone.Identifier"));

        var path = Path.Combine(Path.GetTempPath(), $"procdelta-test-{Guid.NewGuid():N}.baseline.json");
        try
        {
            BaselineLoader.Save(recorded, path);
            var loaded = BaselineLoader.TryLoad(path, out var error);
            Assert.NotNull(loaded);
            Assert.Equal(string.Empty, error);
            Assert.Equal(
                new[] { @"<SYSTEM32>\en-US\app.exe.mui", @"<USERPROFILE>\Downloads\setup.exe:Zone.Identifier" },
                loaded!.Entries.Select(e => e.Target));

            var report = DiffEngine.Compare(loaded, new CaptureSession { ProcessPattern = "app.exe" }, "unit-test");
            Assert.Equal(2, report.BaselineEntryCount);
            Assert.DoesNotContain(report.Candidates, c => c.Target.EndsWith(":WofCompressedData", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Unknown_schema_versions_are_refused()
    {
        var b = BaselineLoader.TryParse("""{ "SchemaVersion": 9, "Entries": [] }""", out var error);
        Assert.Null(b);
        Assert.Contains("Unsupported schema version 9", error);
    }

    [Fact]
    public void Invalid_json_is_reported_not_thrown()
    {
        var b = BaselineLoader.TryParse("{ not json", out var error);
        Assert.Null(b);
        Assert.StartsWith("Invalid JSON", error);
    }
}
