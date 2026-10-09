using ETDucky.ProcDelta.Models;
using Xunit;

namespace ETDucky.ProcDelta.Tests;

public class CaptureSessionTests
{
    private static readonly DateTime T0 = new(2026, 10, 9, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Aggregates_keep_a_count_per_result_and_first_last_timestamps()
    {
        var s = new CaptureSession { ProcessPattern = "app.exe", StartedAtUtc = T0 };
        const string key = @"HKEY_LOCAL_MACHINE\SOFTWARE\Vendor";
        s.Append(TestData.Access(AccessKind.Registry, key, "QueryValue", "BUFFER_OVERFLOW", T0.AddSeconds(1), detail: "InstallPath"));
        s.Append(TestData.Access(AccessKind.Registry, key, "QueryValue", "SUCCESS", T0.AddSeconds(1.001), detail: "InstallPath"));
        s.Append(TestData.Access(AccessKind.Registry, key, "QueryValue", "SUCCESS", T0.AddSeconds(5), detail: "InstallPath", image: "child.exe"));

        var agg = Assert.Single(s.SnapshotAggregates());
        Assert.Equal(3, agg.Count);
        Assert.Equal(1, agg.Results["BUFFER_OVERFLOW"]);
        Assert.Equal(2, agg.Results["SUCCESS"]);
        Assert.Equal("SUCCESS", agg.LastResult);
        Assert.Equal(T0.AddSeconds(1), agg.FirstTimestampUtc);
        Assert.Equal(T0.AddSeconds(5), agg.LastTimestampUtc);
        Assert.Equal(new[] { "app.exe", "child.exe" }, agg.Images);

        Assert.Equal(T0.AddSeconds(1), s.FirstEventUtc);
        Assert.Equal(T0.AddSeconds(5), s.LastEventUtc);
        Assert.Equal(TimeSpan.FromSeconds(4), s.TrackedActivity);
        Assert.Equal(3, s.TotalEventCount);
    }

    [Fact]
    public void Last_result_is_by_timestamp_not_by_arrival_order()
    {
        var s = new CaptureSession { ProcessPattern = "app.exe", StartedAtUtc = T0 };
        s.Append(TestData.Access(AccessKind.File, @"<WINDOWS>\x.dll", "Create", "SUCCESS", T0.AddSeconds(3)));
        s.Append(TestData.Access(AccessKind.File, @"<WINDOWS>\x.dll", "Create", "ACCESS_DENIED", T0.AddSeconds(2)));
        var agg = Assert.Single(s.SnapshotAggregates());
        Assert.Equal("SUCCESS", agg.LastResult);
        Assert.Equal(T0.AddSeconds(2), agg.FirstTimestampUtc);
    }

    [Fact]
    public void Network_targets_are_rewritten_by_dns_and_merged()
    {
        var s = new CaptureSession { ProcessPattern = "app.exe", StartedAtUtc = T0 };
        s.Append(TestData.Access(AccessKind.Network, "203.0.113.10:443", "Connect", "SUCCESS", T0.AddSeconds(1)));
        s.Append(TestData.Access(AccessKind.Network, "203.0.113.11:443", "Connect", "SUCCESS", T0.AddSeconds(2)));
        s.Append(TestData.Access(AccessKind.Network, "198.51.100.7:443", "Connect", "SUCCESS", T0.AddSeconds(3)));
        // The DNS answer may be delivered after the connect; the rewrite is
        // applied at snapshot time, so order does not matter.
        s.Dns.Record("login.example.com", "type: 1 203.0.113.10;type: 1 203.0.113.11;");

        var aggregates = s.SnapshotAggregates();
        Assert.Equal(2, aggregates.Count);
        var merged = Assert.Single(aggregates, a => a.Target == "login.example.com:443");
        Assert.Equal(2, merged.Count);
        Assert.Equal(2, merged.Results["SUCCESS"]);
        Assert.Equal(T0.AddSeconds(1), merged.FirstTimestampUtc);
        Assert.Equal(T0.AddSeconds(2), merged.LastTimestampUtc);
        Assert.Single(aggregates, a => a.Target == "198.51.100.7:443");
    }

    [Fact]
    public void Root_exit_and_root_image_are_recorded_once()
    {
        var s = new CaptureSession { ProcessPattern = "app.exe", StartedAtUtc = T0 };
        Assert.Null(s.LastRootExitUtc);
        s.NoteRootExit(T0.AddSeconds(10));
        s.NoteRootExit(T0.AddSeconds(8));
        Assert.Equal(T0.AddSeconds(10), s.LastRootExitUtc);

        s.NoteRootImage(@"<PROGRAMFILES>\Vendor\app.exe", "1.0.0.0");
        s.NoteRootImage(@"<PROGRAMFILES>\Vendor\other.exe", "9.9.9.9");
        Assert.Equal(@"<PROGRAMFILES>\Vendor\app.exe", s.AppImagePath);
        Assert.Equal("1.0.0.0", s.AppVersion);
    }

    [Fact]
    public void ImportBaseline_rebuilds_aggregates_with_offsets()
    {
        var baseline = TestData.BaselineWith(
            TestData.Entry(AccessKind.File, @"<WINDOWS>\a.dll", "Create", "", 500, ("SUCCESS", 4)),
            TestData.Entry(AccessKind.File, @"<WINDOWS>\b.dll", "Create", "", 2500, ("OBJECT_NAME_NOT_FOUND", 1)));
        baseline.Entries[0].Images.Add("app.exe");

        var s = new CaptureSession { ProcessPattern = "app.exe", StartedAtUtc = T0 };
        s.ImportBaseline(baseline);

        var aggregates = s.SnapshotAggregates();
        Assert.Equal(2, aggregates.Count);
        var a = Assert.Single(aggregates, x => x.Target == @"<WINDOWS>\a.dll");
        Assert.Equal(4, a.Count);
        Assert.Equal(4, a.Results["SUCCESS"]);
        Assert.Equal(T0.AddMilliseconds(500), a.FirstTimestampUtc);
        Assert.Equal(new[] { "app.exe" }, a.Images);
        Assert.Equal(T0.AddMilliseconds(500), s.FirstEventUtc);
        Assert.Equal(T0.AddMilliseconds(2500), s.LastEventUtc);
        Assert.Equal(5, s.TotalEventCount);
        Assert.Equal(T0 + baseline.Duration, s.StoppedAtUtc);
    }
}
