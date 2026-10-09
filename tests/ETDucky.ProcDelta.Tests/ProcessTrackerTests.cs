using ETDucky.ProcDelta.Services;
using Xunit;

namespace ETDucky.ProcDelta.Tests;

public class ProcessTrackerTests
{
    private static ProcessTracker New(string pattern) => new(pattern, seedFromRunningProcesses: false);

    [Fact]
    public void Exact_names_get_exe_appended_and_match_case_insensitively()
    {
        var t = New("acrobat|AcroCEF.exe");
        t.OnProcessStart(10, 1, @"C:\Program Files\Adobe\Acrobat.EXE");
        t.OnProcessStart(11, 1, @"C:\Program Files\Adobe\acrocef.exe");
        t.OnProcessStart(12, 1, @"C:\Windows\explorer.exe");

        Assert.True(t.IsTracked(10));
        Assert.True(t.IsTracked(11));
        Assert.False(t.IsTracked(12));
        Assert.True(t.IsNameMatched(10));
        Assert.Equal("Acrobat.EXE", t.ImageNameFor(10));
    }

    [Fact]
    public void Wildcards_match_without_exe_suffix()
    {
        var t = New("Acro*");
        t.OnProcessStart(10, 1, "Acrobat.exe");
        t.OnProcessStart(11, 1, "AcroCEF.exe");
        t.OnProcessStart(12, 1, "Chrome.exe");
        Assert.True(t.IsTracked(10));
        Assert.True(t.IsTracked(11));
        Assert.False(t.IsTracked(12));
    }

    [Fact]
    public void Children_follow_their_parent_and_cascade_when_the_parent_arrives_late()
    {
        var t = New("app.exe");
        // Rundown delivered grandchild, child, then root: arbitrary order.
        t.OnProcessStart(30, 20, "grandchild.exe");
        t.OnProcessStart(20, 10, "child.exe");
        Assert.False(t.IsTracked(20));
        Assert.False(t.IsTracked(30));

        t.OnProcessStart(10, 1, "app.exe");
        Assert.True(t.IsTracked(10));
        Assert.True(t.IsTracked(20));
        Assert.True(t.IsTracked(30));
        Assert.True(t.IsNameMatched(10));
        Assert.False(t.IsNameMatched(20));
        Assert.Equal(3, t.TrackedCount);

        // A live child of a tracked process joins immediately.
        t.OnProcessStart(40, 30, "helper.exe");
        Assert.True(t.IsTracked(40));
    }

    [Fact]
    public void Stop_removes_the_pid_and_its_name_stays_known_only_while_seen()
    {
        var t = New("app.exe");
        t.OnProcessStart(10, 1, "app.exe");
        t.OnProcessStart(5, 1, "explorer.exe");
        Assert.Equal("explorer.exe", t.KnownImageNameFor(5));
        Assert.Equal(string.Empty, t.ImageNameFor(5));

        t.OnProcessStop(10);
        Assert.False(t.IsTracked(10));
        Assert.Equal(string.Empty, t.KnownImageNameFor(10));
        Assert.Equal(string.Empty, t.KnownImageNameFor(0));
    }

    [Fact]
    public void TrackPid_roots_a_process_regardless_of_pattern()
    {
        var t = New("something-else.exe");
        t.OnProcessStart(20, 10, "child.exe");
        t.TrackPid(10, "launched.exe");

        Assert.True(t.IsTracked(10));
        Assert.True(t.IsNameMatched(10));
        Assert.Equal("launched.exe", t.ImageNameFor(10));
        Assert.True(t.IsTracked(20));
    }

    [Fact]
    public void Empty_pattern_tracks_nothing()
    {
        var t = New("");
        t.OnProcessStart(10, 1, "app.exe");
        Assert.False(t.IsTracked(10));
        Assert.Equal(0, t.TrackedCount);
    }
}
