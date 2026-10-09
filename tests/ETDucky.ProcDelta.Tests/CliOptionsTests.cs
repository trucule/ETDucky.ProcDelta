using Xunit;

namespace ETDucky.ProcDelta.Tests;

public class CliOptionsTests
{
    [Fact]
    public void Parses_verb_values_and_flags()
    {
        var o = CliOptions.Parse(new[] { "Compare", "--baseline", @"C:\b.json", "--report", "out.md", "--probe-network", "--duration=30", "--fail-on-findings" });

        Assert.Equal("compare", o.Verb);
        Assert.Equal(@"C:\b.json", o.Get("baseline"));
        Assert.Equal("out.md", o.Get("report"));
        Assert.Equal(30, o.GetInt("duration"));
        Assert.True(o.Has("probe-network"));
        Assert.True(o.Has("fail-on-findings"));
        Assert.True(o.Has("duration"));
        Assert.False(o.Has("show-values"));
        Assert.Null(o.Get("missing"));
        Assert.Null(o.GetInt("report"));
        Assert.Empty(o.Errors);
    }

    [Fact]
    public void A_flag_before_another_option_takes_no_value()
    {
        var o = CliOptions.Parse(new[] { "record", "--include-user", "--out", "x.json" });
        Assert.True(o.Has("include-user"));
        Assert.Equal("x.json", o.Get("out"));
    }

    [Fact]
    public void Stray_positional_arguments_are_errors()
    {
        var o = CliOptions.Parse(new[] { "record", "oops", "--out", "x.json" });
        Assert.Single(o.Errors);
        Assert.Equal("x.json", o.Get("out"));
    }

    [Fact]
    public void No_arguments_means_no_verb()
    {
        var o = CliOptions.Parse(Array.Empty<string>());
        Assert.Equal(string.Empty, o.Verb);
        Assert.Empty(o.Errors);
    }
}
