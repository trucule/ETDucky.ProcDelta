using ETDucky.ProcDelta.Services;
using Xunit;

namespace ETDucky.ProcDelta.Tests;

public class TargetScrubberTests
{
    [Theory]
    [InlineData("https://api.example.com/v1/token?sig=SECRET&sv=2024-01-01", "https://api.example.com/v1/token")]
    [InlineData("https://example.com/path#access_token=abc", "https://example.com/path")]
    [InlineData("https://user:pw@example.com/x", "https://example.com/x")]
    [InlineData("https://example.com", "https://example.com/")]
    [InlineData("http://example.com:8080/a/b", "http://example.com:8080/a/b")]
    [InlineData("https://example.com:443/a", "https://example.com/a")]
    [InlineData("HTTPS://Example.COM/A?b=c", "https://example.com/A")]
    public void ScrubUrl_keeps_scheme_host_port_and_path_only(string input, string expected)
        => Assert.Equal(expected, TargetScrubber.ScrubUrl(input));

    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("example.com/path?token=abc", "example.com/path")]
    [InlineData("user:pw@example.com", "example.com")]
    [InlineData("(unknown)", "(unknown)")]
    [InlineData("", "")]
    public void ScrubUrl_handles_values_that_are_not_absolute_urls(string input, string expected)
        => Assert.Equal(expected, TargetScrubber.ScrubUrl(input));

    [Fact]
    public void ScrubUrl_output_is_stable_across_runs_with_different_query_strings()
    {
        var a = TargetScrubber.ScrubUrl("https://cdn.example.com/app/update.json?ts=1&nonce=abc");
        var b = TargetScrubber.ScrubUrl("https://cdn.example.com/app/update.json?ts=2&nonce=xyz");
        Assert.Equal(a, b);
    }
}
