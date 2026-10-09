using ETDucky.ProcDelta.Services;
using Xunit;

namespace ETDucky.ProcDelta.Tests;

public class ResultSemanticsTests
{
    [Theory]
    [InlineData(0, true)]                      // STATUS_SUCCESS
    [InlineData(0x00000103, true)]             // STATUS_PENDING (informational)
    [InlineData(0x40000000, true)]             // STATUS_OBJECT_NAME_EXISTS (informational)
    [InlineData(unchecked((int)0x80000005), false)] // STATUS_BUFFER_OVERFLOW (warning)
    [InlineData(unchecked((int)0xC0000034), false)] // STATUS_OBJECT_NAME_NOT_FOUND (error)
    public void NtSuccess_follows_the_severity_bits(int status, bool expected)
        => Assert.Equal(expected, ResultSemantics.NtSuccess(status));

    [Theory]
    [InlineData(0, "SUCCESS")]
    [InlineData(0x40000000, "SUCCESS")]
    [InlineData(unchecked((int)0x80000005), "BUFFER_OVERFLOW")]
    [InlineData(unchecked((int)0xC0000023), "BUFFER_TOO_SMALL")]
    [InlineData(unchecked((int)0xC0000034), "OBJECT_NAME_NOT_FOUND")]
    [InlineData(unchecked((int)0xC0000022), "ACCESS_DENIED")]
    [InlineData(unchecked((int)0xC0001234), "0xC0001234")]
    public void ResultFor_names_known_statuses_and_hexes_the_rest(int status, string expected)
        => Assert.Equal(expected, ResultSemantics.ResultFor(status));

    [Theory]
    [InlineData("BUFFER_OVERFLOW", "QueryValue", true)]
    [InlineData("BUFFER_TOO_SMALL", "QueryValue", true)]
    [InlineData("BUFFER_OVERFLOW", "OpenKey", false)]
    [InlineData("OBJECT_NAME_NOT_FOUND", "QueryValue", false)]
    public void Size_probes_on_QueryValue_are_benign(string result, string operation, bool expected)
        => Assert.Equal(expected, ResultSemantics.IsBenign(result, operation));

    [Fact]
    public void EverSucceeded_looks_at_counts_not_order()
    {
        var results = new Dictionary<string, int> { ["OBJECT_NAME_NOT_FOUND"] = 1, ["SUCCESS"] = 12 };
        Assert.True(ResultSemantics.EverSucceeded(results, "QueryValue"));
        Assert.True(ResultSemantics.EverFailed(results, "QueryValue"));

        var probeOnly = new Dictionary<string, int> { ["BUFFER_OVERFLOW"] = 3 };
        Assert.True(ResultSemantics.EverSucceeded(probeOnly, "QueryValue"));
        Assert.False(ResultSemantics.EverFailed(probeOnly, "QueryValue"));

        var zeroCount = new Dictionary<string, int> { ["SUCCESS"] = 0, ["ACCESS_DENIED"] = 2 };
        Assert.False(ResultSemantics.EverSucceeded(zeroCount, "Create"));
    }

    [Fact]
    public void Describe_orders_by_count_and_omits_x1()
    {
        var results = new Dictionary<string, int> { ["OBJECT_NAME_NOT_FOUND"] = 1, ["SUCCESS"] = 12 };
        Assert.Equal("SUCCESS x12, OBJECT_NAME_NOT_FOUND", ResultSemantics.Describe(results));
        Assert.Equal("(none)", ResultSemantics.Describe(new Dictionary<string, int>()));
    }

    [Theory]
    [InlineData("0", "SUCCESS")]
    [InlineData("", "SUCCESS")]
    [InlineData("success", "SUCCESS")]
    [InlineData("2147954407", "0x80072EE7")]
    [InlineData("0x80072EE7", "0x80072EE7")]
    [InlineData("0x80072ee7", "0x80072EE7")]
    [InlineData("ERROR_INTERNET_TIMEOUT", "ERROR_INTERNET_TIMEOUT")]
    public void NormalizeOutcome_canonicalises_numeric_spellings(string input, string expected)
        => Assert.Equal(expected, ResultSemantics.NormalizeOutcome(input));

    [Theory]
    [InlineData("SUCCESS", true)]
    [InlineData("ExitCode=0", true)]
    [InlineData("ExitCode=1", false)]
    [InlineData("ExitCode=-1073741819", false)]
    public void IsSuccess_covers_exit_codes(string result, bool expected)
        => Assert.Equal(expected, ResultSemantics.IsSuccess(result));
}
