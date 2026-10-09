using ETDucky.ProcDelta.Services;
using Xunit;

namespace ETDucky.ProcDelta.Tests;

public class PathNormalizerTokenTests
{
    [Theory]
    [InlineData(@"<LOCALAPPDATA>\Vendor\Cache\{3F2504E0-4F89-11D3-9A0C-0305E82C3301}\index.dat",
                @"<LOCALAPPDATA>\Vendor\Cache\<GUID>\index.dat")]
    [InlineData(@"<LOCALAPPDATA>\Vendor\3f2504e04f8911d39a0c0305e82c3301.json",
                @"<LOCALAPPDATA>\Vendor\<HEX>.json")]
    [InlineData(@"<TEMP>\tmpA1B2.tmp", @"<TEMP>\<TMP>.tmp")]
    [InlineData(@"<TEMP>\~DF8E1C9A2B.TMP", @"<TEMP>\<TMP>.tmp")]
    [InlineData(@"<TEMP>\3f2504e0-4f89-11d3-9a0c-0305e82c3301", @"<TEMP>\<GUID>")]
    [InlineData(@"<PROGRAMDATA>\Package Cache\{3F2504E0-4F89-11D3-9A0C-0305E82C3301}v14.0\vc_redist.x64.exe",
                @"<PROGRAMDATA>\Package Cache\{3F2504E0-4F89-11D3-9A0C-0305E82C3301}v14.0\vc_redist.x64.exe")]
    public void Volatile_segments_become_tokens(string input, string expected)
        => Assert.Equal(expected, PathNormalizer.TokeniseVolatileSegments(input));

    [Theory]
    [InlineData(@"<PROGRAMFILES>\Vendor\App\128.0.6613.84\app.exe")]
    [InlineData(@"<WINDOWS>\WinSxS\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.26100.1_none_1a2b3c4d\gdiplus.dll")]
    [InlineData(@"<SYSTEM32>\kernel32.dll")]
    [InlineData(@"<LOCALAPPDATA>\Vendor\settings.json")]
    [InlineData(@"<LOCALAPPDATA>\Vendor\deadbeef.cache")]
    public void Ordinary_segments_are_untouched(string input)
        => Assert.Same(input, PathNormalizer.TokeniseVolatileSegments(input));

    [Fact]
    public void Registry_paths_keep_their_guids()
    {
        // A CLSID is a stable identifier. NormalizeRegistry must never run
        // the volatile-segment pass.
        const string key = @"\REGISTRY\MACHINE\SOFTWARE\Classes\CLSID\{3F2504E0-4F89-11D3-9A0C-0305E82C3301}\InprocServer32";
        var normalized = PathNormalizer.NormalizeRegistry(key);
        Assert.Equal(@"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{3F2504E0-4F89-11D3-9A0C-0305E82C3301}\InprocServer32", normalized);
    }

    [Fact]
    public void Normalize_applies_root_tokens_then_volatile_tokens()
    {
        var temp = Path.GetTempPath().TrimEnd('\\');
        var input = temp + @"\{3F2504E0-4F89-11D3-9A0C-0305E82C3301}\work.tmp";
        var normalized = PathNormalizer.Normalize(input);
        Assert.StartsWith("<", normalized);
        Assert.EndsWith(@"\<GUID>\<TMP>.tmp", normalized);
        Assert.True(PathNormalizer.ContainsToken(normalized));
    }

    [Fact]
    public void ControlSet_and_other_user_sids_are_folded()
    {
        Assert.Equal(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Foo",
            PathNormalizer.NormalizeRegistry(@"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Foo"));
        Assert.Equal(@"HKEY_USERS\<SID>\Software\Vendor",
            PathNormalizer.NormalizeRegistry(@"\REGISTRY\USER\S-1-5-21-1111111111-2222222222-3333333333-1001\Software\Vendor"));
    }
}
