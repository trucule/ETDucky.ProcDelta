using ETDucky.ProcDelta.Models;
using ETDucky.ProcDelta.Services;
using Xunit;

namespace ETDucky.ProcDelta.Tests;

public class StorageArtifactsTests
{
    [Theory]
    [InlineData(AccessKind.File, @"<SYSTEM32>\en-US\app.exe.mui:WofCompressedData", true)]
    [InlineData(AccessKind.File, @"C:\Windows\System32\en-US\app.exe.mui:wofcompresseddata", true)]
    [InlineData(AccessKind.File, @"<SYSTEM32>\en-US\app.exe.mui", false)]
    [InlineData(AccessKind.File, @"<USERPROFILE>\Downloads\setup.exe:Zone.Identifier", false)]
    [InlineData(AccessKind.File, @"C:\data\WofCompressedData", false)]
    [InlineData(AccessKind.File, "", false)]
    [InlineData(AccessKind.Registry, @"HKEY_LOCAL_MACHINE\SOFTWARE\x:WofCompressedData", false)]
    public void Only_the_storage_stack_s_own_streams_are_artifacts(AccessKind kind, string target, bool expected)
    {
        Assert.Equal(expected, StorageArtifacts.IsStorageArtifact(kind, target));
    }

    [Theory]
    [InlineData(@"C:\dir\file.txt:Zone.Identifier", @"C:\dir\file.txt")]
    [InlineData(@"C:\dir\file.txt:WofCompressedData", @"C:\dir\file.txt")]
    [InlineData(@"C:\dir\file.txt:stream:$DATA", @"C:\dir\file.txt")]
    [InlineData(@"C:\dir\file.txt", @"C:\dir\file.txt")]
    [InlineData(@"C:\dir.v2\file", @"C:\dir.v2\file")]
    [InlineData(@"C:\di:r\file.txt", @"C:\di:r\file.txt")]
    [InlineData(@"\\server\share\file.txt:probe", @"\\server\share\file.txt")]
    [InlineData(@"C:", @"C:")]
    [InlineData("", "")]
    public void FileOfStream_strips_only_a_stream_suffix(string path, string expected)
    {
        Assert.Equal(expected, StorageArtifacts.FileOfStream(path));
    }
}
