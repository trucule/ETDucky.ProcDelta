using ETDucky.ProcDelta.Services;
using Microsoft.Win32;
using Xunit;

namespace ETDucky.ProcDelta.Tests;

/// <summary>
/// A launch target can be a full path, a relative path, or a bare name,
/// and a bare name is found the way the Run dialog finds it. cmd.exe is
/// the fixture: it is in System32, which is on PATH on every Windows host.
/// </summary>
public class ProcessLauncherTests
{
    private static string SystemCmd => Path.Combine(Environment.SystemDirectory, "cmd.exe");

    [Theory]
    [InlineData("cmd")]
    [InlineData("cmd.exe")]
    [InlineData("CMD.EXE")]
    [InlineData("  \"cmd.exe\"  ")]
    public void Bare_names_resolve_through_PATH_with_exe_appended(string target)
    {
        var resolved = ProcessLauncher.ResolveExecutable(target);

        Assert.NotNull(resolved);
        Assert.Equal(SystemCmd, resolved, ignoreCase: true);
    }

    [Fact]
    public void Full_paths_are_returned_as_given_when_the_file_exists()
    {
        Assert.Equal(SystemCmd, ProcessLauncher.ResolveExecutable(SystemCmd), ignoreCase: true);
        Assert.Null(ProcessLauncher.ResolveExecutable(Path.Combine(Environment.SystemDirectory, "no-such-program-9f3a.exe")));
    }

    [Fact]
    public void Relative_paths_are_taken_from_the_current_directory()
    {
        // The fixture sits under the current directory so the relative path
        // has a directory part and stays relative on every drive layout.
        var folder = "procdelta-fixture-" + Guid.NewGuid().ToString("N");
        var dir = Path.Combine(Environment.CurrentDirectory, folder);
        Directory.CreateDirectory(dir);
        var exe = Path.Combine(dir, "fixture.exe");
        File.WriteAllBytes(exe, new byte[] { 0x4D, 0x5A });
        try
        {
            Assert.Equal(exe, ProcessLauncher.ResolveExecutable(folder + @"\fixture.exe"), ignoreCase: true);
            Assert.Equal(exe, ProcessLauncher.ResolveExecutable(@".\" + folder + @"\fixture.exe"), ignoreCase: true);
            Assert.Null(ProcessLauncher.ResolveExecutable(folder + @"\missing.exe"));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("no-such-program-9f3a")]
    [InlineData("no-such-program-9f3a.exe")]
    [InlineData(@"Z:\no\such\dir\no-such-program-9f3a.exe")]
    public void Targets_that_match_nothing_resolve_to_null(string target)
    {
        Assert.Null(ProcessLauncher.ResolveExecutable(target));
    }

    [Fact]
    public void App_Paths_registrations_are_honoured_for_names_not_on_PATH()
    {
        // HKCU App Paths is writable without elevation and is the first hive
        // the lookup reads. The name is unique so no real registration is
        // touched, and the key is removed whatever the assertion does.
        var name = "procdelta-test-" + Guid.NewGuid().ToString("N") + ".exe";
        const string appPaths = @"Software\Microsoft\Windows\CurrentVersion\App Paths";
        using (var key = Registry.CurrentUser.CreateSubKey(appPaths + @"\" + name))
        {
            key.SetValue(null, "\"" + SystemCmd + "\"");
        }
        try
        {
            Assert.Equal(SystemCmd, ProcessLauncher.ResolveExecutable(name), ignoreCase: true);
            Assert.Equal(SystemCmd, ProcessLauncher.ResolveExecutable(Path.GetFileNameWithoutExtension(name)), ignoreCase: true);
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(appPaths + @"\" + name, throwOnMissingSubKey: false);
        }
    }

    [Fact]
    public void PatternFor_uses_the_file_name_of_the_resolved_executable()
    {
        Assert.Equal("cmd.exe", ProcessLauncher.PatternFor("cmd"));
        Assert.Equal("cmd.exe", ProcessLauncher.PatternFor(SystemCmd));
        Assert.Equal("no-such-program-9f3a", ProcessLauncher.PatternFor("no-such-program-9f3a"));
        Assert.Equal("Acrobat.exe", ProcessLauncher.PatternFor(@"C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe"));
    }

    [Fact]
    public void Launch_reports_an_unresolvable_target_without_starting_anything()
    {
        var result = ProcessLauncher.Launch("no-such-program-9f3a", null);

        Assert.False(result.Started);
        Assert.False(result.Elevated);
        Assert.Equal(string.Empty, result.ResolvedPath);
        Assert.StartsWith("Not found: no-such-program-9f3a", result.Note, StringComparison.Ordinal);
        Assert.Contains("App Paths", result.Note, StringComparison.Ordinal);
    }
}
