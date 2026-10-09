using System.Net;
using System.Net.Sockets;
using System.Text;
using ETDucky.ProcDelta.Models;
using ETDucky.ProcDelta.Services;
using Microsoft.Win32;
using Xunit;

namespace ETDucky.ProcDelta.Tests;

/// <summary>
/// The gate: with default options the inspector must not open a socket or
/// touch a network path, and must not print registry value content. These
/// run on Windows only (HKCU, loopback), which is where the app runs.
/// </summary>
public class LiveStateInspectorTests
{
    [Theory]
    [InlineData(@"\\fileserver\share\file.txt", true)]
    [InlineData(@"\\?\UNC\fileserver\share\file.txt", true)]
    [InlineData(@"\??\UNC\fileserver\share\file.txt", true)]
    [InlineData(@"\Device\Mup\fileserver\share\file.txt", true)]
    [InlineData(@"\Device\LanmanRedirector\;Z:000000000001\fileserver\share", true)]
    [InlineData(@"//fileserver/share/file.txt", true)]
    [InlineData(@"\\.\pipe\something", true)]
    [InlineData(@"\\.\PhysicalDrive0", true)]
    [InlineData(@"C:\Windows\System32\kernel32.dll", false)]
    [InlineData(@"\\?\C:\Windows\System32\kernel32.dll", false)]
    [InlineData(@"\Device\HarddiskVolume3\Windows\x.dll", false)]
    [InlineData("relative\\path.txt", false)]
    [InlineData("", false)]
    public void IsNetworkPath_classifies_every_spelling(string path, bool expected)
        => Assert.Equal(expected, LiveStateInspector.IsNetworkPath(path));

    [Fact]
    public void Default_options_are_both_off()
    {
        Assert.False(InspectOptions.Default.AllowNetwork);
        Assert.False(InspectOptions.Default.ShowRegistryValues);
        Assert.Equal(InspectOptions.Default, new InspectOptions());
    }

    [Theory]
    [InlineData(AccessKind.File)]
    [InlineData(AccessKind.Process)]
    public void Network_paths_are_not_touched_without_consent(AccessKind kind)
    {
        // 127.0.0.1 as a UNC server would open an SMB session to the local
        // host if the gate were missing. The three-argument overload is the
        // "no options given" path and must be just as closed.
        var target = @"\\127.0.0.1\nonexistent-share\x.txt";

        var viaDefault = LiveStateInspector.Inspect(kind, target, "");
        var viaOptions = LiveStateInspector.Inspect(kind, target, "", InspectOptions.Default);

        Assert.StartsWith(LiveStateInspector.NetworkPathDisabled, viaDefault);
        Assert.StartsWith(LiveStateInspector.NetworkPathDisabled, viaOptions);
    }

    [Fact]
    public void Tcp_targets_are_not_probed_without_consent()
    {
        var viaDefault = LiveStateInspector.Inspect(AccessKind.Network, "127.0.0.1:9", "");
        var viaOptions = LiveStateInspector.Inspect(AccessKind.Network, "https://127.0.0.1:9/x", "", InspectOptions.Default);

        Assert.Equal(LiveStateInspector.NetworkProbingDisabled, viaDefault);
        Assert.Equal(LiveStateInspector.NetworkProbingDisabled, viaOptions);
    }

    [Fact]
    public void Tcp_probe_runs_only_when_allowed()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var target = $"127.0.0.1:{port}";

            var closed = LiveStateInspector.Inspect(AccessKind.Network, target, "", new InspectOptions(AllowNetwork: false));
            Assert.Equal(LiveStateInspector.NetworkProbingDisabled, closed);

            var open = LiveStateInspector.Inspect(AccessKind.Network, target, "", new InspectOptions(AllowNetwork: true));
            Assert.Contains("succeeded", open);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public void Local_files_are_still_inspected_with_default_options()
    {
        var text = LiveStateInspector.Inspect(AccessKind.File, Environment.SystemDirectory + @"\kernel32.dll", "", InspectOptions.Default);
        Assert.StartsWith("File present", text);
    }

    [Fact]
    public void Stream_paths_report_the_acl_of_their_file()
    {
        // The ACL API rejects file:stream paths; the stream shares the
        // file's descriptor, so the inspector reads it from the file.
        var path = Path.Combine(Path.GetTempPath(), $"procdelta-test-{Guid.NewGuid():N}.txt");
        File.WriteAllText(path, "body");
        File.WriteAllText(path + ":probe", "stream body");
        try
        {
            var text = LiveStateInspector.Inspect(AccessKind.File, path + ":probe", "", InspectOptions.Default);
            Assert.StartsWith("File present, 11 bytes", text);
            Assert.DoesNotContain("read failed", text);
            Assert.Contains("ACL: ", text);
            Assert.Contains("=allow:", text);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Registry_values_are_hidden_unless_shown()
    {
        const string parent = @"Software\ETDucky.ProcDelta.Tests";
        var sub = parent + @"\" + Guid.NewGuid().ToString("N");
        const string valueName = "Token";
        const string secret = "SECRET-VALUE-123";

        using (var key = Registry.CurrentUser.CreateSubKey(sub))
        {
            Assert.NotNull(key);
            key!.SetValue(valueName, secret, RegistryValueKind.String);
        }

        try
        {
            var target = @"HKEY_CURRENT_USER\" + sub;
            var expectedHash = RegistryPaths.HashString(Encoding.UTF8.GetBytes(secret));

            var hidden = LiveStateInspector.Inspect(AccessKind.Registry, target, valueName, InspectOptions.Default);
            Assert.DoesNotContain(secret, hidden);
            Assert.Contains("Content hidden", hidden);
            Assert.Contains(expectedHash, hidden);
            Assert.Contains($"{Encoding.UTF8.GetByteCount(secret)} bytes", hidden);

            var shown = LiveStateInspector.Inspect(AccessKind.Registry, target, valueName, new InspectOptions(ShowRegistryValues: true));
            Assert.Contains(secret, shown);

            // Key-only lookups never had content to hide and still work.
            var keyOnly = LiveStateInspector.Inspect(AccessKind.Registry, target, "", InspectOptions.Default);
            Assert.StartsWith("Key present.", keyOnly);
        }
        finally
        {
            DeleteTestKey(parent, sub);
        }
    }

    [Fact]
    public void Hidden_registry_hash_matches_what_the_recorder_writes_into_baselines()
    {
        // The report's hidden-value hash must be the same string a baseline
        // entry carries in ValueHash, or an operator cannot compare them.
        const string parent = @"Software\ETDucky.ProcDelta.Tests";
        var sub = parent + @"\" + Guid.NewGuid().ToString("N");
        using (var key = Registry.CurrentUser.CreateSubKey(sub))
        {
            key!.SetValue("Flag", 7, RegistryValueKind.DWord);
        }

        try
        {
            var target = @"HKEY_CURRENT_USER\" + sub;
            var live = RegistryValueCache.HashLiveValue(target, "Flag");
            Assert.NotNull(live);

            var hidden = LiveStateInspector.Inspect(AccessKind.Registry, target, "Flag", InspectOptions.Default);
            Assert.Contains(live!.Hash, hidden);
            Assert.Equal("DWord", live.TypeName);
        }
        finally
        {
            DeleteTestKey(parent, sub);
        }
    }

    [Fact]
    public void Expand_string_values_hash_their_stored_text_not_the_local_expansion()
    {
        const string parent = @"Software\ETDucky.ProcDelta.Tests";
        var sub = parent + @"\" + Guid.NewGuid().ToString("N");
        const string stored = @"%USERPROFILE%\Vendor\cache";
        using (var key = Registry.CurrentUser.CreateSubKey(sub))
        {
            key!.SetValue("CachePath", stored, RegistryValueKind.ExpandString);
        }

        try
        {
            var target = @"HKEY_CURRENT_USER\" + sub;
            var expected = RegistryPaths.HashString(Encoding.UTF8.GetBytes(stored));

            var live = RegistryValueCache.HashLiveValue(target, "CachePath");
            Assert.NotNull(live);
            Assert.Equal(expected, live!.Hash);

            var hidden = LiveStateInspector.Inspect(AccessKind.Registry, target, "CachePath", InspectOptions.Default);
            Assert.Contains(expected, hidden);
        }
        finally
        {
            DeleteTestKey(parent, sub);
        }
    }

    /// <summary>
    /// Removes this test's own key, then the shared parent only when it is
    /// empty, so tests never delete each other's keys if they ever run in
    /// parallel.
    /// </summary>
    private static void DeleteTestKey(string parent, string sub)
    {
        Registry.CurrentUser.DeleteSubKeyTree(sub, throwOnMissingSubKey: false);
        try { Registry.CurrentUser.DeleteSubKey(parent, throwOnMissingSubKey: false); }
        catch (InvalidOperationException) { /* another test's key is still there */ }
    }
}
