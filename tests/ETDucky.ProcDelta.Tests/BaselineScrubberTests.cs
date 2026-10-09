using ETDucky.ProcDelta.Models;
using ETDucky.ProcDelta.Services;
using Xunit;

namespace ETDucky.ProcDelta.Tests;

public class BaselineScrubberTests
{
    private static Baseline With(params Baseline.Entry[] entries)
        => new() { AppName = "App", Entries = entries.ToList() };

    private static Baseline.Entry Entry(AccessKind kind, string target, string detail = "")
        => new() { Kind = kind, Target = target, Operation = "Create", Detail = detail, Result = "SUCCESS", AccessCount = 1 };

    [Fact]
    public void Flags_entries_whose_target_or_detail_contains_an_at_sign()
    {
        var baseline = With(
            Entry(AccessKind.Registry, @"HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Outlook\Profiles\user@contoso.com"),
            Entry(AccessKind.Registry, @"HKEY_CURRENT_USER\Software\Vendor", detail: "someone@contoso.com"));

        var findings = BaselineScrubber.FindSensitive(baseline);

        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal(BaselineScrubber.ReasonEmail, f.Reason));
    }

    [Fact]
    public void Flags_unc_and_untokenised_drive_paths_but_not_tokenised_or_basename_targets()
    {
        var baseline = With(
            Entry(AccessKind.File, @"\\fileserver\clients\acme\contract.pdf"),
            Entry(AccessKind.File, @"\\?\UNC\fileserver\share\x"),
            Entry(AccessKind.File, @"D:\Clients\Acme\contract.pdf"),
            Entry(AccessKind.File, @"<APPDATA>\Vendor\settings.json"),
            Entry(AccessKind.File, @"<USERS>\<OTHERUSER>\Desktop\x.txt"),
            Entry(AccessKind.File, @"\Device\HarddiskVolume3\Windows\x.dll"),
            Entry(AccessKind.File, @"\\?\C:\Windows\System32\x.dll"),
            Entry(AccessKind.Process, "AcroCEF.exe"),
            Entry(AccessKind.Network, "10.0.0.5:443"));

        var findings = BaselineScrubber.FindSensitive(baseline);

        Assert.Equal(3, findings.Count);
        Assert.Equal(BaselineScrubber.ReasonUncPath, findings[0].Reason);
        Assert.Equal(@"\\fileserver\clients\acme\contract.pdf", findings[0].Target);
        Assert.Equal(BaselineScrubber.ReasonUncPath, findings[1].Reason);
        Assert.Equal(BaselineScrubber.ReasonUntokenisedPath, findings[2].Reason);
        Assert.Equal(@"D:\Clients\Acme\contract.pdf", findings[2].Target);
    }

    [Fact]
    public void Drive_paths_are_only_checked_for_file_and_process_kinds()
    {
        // A registry target never starts with a drive letter, but a Network
        // target could be anything WinINet reported. Only File/Process
        // targets are paths.
        var baseline = With(Entry(AccessKind.Network, @"C:\not-a-host"));
        Assert.Empty(BaselineScrubber.FindSensitive(baseline));
    }

    [Fact]
    public void Clean_baseline_has_no_findings()
    {
        var baseline = With(
            Entry(AccessKind.File, @"<PROGRAMFILES>\Vendor\app.exe"),
            Entry(AccessKind.Registry, @"HKEY_LOCAL_MACHINE\SOFTWARE\Vendor", detail: "InstallPath"),
            Entry(AccessKind.Network, "203.0.113.10:443"),
            Entry(AccessKind.Process, "app.exe"));

        Assert.Empty(BaselineScrubber.FindSensitive(baseline));
    }
}
