using ETDucky.ProcDelta.Services;
using Xunit;

namespace ETDucky.ProcDelta.Tests;

/// <summary>
/// EventLog is the fixture: it is installed and running on every Windows
/// host, with an Automatic start type.
/// </summary>
public class ServiceStateTests
{
    [Theory]
    [InlineData("service:ClipSVC", true, "ClipSVC")]
    [InlineData("SERVICE:wuauserv", true, "wuauserv")]
    [InlineData(@"C:\Windows\service:x", false, @"C:\Windows\service:x")]
    [InlineData("", false, "")]
    public void Service_targets_carry_the_prefix_the_capture_writes(string target, bool isService, string name)
    {
        Assert.Equal(isService, ServiceState.IsServiceTarget(target));
        Assert.Equal(name, ServiceState.NameOf(target));
    }

    [Theory]
    [InlineData("ServiceStart", true)]
    [InlineData("servicestart", true)]
    [InlineData("ServiceStop", false)]
    [InlineData("ServiceStartTypeChanged", false)]
    [InlineData("StartType", false)]
    [InlineData("Start", false)]
    [InlineData("", false)]
    public void Only_a_service_start_is_a_start_operation(string operation, bool expected)
    {
        Assert.Equal(expected, ServiceState.IsStartOperation(operation));
    }

    [Fact]
    public void Running_service_is_reported_with_its_start_type()
    {
        Assert.Equal(ServiceState.Status.Running, ServiceState.Query("EventLog"));
        Assert.Equal("Automatic", ServiceState.StartTypeOf("EventLog"));
        Assert.Equal(new ServiceState.Snapshot(ServiceState.Status.Running, "Automatic"), ServiceState.Take("EventLog"));
        Assert.Equal("Service EventLog is running (start type Automatic).", ServiceState.Describe("EventLog"));
    }

    [Fact]
    public void Unknown_service_is_not_installed()
    {
        Assert.Equal(ServiceState.Status.NotInstalled, ServiceState.Query("no-such-service-9f3a"));
        Assert.Equal("unknown", ServiceState.StartTypeOf("no-such-service-9f3a"));
        Assert.Equal(new ServiceState.Snapshot(ServiceState.Status.NotInstalled, "unknown"), ServiceState.Take("no-such-service-9f3a"));
        Assert.Equal("Service no-such-service-9f3a is not installed on this host.", ServiceState.Describe("no-such-service-9f3a"));
        Assert.Equal(ServiceState.Status.Unavailable, ServiceState.Query(""));
    }

    [Theory]
    [InlineData(ServiceState.Status.Stopped, "Disabled", true, true)]
    [InlineData(ServiceState.Status.NotInstalled, "unknown", false, true)]
    [InlineData(ServiceState.Status.Stopped, "Manual", false, false)]
    [InlineData(ServiceState.Status.Stopped, "Automatic", false, false)]
    [InlineData(ServiceState.Status.Running, "Disabled", false, false)]
    [InlineData(ServiceState.Status.Unavailable, "unknown", false, false)]
    public void A_snapshot_knows_whether_anything_can_start_the_service(ServiceState.Status status, string startType, bool disabled, bool cannotStart)
    {
        var snapshot = new ServiceState.Snapshot(status, startType);
        Assert.Equal(disabled, snapshot.IsDisabled);
        Assert.Equal(cannotStart, snapshot.CannotStart);
    }

    [Fact]
    public void A_disabled_service_gets_the_extra_sentence()
    {
        var text = ServiceState.Describe("Example", new ServiceState.Snapshot(ServiceState.Status.Stopped, "Disabled"));
        Assert.Equal("Service Example is stopped (start type Disabled). A disabled service cannot be started by the application.", text);
        Assert.Equal("Service Example is paused (start type Manual).", ServiceState.Describe("Example", new ServiceState.Snapshot(ServiceState.Status.Paused, "Manual")));
    }
}
