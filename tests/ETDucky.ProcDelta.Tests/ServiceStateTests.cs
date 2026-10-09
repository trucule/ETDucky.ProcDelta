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
        Assert.Equal("Service EventLog is running (start type Automatic).", ServiceState.Describe("EventLog"));
    }

    [Fact]
    public void Unknown_service_is_not_installed()
    {
        Assert.Equal(ServiceState.Status.NotInstalled, ServiceState.Query("no-such-service-9f3a"));
        Assert.Equal("unknown", ServiceState.StartTypeOf("no-such-service-9f3a"));
        Assert.Equal("Service no-such-service-9f3a is not installed on this host.", ServiceState.Describe("no-such-service-9f3a"));
        Assert.Equal(ServiceState.Status.Unavailable, ServiceState.Query(""));
    }
}
