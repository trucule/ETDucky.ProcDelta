using ETDucky.ProcDelta.Services;
using Xunit;

namespace ETDucky.ProcDelta.Tests;

public class DnsCacheTests
{
    [Fact]
    public void ParseAddresses_reads_the_dns_client_result_string()
    {
        var addresses = DnsCache.ParseAddresses("type: 5 cdn.example.com;type: 1 93.184.216.34;::ffff:93.184.216.35;2606:2800:220:1:248:1893:25c8:1946;");
        Assert.Equal(new[] { "93.184.216.34", "93.184.216.35", "2606:2800:220:1:248:1893:25c8:1946" }, addresses);
    }

    [Fact]
    public void ParseAddresses_ignores_bare_numbers_and_names()
    {
        Assert.Empty(DnsCache.ParseAddresses("type: 5 cdn.example.com;"));
        Assert.Empty(DnsCache.ParseAddresses(""));
        Assert.Empty(DnsCache.ParseAddresses(null));
    }

    [Fact]
    public void RewriteEndpoint_keys_known_addresses_by_hostname()
    {
        var cache = new DnsCache();
        cache.Record("Login.Example.COM.", "type: 1 203.0.113.10;type: 1 203.0.113.11;");

        Assert.Equal("login.example.com:443", cache.RewriteEndpoint("203.0.113.10:443"));
        Assert.Equal("login.example.com:443", cache.RewriteEndpoint("203.0.113.11:443"));
        Assert.Equal("203.0.113.12:443", cache.RewriteEndpoint("203.0.113.12:443"));
        Assert.Equal("https://203.0.113.10/x", cache.RewriteEndpoint("https://203.0.113.10/x"));
        Assert.Equal("tcp-connect-failure", cache.RewriteEndpoint("tcp-connect-failure"));
        Assert.Equal("login.example.com", cache.HostFor("::ffff:203.0.113.10"));
        Assert.Null(cache.HostFor("not an address"));
    }

    [Fact]
    public void Two_machines_resolving_differently_produce_the_same_key()
    {
        var good = new DnsCache();
        good.Record("cdn.example.com", "type: 1 13.107.42.14;");
        var broken = new DnsCache();
        broken.Record("cdn.example.com", "type: 1 13.107.43.12;");

        Assert.Equal(good.RewriteEndpoint("13.107.42.14:443"), broken.RewriteEndpoint("13.107.43.12:443"));
    }
}
