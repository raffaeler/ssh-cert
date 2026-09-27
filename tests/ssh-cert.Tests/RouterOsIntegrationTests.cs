using SshCert.Models;
using SshCert.Provisioning;
using SshCert.Ssh;

namespace SshCert.Tests;

public sealed class RouterOsFixtureFactAttribute : FactAttribute
{
    public RouterOsFixtureFactAttribute()
    {
        if (new[] { "HOST", "USER", "ADMIN", "PASSWORD", "HOST_FINGERPRINT" }
            .Any(name => string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("SSHCERT_ROUTER_TEST_" + name))))
            Skip = "Requires an explicitly authorized RouterOS 7.20+ lab account and pinned host fingerprint.";
    }
}

public class RouterOsIntegrationTests
{
    [RouterOsFixtureFact]
    public async Task ProvisionIsIdempotentKeyOnlyLoginWorksAndExactKeyCanBeRevoked()
    {
        static string Setting(string name) => Environment.GetEnvironmentVariable("SSHCERT_ROUTER_TEST_" + name)
            ?? throw new InvalidOperationException("Missing RouterOS lab setting: " + name);
        using var local = new TestHome();
        var remote = StateTests.Remote(local, "router-test-" + Guid.NewGuid().ToString("N")[..8]) with
        {
            Kind = ServerKind.MikroTik, Host = Setting("HOST"), User = Setting("USER"),
            Port = int.Parse(Environment.GetEnvironmentVariable("SSHCERT_ROUTER_TEST_PORT") ?? "22")
        };
        Validation.Remote(remote);
        var expectedFingerprint = Setting("HOST_FINGERPRINT");
        if (!System.Text.RegularExpressions.Regex.IsMatch(expectedFingerprint, @"^SHA256:[A-Za-z0-9+/]{43}$"))
            throw new InvalidOperationException("Supply the independently verified SHA256 host fingerprint.");
        var transport = new SshTransport(new HostTrust(local.Store, prompt =>
            prompt.EndsWith(" " + expectedFingerprint + "? Verify this fingerprint independently.", StringComparison.Ordinal)),
            _ => throw new InvalidOperationException("The lab account must not require additional interactive challenges."));
        var login = new Login(Setting("ADMIN"), Password: Setting("PASSWORD"));
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        using var session = await transport.Connect(remote, login, timeout.Token);
        Exception? failure = null;
        try
        {
            remote = await MikroTikProvisioner.Provision(session, remote, timeout.Token);
            await transport.Test(remote, "", timeout.Token);
            var repeated = await MikroTikProvisioner.Provision(session, remote, timeout.Token);
            Assert.Equal(remote.RouterKeyId, repeated.RouterKeyId);
        }
        catch (Exception ex) { failure = ex; throw; }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(45));
            try { await MikroTikProvisioner.Revoke(session, remote, cleanup.Token); }
            catch (Exception ex)
            {
                throw new AggregateException($"Lab cleanup failed. Inspect only {remote.User}'s generated key " +
                    $"{KeyService.Fingerprint(remote.PublicKey)} on {remote.Host}.",
                    failure is null ? [ex] : [failure, ex]);
            }
        }
        await Assert.ThrowsAnyAsync<Renci.SshNet.Common.SshException>(() => transport.Test(remote, "", timeout.Token));
    }
}
