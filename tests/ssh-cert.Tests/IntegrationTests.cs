using System.Diagnostics;
using SshCert.Models;
using SshCert.Provisioning;
using SshCert.Ssh;

namespace SshCert.Tests;

public sealed class LinuxFactAttribute : FactAttribute
{
    public LinuxFactAttribute()
    {
        if (!OperatingSystem.IsLinux()) Skip = "Runs the remote POSIX mutation script on Linux.";
    }
}

public sealed class SshFixtureFactAttribute : FactAttribute
{
    public SshFixtureFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("SSHCERT_TEST_PASSWORD") is null)
            Skip = "Requires the explicitly configured disposable SSH fixture used by Linux CI.";
    }
}

public sealed class KeyFixtureFactAttribute : FactAttribute
{
    public KeyFixtureFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("SSHCERT_TEST_KEY") is null)
            Skip = "Requires an explicitly configured isolated key-authentication SSH fixture.";
    }
}

public class IntegrationTests
{
    [KeyFixtureFact]
    public async Task RealSshKeyBootstrapProvisionAndRevocation()
    {
        using var local = new TestHome();
        var remote = StateTests.Remote(local, "key-integration") with
        {
            Host = Environment.GetEnvironmentVariable("SSHCERT_TEST_HOST")!,
            Port = int.Parse(Environment.GetEnvironmentVariable("SSHCERT_TEST_PORT")!),
            User = Environment.GetEnvironmentVariable("SSHCERT_TEST_USER")!
        };
        var transport = new SshTransport(new HostTrust(local.Store, _ => true),
            _ => throw new InvalidOperationException("This fixture must never ask for a password."));
        var login = new Login(remote.User, KeyPath: Environment.GetEnvironmentVariable("SSHCERT_TEST_KEY"));
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(1));
        using var session = await transport.Connect(remote, login, timeout.Token);
        await LinuxProvisioner.Apply(session, remote, login, null, false, timeout.Token);
        await transport.Test(remote, "", timeout.Token);
        await LinuxProvisioner.Apply(session, remote, login, null, false, timeout.Token);
        await transport.Test(remote, "", timeout.Token);
        await LinuxProvisioner.Apply(session, remote, login, null, true, timeout.Token);
        await Assert.ThrowsAnyAsync<Renci.SshNet.Common.SshException>(() => transport.Test(remote, "", timeout.Token));
    }

    [LinuxFact]
    public async Task LinuxScriptPreservesRestrictedKeysIsIdempotentAndRevokesPrecisely()
    {
        using var local = new TestHome();
        using var target = new TestHome();
        var r = StateTests.Remote(local, "linux");
        var other = StateTests.Remote(local, "other");
        var uid = await Process("id", ["-u"]);
        var gid = await Process("id", ["-g"]);
        var bin = Path.Combine(local.Path, "test-bin");
        Directory.CreateDirectory(bin);
        var getent = Path.Combine(bin, "getent");
        await File.WriteAllTextAsync(getent, $"#!/bin/sh\nprintf '%s\\n' {LinuxProvisioner.Quote($"{r.User}:x:{uid.Trim()}:{gid.Trim()}:fixture:{target.Path}:/bin/sh")}\n");
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(getent, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var dir = Path.Combine(target.Path, ".ssh");
        Directory.CreateDirectory(dir);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var authorized = Path.Combine(dir, "authorized_keys");
        var restricted = "command=\"echo restricted test\",no-port-forwarding " + r.PublicKey;
        await File.WriteAllTextAsync(authorized, "# preserve\n" + restricted + "\n" + other.PublicKey + "\n");
        await Script(false);
        var first = await File.ReadAllTextAsync(authorized);
        Assert.Contains(restricted, first);
        Assert.Equal(1, first.Split('\n').Count(line => line.Contains(Validation.KeyIdentity(r.PublicKey))));
        await Script(false);
        Assert.Equal(first, await File.ReadAllTextAsync(authorized));
        await Script(true);
        var remaining = await File.ReadAllTextAsync(authorized);
        Assert.DoesNotContain(Validation.KeyIdentity(r.PublicKey), remaining);
        Assert.Contains(other.PublicKey, remaining);
        Assert.Contains("# preserve", remaining);
        Assert.False(Directory.Exists(Path.Combine(dir, ".ssh-cert.lock")));

        async Task Script(bool revoke) => await Process("sh", ["-c", LinuxProvisioner.Script(r, revoke)],
            bin + ":" + Environment.GetEnvironmentVariable("PATH"));
    }

    [SshFixtureFact]
    public async Task RealSshSameUserAndAdminProvisionTestAndRevoke()
    {
        var host = Environment.GetEnvironmentVariable("SSHCERT_TEST_HOST")!;
        var port = int.Parse(Environment.GetEnvironmentVariable("SSHCERT_TEST_PORT")!);
        var user = Environment.GetEnvironmentVariable("SSHCERT_TEST_USER")!;
        var admin = Environment.GetEnvironmentVariable("SSHCERT_TEST_ADMIN")!;
        var password = Environment.GetEnvironmentVariable("SSHCERT_TEST_PASSWORD")!;
        using var local = new TestHome();
        var a = StateTests.Remote(local, "integration") with { Host = host, Port = port, User = user };
        var b = StateTests.Remote(local, "second") with { Host = host, Port = port, User = user };
        var transport = new SshTransport(new HostTrust(local.Store, _ => true), _ => password);
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        var ct = timeout.Token;
        using var target = await transport.Connect(a, new Login(user, Password: password), ct);
        await LinuxProvisioner.Apply(target, a, new Login(user), null, false, ct);
        await transport.Test(a, "", ct);
        using var bootstrap = await transport.Connect(a, new Login(admin, Password: password), ct);
        await LinuxProvisioner.Apply(bootstrap, b, new Login(admin), password, false, ct);
        await transport.Test(b, "", ct);
        await LinuxProvisioner.Apply(bootstrap, a, new Login(admin), password, true, ct);
        await Assert.ThrowsAnyAsync<Renci.SshNet.Common.SshException>(() => transport.Test(a, "", ct));
        await transport.Test(b, "", ct);
        await LinuxProvisioner.Apply(bootstrap, b, new Login(admin), password, true, ct);
        await Assert.ThrowsAnyAsync<Renci.SshNet.Common.SshException>(() => transport.Test(b, "", ct));
    }

    private static async Task<string> Process(string file, string[] args, string? path = null)
    {
        var info = new ProcessStartInfo(file) { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in args) info.ArgumentList.Add(arg);
        if (path is not null) info.Environment["PATH"] = path;
        using var process = System.Diagnostics.Process.Start(info)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await process.WaitForExitAsync(timeout.Token);
        Assert.True(process.ExitCode == 0, await stderr);
        return await stdout;
    }
}
