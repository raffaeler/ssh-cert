using SshCert.Models;
using SshCert.Provisioning;
using SshCert.Ssh;
using SshCert.Storage;

namespace SshCert.Tests;

public sealed class FakeSession : IRemoteSession
{
    public Queue<string> Results { get; } = new();
    public List<(string Command, string? Input, bool Router)> Commands { get; } = [];
    public List<string> Uploads { get; } = [];
    public string RouterVersion { get; set; } = "7.20";
    public Exception? Failure { get; set; }
    public Func<string, Exception?>? FailureFor { get; set; }
    public Task<string> Run(string command, string? input, bool router, CancellationToken cancellation)
    {
        cancellation.ThrowIfCancellationRequested();
        Commands.Add((command, input, router));
        if (Failure is not null) throw Failure;
        var specificFailure = FailureFor?.Invoke(command);
        if (specificFailure is not null) throw specificFailure;
        if (command == ":put [/system resource get version]") return Task.FromResult(RouterVersion);
        return Task.FromResult(Results.Count > 0 ? Results.Dequeue() : "");
    }
    public Task Upload(byte[] content, string name, CancellationToken cancellation)
    { Uploads.Add(name); return Task.CompletedTask; }
    public void Dispose() { }
}

public class TrustAndProvisioningTests
{
    [Fact]
    public void TrustRequiresApprovalRejectsChangesAndScopesPorts()
    {
        using var home = new TestHome();
        var confirmations = new List<string>();
        var trust = new HostTrust(home.Store, text => { confirmations.Add(text); return true; });
        trust.Verify("server", 22, "ssh-ed25519", [1, 2, 3]);
        trust.Verify("SERVER", 22, "ssh-ed25519", [1, 2, 3]);
        Assert.Single(confirmations);
        Assert.Throws<IOException>(() => trust.Verify("server", 22, "ssh-ed25519", [4, 5, 6]));
        Assert.Single(confirmations);
        trust.Verify("server", 22, "ssh-ed25519", [4, 5, 6], review: true);
        Assert.Contains("OLD", confirmations[1]);
        trust.Verify("server", 2222, "ssh-ed25519", [4, 5, 6]);
        Assert.Equal(3, confirmations.Count);
    }

    [Fact]
    public void RejectedTrustIsNeverPersisted()
    {
        using var home = new TestHome();
        Assert.Throws<OperationCanceledException>(() =>
            new HostTrust(home.Store, _ => false).Verify("server", 22, "ssh-ed25519", [1]));
        Assert.False(File.Exists(home.Store.TrustPath));
    }

    [Fact]
    public async Task LinuxSudoPasswordIsOnlyOnInputNotCommand()
    {
        using var home = new TestHome();
        var r = StateTests.Remote(home, "linux");
        using var session = new FakeSession();
        await LinuxProvisioner.Apply(session, r, new Login("bootstrap"), "a-secret-value", false, CancellationToken.None);
        var command = Assert.Single(session.Commands);
        Assert.StartsWith("sudo -S -p '' -u 'operator' -- sh -c ", command.Command);
        Assert.DoesNotContain("a-secret-value", command.Command);
        Assert.DoesNotContain("\r", command.Command);
        Assert.Equal("a-secret-value\n", command.Input);
    }

    [Fact]
    public async Task RootBootstrapDropsPrivilegesBeforeTouchingTargetFiles()
    {
        using var home = new TestHome();
        using var session = new FakeSession();
        await LinuxProvisioner.Apply(session, StateTests.Remote(home, "linux"), new Login("root"), null, false, CancellationToken.None);
        Assert.StartsWith("runuser -u 'operator' -- sh -c ", Assert.Single(session.Commands).Command);
    }

    [Fact]
    public async Task RouterCommandsUseClassicSpaceSeparatedPaths()
    {
        using var home = new TestHome();
        var remote = StateTests.Remote(home, "router");
        var inventory = "*A\t" + KeyService.Fingerprint(remote.PublicKey);
        using var session = new FakeSession();
        foreach (var result in new[] { "", "", "", inventory, "", inventory, "" })
            session.Results.Enqueue(result);

        await MikroTikProvisioner.Provision(session, remote, CancellationToken.None);
        await MikroTikProvisioner.Revoke(session, remote, CancellationToken.None);

        Assert.Equal(":put [/system resource get version]", session.Commands[0].Command);
        Assert.Contains("[/user find where name=", session.Commands[1].Command);
        Assert.All(session.Commands, command => Assert.DoesNotMatch(@"/(?:user|file|system)/", command.Command));
        Assert.Contains(session.Commands, command => command.Command.StartsWith("/user ssh-keys import "));
        Assert.Contains(session.Commands, command => command.Command.Contains("/user ssh-keys remove *A"));
        Assert.Contains(session.Commands, command => command.Command.StartsWith("/file remove [/file find "));
    }

    [Fact]
    public async Task RouterOs6RejectsEd25519BeforeUploadingOrMutatingKeys()
    {
        using var home = new TestHome();
        using var session = new FakeSession { RouterVersion = "6.45.9 (long-term)" };

        var error = await Assert.ThrowsAsync<InputException>(() =>
            MikroTikProvisioner.Provision(session, StateTests.Remote(home, "old-router"), CancellationToken.None));

        Assert.Contains("RSA-4096", error.Message);
        Assert.Contains("No public key was uploaded", error.Message);
        Assert.Empty(session.Uploads);
        Assert.Equal(":put [/system resource get version]", Assert.Single(session.Commands).Command);
    }

    [Fact]
    public async Task RouterOs6CanProvisionAnExplicitlySelectedRsaKeyWithoutFingerprints()
    {
        using var home = new TestHome();
        var remote = new KeyService(home.Store).Generate(new Remote
        {
            Alias = "legacy", Host = "legacy.example", User = "operator", Operator = "test",
            Tag = "legacy", Kind = ServerKind.MikroTik
        }, true, "");
        using var session = new FakeSession { RouterVersion = "6.45.9" };
        foreach (var result in new[] { "", "", "", "*A\t", "" }) session.Results.Enqueue(result);

        var provisioned = await MikroTikProvisioner.Provision(session, remote, CancellationToken.None);

        Assert.Equal("*A", provisioned.RouterKeyId);
        Assert.StartsWith("ssh-rsa ", provisioned.PublicKey);
        Assert.Single(session.Uploads);
        Assert.Contains(session.Commands, command => command.Command.StartsWith("/user ssh-keys import "));
    }

    [Fact]
    public async Task UnrecognizedRouterVersionFailsBeforeAnyUpload()
    {
        using var home = new TestHome();
        using var session = new FakeSession { RouterVersion = "unrecognized" };
        await Assert.ThrowsAsync<IOException>(() =>
            MikroTikProvisioner.Provision(session, StateTests.Remote(home, "router"), CancellationToken.None));
        Assert.Empty(session.Uploads);
        Assert.Single(session.Commands);
    }

    [Fact]
    public async Task RouterRevocationUsesFingerprintAndNeverComment()
    {
        using var home = new TestHome();
        var r = StateTests.Remote(home, "router") with { Kind = ServerKind.MikroTik };
        using var session = new FakeSession();
        var other = StateTests.Remote(home, "unrelated");
        session.Results.Enqueue("*A\t" + KeyService.Fingerprint(r.PublicKey) + "\n*B\t" + KeyService.Fingerprint(other.PublicKey));
        await MikroTikProvisioner.Revoke(session, r, CancellationToken.None);
        Assert.Equal(2, session.Commands.Count);
        Assert.Contains("remove *A", session.Commands[1].Command);
        Assert.DoesNotContain("remove *B", session.Commands[1].Command);
        Assert.Contains("fingerprint", session.Commands[1].Command);
    }

    [Fact]
    public async Task RouterWithoutFingerprintsFailsSafe()
    {
        using var home = new TestHome();
        using var session = new FakeSession();
        session.Results.Enqueue("*A\t");
        await Assert.ThrowsAsync<IOException>(() =>
            MikroTikProvisioner.Revoke(session, StateTests.Remote(home, "router"), CancellationToken.None));
        Assert.Single(session.Commands);
    }

    [Fact]
    public async Task ExistingRouterKeyIsIdempotentWithoutUpload()
    {
        using var home = new TestHome();
        var r = StateTests.Remote(home, "router");
        using var session = new FakeSession();
        session.Results.Enqueue("");
        session.Results.Enqueue("*A\t" + KeyService.Fingerprint(r.PublicKey));
        var result = await MikroTikProvisioner.Provision(session, r, CancellationToken.None);
        Assert.Equal("*A", result.RouterKeyId);
        Assert.Empty(session.Uploads);
    }

    [Fact]
    public async Task RouterImportUploadsOnlyPublicKeyAndCleansItsOwnFile()
    {
        using var home = new TestHome();
        var remote = StateTests.Remote(home, "router");
        using var session = new FakeSession();
        foreach (var value in new[] { "", "", "", "*A\t" + KeyService.Fingerprint(remote.PublicKey), "" })
            session.Results.Enqueue(value);
        var result = await MikroTikProvisioner.Provision(session, remote, CancellationToken.None);
        Assert.Equal("*A", result.RouterKeyId);
        var uploaded = Assert.Single(session.Uploads);
        Assert.StartsWith("ssh-cert-", uploaded);
        Assert.EndsWith(".pub", uploaded);
        Assert.Contains(uploaded, session.Commands[^1].Command);
        Assert.StartsWith("/file remove", session.Commands[^1].Command);
        Assert.DoesNotContain(session.Commands, c => c.Command.Contains("/user ssh-keys remove"));
    }

    [Fact]
    public async Task FailedRouterImportStillCleansItsTemporaryFileWithoutRemovingUserKeys()
    {
        using var home = new TestHome();
        using var session = new FakeSession
        {
            FailureFor = command => command.StartsWith("/user ssh-keys import", StringComparison.Ordinal)
                ? new IOException("Import rejected") : null
        };
        var error = await Assert.ThrowsAsync<IOException>(() =>
            MikroTikProvisioner.Provision(session, StateTests.Remote(home, "router"), CancellationToken.None));
        Assert.Equal("Import rejected", error.Message);
        Assert.Contains(Assert.Single(session.Uploads), session.Commands[^1].Command);
        Assert.StartsWith("/file remove", session.Commands[^1].Command);
        Assert.DoesNotContain(session.Commands, c => c.Command.Contains("/user ssh-keys remove"));
    }
}
