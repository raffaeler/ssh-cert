using SshCert.Cli;
using SshCert.Models;
using SshCert.Ssh;
using SshCert.Storage;

namespace SshCert.Tests;

public class PendingKeyTests
{
    [Fact]
    public void StagingSnapshotDetectsConcurrentChangesBeforeProvisioningCanBeMarkedStarted()
    {
        using var home = new TestHome();
        var pending = StateTests.Remote(home, "pending") with { ProvisioningNotStarted = true };
        var service = new ConnectionService(home.Store);
        var staged = service.Save(home.Store.Load(), new ConnectionFile { PendingCleanup = [pending] });
        service.Save(home.Store.Load(), staged.State, [new Group { Name = "Concurrent" }]);

        Assert.Throws<IOException>(() => service.Save(staged, staged.State with
        {
            PendingCleanup = [pending with { ProvisioningNotStarted = false }]
        }));

        Assert.True(Assert.Single(home.Store.Load().State.PendingCleanup).ProvisioningNotStarted);
        Assert.Equal("Concurrent", Assert.Single(home.Store.Load().Groups).Name);
    }

    [Fact]
    public void RecoveryKeepsTheKeyAndSavesADisabledConnection()
    {
        using var home = new TestHome();
        var pending = StateTests.Remote(home, "pending") with { ProvisioningNotStarted = true };
        var service = new ConnectionService(home.Store);
        service.Save(home.Store.Load(), new ConnectionFile { PendingCleanup = [pending] }, [new Group { Name = "Empty" }]);

        service.RecoverPending(home.Store.Load(), pending, "recovered");

        var saved = home.Store.Load();
        var recovered = Assert.Single(saved.State.Connections);
        Assert.Equal("recovered", recovered.Alias);
        Assert.False(recovered.Enabled);
        Assert.False(recovered.OwnsHost);
        Assert.False(recovered.ProvisioningNotStarted);
        Assert.True(recovered.OwnsKey);
        Assert.Equal(pending.KeyPath, recovered.KeyPath);
        Assert.Empty(saved.State.PendingCleanup);
        Assert.Empty(Assert.Single(saved.Groups).Connections);
        Assert.True(File.Exists(pending.KeyPath));
        Assert.Contains("Match originalhost recovered", File.ReadAllText(home.Store.DisabledPath));
    }

    [Fact]
    public void RecoveryCannotOverwriteAnExistingAlias()
    {
        using var home = new TestHome();
        var existing = StateTests.Remote(home, "existing");
        var pending = StateTests.Remote(home, "pending");
        var service = new ConnectionService(home.Store);
        service.Save(home.Store.Load(), new ConnectionFile { Connections = [existing], PendingCleanup = [pending] });
        var snapshot = home.Store.Load();

        Assert.Throws<InputException>(() => service.RecoverPending(snapshot, pending, "EXISTING"));
        Assert.All(home.Store.Load().Files, pair => Assert.True(StateStore.Same(pair.Value, snapshot.Files[pair.Key])));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CleanupDeletesOnlyExplicitlySelectedAppOwnedFiles(bool deleteKey)
    {
        using var home = new TestHome();
        var pending = StateTests.Remote(home, "pending");
        var service = new ConnectionService(home.Store);
        service.Save(home.Store.Load(), new ConnectionFile { PendingCleanup = [pending] });

        service.RemovePending(home.Store.Load(), pending, deleteKey);

        Assert.Empty(home.Store.Load().State.PendingCleanup);
        Assert.Equal(!deleteKey, File.Exists(pending.KeyPath));
        Assert.Equal(!deleteKey, File.Exists(pending.KeyPath + ".pub"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CleanupCannotDeleteExternalOrSharedKeys(bool shared)
    {
        using var home = new TestHome();
        var pending = StateTests.Remote(home, "pending") with { OwnsKey = shared };
        var other = pending with { Id = Guid.NewGuid() };
        var service = new ConnectionService(home.Store);
        service.Save(home.Store.Load(), new ConnectionFile { PendingCleanup = shared ? [pending, other] : [pending] });

        Assert.Throws<InputException>(() => service.RemovePending(home.Store.Load(), pending, deleteKey: true));
        Assert.True(File.Exists(pending.KeyPath));
        Assert.True(File.Exists(pending.KeyPath + ".pub"));
        Assert.Contains(home.Store.Load().State.PendingCleanup, r => r.Id == pending.Id);
    }

    [Fact]
    public void AFileDeletionFailureDoesNotLoseThePendingRecord()
    {
        using var home = new TestHome();
        var pending = StateTests.Remote(home, "pending");
        var service = new ConnectionService(home.Store);
        service.Save(home.Store.Load(), new ConnectionFile { PendingCleanup = [pending] });
        File.Delete(pending.KeyPath + ".pub");
        Directory.CreateDirectory(pending.KeyPath + ".pub");

        var error = Record.Exception(() => service.RemovePending(home.Store.Load(), pending, deleteKey: true));

        Assert.True(error is IOException or UnauthorizedAccessException);
        Assert.True(File.Exists(pending.KeyPath));
        Assert.Single(home.Store.Load().State.PendingCleanup);
    }

    [Fact]
    public void AConcurrentReferenceIsDetectedBeforeAnyKeyFileIsDeleted()
    {
        using var home = new TestHome();
        var pending = StateTests.Remote(home, "pending");
        var service = new ConnectionService(home.Store);
        service.Save(home.Store.Load(), new ConnectionFile { PendingCleanup = [pending] });
        var old = home.Store.Load();
        service.Save(old, old.State with
        {
            Connections = [pending with { Id = Guid.NewGuid(), Alias = "shared", OwnsHost = false }]
        });

        Assert.Throws<IOException>(() => service.RemovePending(old, pending, deleteKey: true));

        Assert.True(File.Exists(pending.KeyPath));
        Assert.True(File.Exists(pending.KeyPath + ".pub"));
        Assert.Single(home.Store.Load().State.PendingCleanup);
    }

    [Fact]
    public void BootstrapOffersMatchingSavedAndPendingKeysButNotUnprovisionedKeys()
    {
        using var home = new TestHome();
        var saved = StateTests.Remote(home, "saved");
        var pending = StateTests.Remote(home, "pending") with { Host = saved.Host };
        var state = new ConnectionFile
        {
            Connections = [saved],
            PendingCleanup =
            [
                saved with { Id = Guid.NewGuid() },
                pending,
                pending with { Id = Guid.NewGuid(), ProvisioningNotStarted = true, KeyPath = saved.KeyPath },
                pending with { Id = Guid.NewGuid(), Host = "elsewhere.example" },
                pending with { Id = Guid.NewGuid(), Port = 2222 },
                pending with { Id = Guid.NewGuid(), User = "different" },
                pending with { Id = Guid.NewGuid(), KeyPath = Path.Combine(home.Path, "missing") }
            ]
        };

        var keys = Application.BootstrapKeys(state, saved with { Host = saved.Host.ToUpperInvariant() + "." }, saved.User);

        Assert.Equal([saved.Id, pending.Id], keys.Select(r => r.Id).ToArray());
        Assert.Empty(Application.BootstrapKeys(new ConnectionFile
        {
            PendingCleanup = [pending with { ProvisioningNotStarted = true }]
        }, saved, saved.User));
    }

    [Theory]
    [InlineData(ServerKind.MikroTik, false, true)]
    [InlineData(ServerKind.MikroTik, true, false)]
    [InlineData(ServerKind.Linux, false, false)]
    public void AuthenticationErrorsExplainTheActualMethodAndRouterPasswordPolicy(ServerKind kind, bool key, bool policyHint)
    {
        var remote = new Remote { Host = "router.example", Port = 2222, Kind = kind };
        var message = SshTransport.AuthenticationFailureMessage(remote, "bootstrap", key, "Permission denied.");

        Assert.Contains("bootstrap@router.example:2222", message);
        Assert.Contains(key ? "private-key authentication" : "password authentication", message);
        Assert.Contains("Permission denied.", message);
        Assert.Equal(policyHint, message.Contains("correct password"));
        Assert.Equal(policyHint, message.Contains("recorded/existing private key"));
    }
}
