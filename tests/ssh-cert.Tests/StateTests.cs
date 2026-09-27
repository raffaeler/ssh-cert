using System.Text;
using SshCert.Models;
using SshCert.Ssh;
using SshCert.Storage;

namespace SshCert.Tests;

public class StateTests
{
    [Fact]
    public void HostOwnershipDefaultsNeverStealAnExistingOrDisabledOwner()
    {
        var owner = new Remote { Host = "Router.Example.", OwnsHost = true, Enabled = false, Port = 2222 };
        Assert.Same(owner, ConnectionService.FindHostOwner([owner], "ROUTER.EXAMPLE"));
        Assert.Null(ConnectionService.FindHostOwner([owner], "different.example"));
        Assert.Null(ConnectionService.FindHostOwner([owner with { OwnsHost = false }], "router.example"));
        Assert.Null(ConnectionService.FindHostOwner([], "router.example"));
    }

    public static Remote Remote(TestHome home, string alias, bool enabled = false, bool hostOwner = true) =>
        new KeyService(home.Store).Generate(new Remote
        {
            Alias = alias, Host = alias + ".example", User = "operator", Operator = "test",
            Tag = alias, Enabled = enabled, OwnsHost = hostOwner
        }, false, "");

    [Fact]
    public void GroupApplicationChangesExactSetIncludingHostnamesAndIsIdempotent()
    {
        using var home = new TestHome();
        var store = home.Store;
        var service = new ConnectionService(store);
        var a = Remote(home, "alpha", true);
        var b = Remote(home, "beta");
        var initial = store.Load();
        var group = new Group { Name = "Office machines", Connections = [b.Id] };
        service.Save(initial, new ConnectionFile { Connections = [a, b] }, [group, new Group { Name = "None" }]);
        service.Apply("office MACHINES");
        var snapshot = store.Load();
        Assert.Equal([b.Id], snapshot.State.Connections.Where(r => r.Enabled).Select(r => r.Id).ToArray());
        var config = File.ReadAllText(store.ConfigPath);
        var disabled = File.ReadAllText(store.DisabledPath);
        Assert.Contains("Match originalhost beta\n", config);
        Assert.Contains("Match originalhost beta.example\n", config);
        Assert.DoesNotContain("Match originalhost alpha", config);
        Assert.Contains("Match originalhost alpha.example\n", disabled);
        var before = snapshot.Files.ToDictionary(p => p.Key, p => p.Value);
        service.Apply(group.Name);
        Assert.All(store.Load().Files, pair => Assert.True(StateStore.Same(before[pair.Key], pair.Value)));
        service.Apply("None");
        Assert.All(store.Load().State.Connections, r => Assert.False(r.Enabled));
        Assert.DoesNotContain("Match originalhost beta", File.ReadAllText(store.ConfigPath));
    }

    [Fact]
    public void FailuresDoNotPartiallyChangeGroup()
    {
        using var home = new TestHome();
        var store = home.Store;
        var service = new ConnectionService(store);
        var r = Remote(home, "missing");
        service.Save(store.Load(), new ConnectionFile { Connections = [r] },
            [new Group { Name = "Enable", Connections = [r.Id] }]);
        var before = store.Load();
        File.Delete(r.KeyPath);
        Assert.Throws<IOException>(() => service.Apply("Enable"));
        Assert.Throws<InputException>(() => service.Apply("Unknown"));
        Assert.All(store.Load().Files, p => Assert.True(StateStore.Same(p.Value, before.Files[p.Key])));
    }

    [Fact]
    public void InvalidGroupsAreRejectedBeforeWriting()
    {
        using var home = new TestHome();
        var service = new ConnectionService(home.Store);
        Assert.Throws<InputException>(() => service.Save(home.Store.Load(), new ConnectionFile(),
            [new Group { Name = "Invalid", Connections = [Guid.NewGuid()] }]));
        Assert.False(File.Exists(home.Store.StatePath));
        Assert.Throws<InputException>(() => service.Save(home.Store.Load(), new ConnectionFile(),
            [new Group { Name = "Office" }, new Group { Name = "office" }]));
    }

    [Fact]
    public void ExternalEditsAndConcurrentGroupsAreNotOverwritten()
    {
        using var home = new TestHome();
        var store = home.Store;
        var service = new ConnectionService(store);
        var snapshot = store.Load();
        Directory.CreateDirectory(store.SshDirectory);
        File.WriteAllText(store.ConfigPath, "# externally added\n");
        Assert.Throws<IOException>(() => service.Save(snapshot, snapshot.State));
        Assert.Equal("# externally added\n", File.ReadAllText(store.ConfigPath));
        snapshot = store.Load();
        var external = new Group { Name = "Other" };
        File.WriteAllBytes(store.GroupPath(external.Id), StateStore.Serialize(external));
        Assert.Throws<IOException>(() => service.Save(snapshot, snapshot.State));
    }

    [Fact]
    public void ManagedEditsRequireExplicitRecovery()
    {
        using var home = new TestHome();
        var r = Remote(home, "edited", true);
        var service = new ConnectionService(home.Store);
        service.Save(home.Store.Load(), new ConnectionFile { Connections = [r] });
        File.AppendAllText(home.Store.ConfigPath, "# user settings\n");
        var snapshot = home.Store.Load();
        service.Save(snapshot, snapshot.State);
        Assert.EndsWith("# user settings\n", File.ReadAllText(home.Store.ConfigPath));
        File.WriteAllText(home.Store.ConfigPath, File.ReadAllText(home.Store.ConfigPath).Replace("Port 22", "Port 23"));
        snapshot = home.Store.Load();
        Assert.Throws<IOException>(() => service.Save(snapshot, snapshot.State));
        Assert.Contains("Port 23", File.ReadAllText(home.Store.ConfigPath));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void InterruptedTransactionsCanCompleteOrRollback(bool forward)
    {
        using var home = new TestHome();
        var store = home.Store;
        PrivateFiles.Directory(store.DataDirectory);
        var before = Encoding.UTF8.GetBytes("# before\n");
        var after = Encoding.UTF8.GetBytes("# after\n");
        File.WriteAllBytes(store.ConfigPath, after);
        var changes = new List<FileChange>
        {
            new(store.ConfigPath, before, after),
            new(store.DisabledPath, null, after)
        };
        File.WriteAllBytes(Path.Combine(store.DataDirectory, "transaction.json"), StateStore.Serialize(changes));
        Assert.Throws<IOException>(() => store.Load());
        store.Recover(forward);
        Assert.Equal(forward ? after : before, File.ReadAllBytes(store.ConfigPath));
        Assert.Equal(forward, File.Exists(store.DisabledPath));
        Assert.False(store.NeedsRecovery);
    }

    [Fact]
    public void RecoveryRefusesUnknownEdits()
    {
        using var home = new TestHome();
        var store = home.Store;
        PrivateFiles.Directory(store.DataDirectory);
        File.WriteAllText(store.ConfigPath, "# unrelated");
        File.WriteAllBytes(Path.Combine(store.DataDirectory, "transaction.json"),
            StateStore.Serialize(new List<FileChange> { new(store.ConfigPath, null, "new"u8.ToArray()) }));
        Assert.Throws<IOException>(() => store.Recover(true));
        Assert.Equal("# unrelated", File.ReadAllText(store.ConfigPath));
    }

    [Fact]
    public void DuplicateOwnersAndSharedKeyDeletionAreRejected()
    {
        using var home = new TestHome();
        var a = Remote(home, "one");
        var b = a with { Id = Guid.NewGuid(), Alias = "two" };
        Assert.Throws<InputException>(() => Validation.State(new ConnectionFile { Connections = [a, b] }, []));
        b = b with { OwnsHost = false };
        var state = new ConnectionFile { Connections = [a, b] };
        Validation.State(state, []);
        Assert.Throws<InputException>(() => ConnectionService.GuardKeyDeletion(state, a));
        Assert.Throws<InputException>(() => ConnectionService.GuardRevocation(state, a));
        Assert.Throws<InputException>(() => ConnectionService.GuardKeyDeletion(new ConnectionFile(), a with { OwnsKey = false }));
    }

    [Fact]
    public void DisabledHostnameOwnerDoesNotTransferToOtherEnabledAlias()
    {
        using var home = new TestHome();
        var a = Remote(home, "one");
        var b = Remote(home, "two", true, false) with { Host = a.Host };
        var service = new ConnectionService(home.Store);
        service.Save(home.Store.Load(), new ConnectionFile { Connections = [a, b] });
        Assert.DoesNotContain("Match originalhost " + a.Host, File.ReadAllText(home.Store.ConfigPath));
        Assert.Contains("Match originalhost two", File.ReadAllText(home.Store.ConfigPath));
    }
}
