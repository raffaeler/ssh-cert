using SshCert.Models;

namespace SshCert.Storage;

public sealed class ConnectionService(StateStore store)
{
    private readonly StateStore _store = store;

    public static Remote? FindHostOwner(IEnumerable<Remote> connections, string host) =>
        connections.SingleOrDefault(r => r.OwnsHost &&
            r.Host.TrimEnd('.').Equals(host.TrimEnd('.'), StringComparison.OrdinalIgnoreCase));

    public Snapshot Save(Snapshot snapshot, ConnectionFile state, List<Group>? groups = null,
        IEnumerable<LegacyBlock>? imports = null)
    {
        groups ??= snapshot.Groups;
        Validation.State(state, groups);
        foreach (var r in state.Connections.Where(r => r.Enabled))
        {
            PrivateFiles.RejectLink(r.KeyPath);
            if (!File.Exists(r.KeyPath)) throw new IOException($"Key for '{r.Alias}' is missing: {r.KeyPath}");
        }
        var config = snapshot.Files[_store.ConfigPath];
        var disabled = snapshot.Files[_store.DisabledPath];
        CheckManaged(config, snapshot.State.Connections.Where(r => r.Enabled));
        CheckManaged(disabled, snapshot.State.Connections.Where(r => !r.Enabled));
        if (imports is not null)
        {
            var blocks = imports.ToList();
            config = SshConfig.RemoveLegacy(config, blocks.Where(b => b.File == _store.ConfigPath));
            disabled = SshConfig.RemoveLegacy(disabled, blocks.Where(b => b.File == _store.DisabledPath));
        }
        return _store.Commit(snapshot, state, groups,
            SshConfig.Render(config, state.Connections.Where(r => r.Enabled)),
            SshConfig.Render(disabled, state.Connections.Where(r => !r.Enabled)));
    }

    private static void CheckManaged(byte[]? original, IEnumerable<Remote> existing)
    {
        if (!SshConfig.IsManagedUnchanged(original, existing))
            throw new IOException("Managed SSH config was edited or removed outside ssh-cert. Restore it before changing state.");
    }

    public void Apply(string name)
    {
        var snapshot = _store.Load();
        var group = snapshot.Groups.SingleOrDefault(g => g.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
            ?? throw new InputException($"Unknown group '{name}'. Use /group to create it.");
        var ids = group.Connections.ToHashSet();
        Save(snapshot, snapshot.State with
        {
            Connections = snapshot.State.Connections.Select(r => r with { Enabled = ids.Contains(r.Id) }).ToList()
        });
    }

    public void RecoverPending(Snapshot snapshot, Remote pending, string alias)
    {
        RequirePending(snapshot, pending);
        var recovered = pending with
        {
            Id = Guid.NewGuid(), Alias = Validation.Token(alias, "Alias"), Enabled = false, OwnsHost = false,
            ProvisioningNotStarted = false
        };
        Save(snapshot, snapshot.State with
        {
            Connections = [.. snapshot.State.Connections, recovered],
            PendingCleanup = snapshot.State.PendingCleanup.Where(r => r.Id != pending.Id).ToList()
        });
    }

    public void RemovePending(Snapshot snapshot, Remote pending, bool deleteKey = false)
    {
        RequirePending(snapshot, pending);
        var state = snapshot.State with
        {
            PendingCleanup = snapshot.State.PendingCleanup.Where(r => r.Id != pending.Id).ToList()
        };
        _store.Commit(snapshot, state, snapshot.Groups, snapshot.Files[_store.ConfigPath], snapshot.Files[_store.DisabledPath],
            beforeCommit: () =>
            {
                if (!deleteKey) return;
                GuardKeyDeletion(snapshot.State, pending);
                // Delete under the state lock; retain the record on failure, never journal private keys.
                File.Delete(pending.KeyPath + ".pub");
                File.Delete(pending.KeyPath);
            });
    }

    private static void RequirePending(Snapshot snapshot, Remote pending)
    {
        if (!snapshot.State.PendingCleanup.Contains(pending))
            throw new InputException("The pending key changed or is no longer recorded. Reload and retry.");
    }

    public static void GuardRevocation(ConnectionFile state, Remote remote)
    {
        if (state.Connections.Concat(state.PendingCleanup).Any(r => r.Id != remote.Id &&
            r.Host.Equals(remote.Host, StringComparison.OrdinalIgnoreCase) && r.Port == remote.Port &&
            r.User == remote.User && Validation.KeyIdentity(r.PublicKey) == Validation.KeyIdentity(remote.PublicKey)))
            throw new InputException("Another connection or cleanup record uses this remote key; resolve shared access before revoking it.");
    }

    public static void GuardKeyDeletion(ConnectionFile state, Remote remote)
    {
        if (!remote.OwnsKey) throw new InputException("This is an externally owned key; ssh-cert will not delete it.");
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (state.Connections.Concat(state.PendingCleanup).Any(r => r.Id != remote.Id && r.KeyPath.Equals(remote.KeyPath, comparison)))
            throw new InputException("Another connection or cleanup record references this private key.");
        PrivateFiles.RejectLink(remote.KeyPath);
        PrivateFiles.RejectLink(remote.KeyPath + ".pub");
    }
}
