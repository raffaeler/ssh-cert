using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Renci.SshNet.Common;
using SshCert.ConsoleUi;
using SshCert.Models;
using SshCert.Provisioning;
using SshCert.Ssh;
using SshCert.Storage;
using Group = SshCert.Models.Group;

namespace SshCert.Cli;

public sealed class Application : IDisposable
{
    public static string Version { get; } = (typeof(Application).Assembly
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? throw new InvalidOperationException("Application version metadata is missing.")).Split('+')[0];

    public const string Help = """
        ssh-cert - SSH public-key provisioning and connection groups

        ssh-cert                 Interactive UI (type / for commands)
        ssh-cert --group <name>  Apply a saved group locally and exit
        ssh-cert --help          Show help
        ssh-cert --version       Show version

        /remote       Create, import, edit, test or delete a connection
        /group        Create/apply groups, or use the separate Edit/Delete actions
        /group <name> Apply a group (quote names containing spaces if desired)
        /help         Show help
        /exit         Exit

        Arrows: move | Enter: confirm | Space: toggle [X]/[ ] | Esc: cancel
        Type to filter lists. Ctrl+C cancels the current operation.

        Disabled means local SSH config is parked, NOT remote key revocation.
        Explicit keys, agent keys and other SSH configurations still work.
        Test intentionally checks the key even for a disabled connection.
        Passphrase-protected keys may still prompt for a local passphrase.
        Data: ~/.ssh/ssh-cert; keys and OpenSSH config: ~/.ssh.
        Exit codes: 0 success, 1 operation failed, 2 invalid input, 130 canceled.
        """;

    private readonly StateStore _store = new();
    private readonly ConnectionService _connections;
    private readonly KeyService _keys;
    private readonly Prompts _ui;
    private readonly SshTransport _transport;
    private CancellationTokenSource _operation = new();
    private CancellationToken Cancellation => _operation.Token;

    private Application()
    {
        _ui = new Prompts(new SystemTerminal(), () => Cancellation);
        _connections = new ConnectionService(_store);
        _keys = new KeyService(_store);
        _transport = new SshTransport(new HostTrust(_store, text => _ui.Confirm(text)),
            text => _ui.Text(text, secret: true));
        Console.CancelKeyPress += Cancel;
    }
    private void Cancel(object? sender, ConsoleCancelEventArgs args) { args.Cancel = true; _operation.Cancel(); }
    public void Dispose() { Console.CancelKeyPress -= Cancel; _operation.Dispose(); }

    public static bool Expected(Exception ex) => ex is InputException or IOException or UnauthorizedAccessException or
        JsonException or SshException or SocketException or CryptographicException or FormatException or
        ArgumentException or InvalidOperationException or TimeoutException;

    public static void Message(string message, bool error = false)
    {
        var clean = new string(message.Select(c => char.IsControl(c) && c is not ('\r' or '\n' or '\t') ? '?' : c).ToArray());
        if (error) Console.Error.WriteLine(clean); else Console.WriteLine(clean);
    }

    public static async Task<int> Run(string[] args)
    {
        try
        {
            Message($"ssh-cert {Version}");
            if (args is ["--help"] or ["-h"]) { Message(Help); return 0; }
            if (args is ["--version"]) return 0;
            if (args is ["--group", var name])
            {
                new ConnectionService(new StateStore()).Apply(name);
                Message($"Applied group '{name}'. Only managed local SSH entries were changed.");
                return 0;
            }
            if (args.Length != 0) throw new InputException("Unknown arguments. Use ssh-cert --help.");
            if (!Prompts.Interactive) throw new InputException("Interactive commands require terminal input and output. Use --group <name> or --help.");
            using var app = new Application();
            return await app.Interactive();
        }
        catch (OperationCanceledException) { Message("Canceled.", true); return 130; }
        catch (Exception ex) when (Expected(ex))
        {
            Message("Error: " + ex.Message, true);
            return ex is InputException or JsonException ? 2 : 1;
        }
    }

    private async Task<int> Interactive()
    {
        Message("ssh-cert | Type / for commands. Disabled is a local convenience toggle, not revocation.");
        if (_store.NeedsRecovery)
        {
            var choice = _ui.Choose("Interrupted local update. Recover before continuing.",
                ["Complete the saved update", "Restore the previous state", "Exit without changes"]);
            if (choice == 2) return 1;
            _store.Recover(choice == 0);
            Message("Local update recovered.");
        }
        var snapshot = _store.Load();
        Message(DescribeActiveGroup(snapshot.State, snapshot.Groups));
        while (true)
        {
            _operation.Dispose();
            _operation = new CancellationTokenSource();
            var atRoot = true;
            try
            {
                var command = _ui.Command();
                if (command.Length == 0) continue;
                atRoot = false;
                var (verb, argument) = Parse(command);
                switch (verb)
                {
                    case "/remote" when argument is null: await Remotes(); break;
                    case "/group" when argument is null: Groups(); break;
                    case "/group": _connections.Apply(argument!); Message($"Applied group '{argument}'."); break;
                    case "/help" when argument is null: Message(Help); break;
                    case "/exit" when argument is null: return 0;
                    default: throw new InputException("Unknown command or unexpected arguments. Type / to select a command.");
                }
            }
            catch (OperationCanceledException)
            {
                if (atRoot) return 130;
                Message("Canceled. Completed remote effects, if any, are not automatically undone.");
            }
            catch (Exception ex) when (Expected(ex)) { Message("Error: " + ex.Message, true); }
        }
    }

    public static string DescribeActiveGroup(ConnectionFile state, IEnumerable<Group> groups)
    {
        var enabled = state.Connections.Where(r => r.Enabled).Select(r => r.Id).ToHashSet();
        var matches = groups.Where(group => enabled.SetEquals(group.Connections))
            .Select(group => group.Name).Order(StringComparer.OrdinalIgnoreCase).ToArray();
        return matches.Length switch
        {
            0 => enabled.Count == 0
                ? "Active group: none (no enabled connections)"
                : $"Active group: none (custom selection; {enabled.Count} enabled)",
            1 => $"Active group: {matches[0]}",
            _ => $"Active group: multiple matches ({string.Join(", ", matches)})"
        };
    }

    public static (string Verb, string? Argument) Parse(string command)
    {
        var parts = command.Trim().Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) throw new InputException("Empty command.");
        var argument = parts.Length == 2 ? parts[1].Trim() : null;
        if (argument?.StartsWith('"') == true)
        {
            if (argument.Length < 2 || !argument.EndsWith('"')) throw new InputException("Unclosed quoted name.");
            argument = argument[1..^1];
        }
        if (argument?.Contains('"') == true || argument is "") throw new InputException("Invalid command argument.");
        return (parts[0], argument);
    }

    private void Groups()
    {
        var snapshot = _store.Load();
        var groups = snapshot.Groups.OrderBy(g => g.Name, StringComparer.OrdinalIgnoreCase).ToList();
        var choice = _ui.Choose($"Groups ({snapshot.State.Connections.Count} saved connections)",
            ["Create", .. groups.Select(g => g.Name), "Edit group", "Delete group"]);
        if (choice == 0) { EditGroup(snapshot, null); return; }
        if (choice <= groups.Count) { _connections.Apply(groups[choice - 1].Name); Message("Group applied."); return; }
        var group = groups[_ui.Choose("Select group", groups.Select(g => g.Name).ToArray())];
        if (choice == groups.Count + 1) { EditGroup(snapshot, group); return; }
        if (!_ui.Confirm($"Delete group '{group.Name}'? Current enabled connections will not change.")) return;
        _connections.Save(snapshot, snapshot.State, snapshot.Groups.Where(g => g.Id != group.Id).ToList());
        Message("Group deleted; current enabled connections unchanged.");
    }

    private void EditGroup(Snapshot snapshot, Group? original)
    {
        var name = Validation.Name(_ui.Text("Group name", original?.Name ?? ""));
        var list = snapshot.State.Connections.OrderBy(r => r.Alias, StringComparer.OrdinalIgnoreCase).ToList();
        var chosen = _ui.Check("Group membership", list.Select(Describe).ToArray(),
            Enumerable.Range(0, list.Count).Where(i => original?.Connections.Contains(list[i].Id) == true),
            emptyMessage: "No saved connections. Import/create with /remote.");
        var group = (original ?? new Group()) with { Name = name, Connections = chosen.Order().Select(i => list[i].Id).ToList() };
        _connections.Save(snapshot, snapshot.State, [.. snapshot.Groups.Where(g => g.Id != group.Id), group]);
        Message($"Saved group '{name}'.");
        if (_ui.Confirm("Apply this group now? All other managed connections will be disabled."))
        { _connections.Apply(name); Message("Group applied."); }
    }

    private static string Describe(Remote remote) =>
        $"{remote.Alias} [{(remote.Enabled ? "enabled" : "disabled")}] {remote.User}@{remote.Host}:{remote.Port} ({remote.Kind})";

    private async Task Remotes()
    {
        var snapshot = _store.Load();
        var remotes = snapshot.State.Connections.OrderBy(r => r.Alias, StringComparer.OrdinalIgnoreCase).ToList();
        var choice = _ui.Choose("Remote connections", ["Create", .. remotes.Select(Describe), "Import script connections", "Pending remote cleanup"]);
        if (choice == 0) { await CreateOrEdit(snapshot, null); return; }
        if (choice == remotes.Count + 1) { Import(snapshot); return; }
        if (choice == remotes.Count + 2) { await Cleanup(snapshot); return; }
        var remote = remotes[choice - 1];
        switch (_ui.Choose(Describe(remote), ["Edit", "Test key-only authentication", "Delete", "Review host trust"]))
        {
            case 0: await CreateOrEdit(snapshot, remote); break;
            case 1:
                Message("Testing explicitly with the recorded private key; enabled/disabled configuration will not change.");
                await _transport.Test(remote, KeyPassphrase(remote.KeyPath), Cancellation);
                Message("Key-only authentication succeeded.");
                break;
            case 2: await Delete(snapshot, remote); break;
            case 3:
                await _transport.Test(remote, KeyPassphrase(remote.KeyPath), Cancellation, review: true);
                Message("Host trust reviewed; key-only authentication succeeded.");
                break;
        }
    }

    private Remote Fields(Remote? original, IReadOnlyList<Remote> existing)
    {
        var r = original ?? new Remote
        {
            Operator = Regex.Replace(Environment.UserName, @"[^A-Za-z0-9_.-]", "_"),
            Actor = "ai"
        };
        if (original is null)
        {
            r = r with { Kind = _ui.Choose("Server type", ["Linux / OpenSSH", "MikroTik / RouterOS"]) == 0 ? ServerKind.Linux : ServerKind.MikroTik };
            r = r with { Host = _ui.Text("Server hostname or IP"), User = Validation.Token(_ui.Text("Existing target username"), "User") };
            r = r with { OwnsHost = ConnectionService.FindHostOwner(existing, r.Host) is null };
            var suggestion = Regex.Replace(r.Host, @"[^A-Za-z0-9_-]", "-");
            r = r with { Alias = Validation.Token(_ui.Text("SSH alias", suggestion), "Alias"), Tag = suggestion };
        }
        while (true)
        {
            var fields = new[]
            {
                "Continue", $"Alias: {r.Alias}", $"Server type: {r.Kind}", $"Host: {r.Host}",
                $"Port: {r.Port}", $"Target user: {r.User}", $"Operator: {r.Operator}",
                $"Actor: {r.Actor}", $"Target tag: {r.Tag}", $"Flags: enabled={r.Enabled}, raw-hostname owner={r.OwnsHost}"
            };
            switch (_ui.Choose("Connection details (select a field to change it)", fields))
            {
                case 0: return r;
                case 1: r = r with { Alias = Validation.Token(_ui.Text("Alias", r.Alias), "Alias") }; break;
                case 2: r = r with { Kind = (ServerKind)_ui.Choose("Server type", ["Linux", "MikroTik"], (int)r.Kind) }; break;
                case 3: r = r with { Host = _ui.Text("Hostname or IP", r.Host) }; break;
                case 4:
                    if (!int.TryParse(_ui.Text("Port", r.Port.ToString()), out var port) || port is < 1 or > 65535)
                        throw new InputException("Port must be between 1 and 65535.");
                    r = r with { Port = port };
                    break;
                case 5: r = r with { User = Validation.Token(_ui.Text("Existing target user", r.User), "User") }; break;
                case 6: r = r with { Operator = Validation.Token(_ui.Text("Operator", r.Operator), "Operator") }; break;
                case 7: r = r with { Actor = _ui.Choose("Actor", ["ai", "human"], r.Actor == "ai" ? 0 : 1) == 0 ? "ai" : "human" }; break;
                case 8: r = r with { Tag = Validation.Token(_ui.Text("Target tag", r.Tag), "Target tag") }; break;
                case 9:
                    var flags = _ui.Check("Connection flags", ["Enabled (local SSH config)", "Own raw-hostname entry"],
                        new[] { r.Enabled ? 0 : -1, r.OwnsHost ? 1 : -1 }.Where(i => i >= 0));
                    r = r with { Enabled = flags.Contains(0), OwnsHost = flags.Contains(1) };
                    break;
            }
        }
    }

    private (Remote Remote, string Passphrase, bool Changed) SelectKey(Remote candidate, Remote? original)
    {
        var choices = original is null
            ? new[] { "Generate a new key", "Import an existing key", "Convert existing key to a separate OpenSSH copy" }
            : ["Keep current key", "Generate a new key", "Import an existing key", "Convert existing key to a separate OpenSSH copy"];
        var choice = _ui.Choose("Private key", choices);
        if (original is not null && choice == 0) return (candidate, "", false);
        if (original is not null) choice--;
        if (choice == 0)
        {
            var rsa = _ui.Choose(candidate.Kind == ServerKind.MikroTik ? "Key algorithm (RouterOS 6 requires RSA)" : "Key algorithm",
                [candidate.Kind == ServerKind.MikroTik ? "Ed25519 (modern RouterOS, not RouterOS 6)" : "Ed25519 (recommended)", "RSA-4096"]) == 1;
            var passphrase = _ui.Passphrase(creating: true);
            var remote = _keys.Generate(candidate, rsa, passphrase);
            Message($"Created private key: {remote.KeyPath}");
            return (remote, passphrase, true);
        }
        var path = SelectKeyPath();
        var secret = KeyPassphrase(path);
        return (choice == 1 ? KeyService.Import(candidate, path, secret) : _keys.ConvertKey(candidate, path, secret), secret, true);
    }

    private string SelectKeyPath()
    {
        var paths = Directory.Exists(_store.SshDirectory)
            ? Directory.GetFiles(_store.SshDirectory).Where(p => Path.GetFileName(p).StartsWith("id_", StringComparison.Ordinal) &&
                !p.EndsWith(".pub", StringComparison.OrdinalIgnoreCase)).Order().ToList() : [];
        var choice = _ui.Choose("Existing private key", ["Enter path", .. paths.Select(p => Path.GetFileName(p))]);
        return choice == 0 ? Path.GetFullPath(_ui.Text("Private key path")) : paths[choice - 1];
    }

    private string KeyPassphrase(string path)
    {
        try { using var key = new Renci.SshNet.PrivateKeyFile(path); return ""; }
        catch (SshPassPhraseNullOrEmptyException) { return _ui.Passphrase(); }
    }

    private Login Bootstrap(Remote r)
    {
        var user = Validation.Token(_ui.Text("Bootstrap login user (must be allowed to install the key)", r.User), "Bootstrap user");
        var state = _store.Load().State;
        var recorded = BootstrapKeys(state, r, user);
        var savedIds = state.Connections.Select(connection => connection.Id).ToHashSet();
        var choice = _ui.Choose("Bootstrap authentication",
            [.. recorded.Select(key => $"{(savedIds.Contains(key.Id) ? "Saved" : "Pending")} key: {Path.GetFileName(key.KeyPath)} ({KeyService.Fingerprint(key.PublicKey)})"),
                "Password", "Other existing private key"],
            initial: recorded.Any(key => savedIds.Contains(key.Id)) ? 0 : recorded.Count);
        if (choice < recorded.Count)
        {
            var known = recorded[choice];
            var passphrase = KeyPassphrase(known.KeyPath);
            KeyService.Validate(known, passphrase);
            return new Login(user, KeyPath: known.KeyPath, Passphrase: passphrase);
        }
        if (choice == recorded.Count)
        {
            if (r.Kind == ServerKind.MikroTik)
                Message("RouterOS may reject a correct password if this login user already has SSH keys. Use a recorded key or a separate administrator in that case.");
            return new Login(user, Password: _ui.Text("Bootstrap password", secret: true));
        }
        var path = SelectKeyPath();
        return new Login(user, KeyPath: path, Passphrase: KeyPassphrase(path));
    }

    public static List<Remote> BootstrapKeys(ConnectionFile state, Remote target, string user) =>
        state.Connections.Concat(state.PendingCleanup)
            .Where(r => r.Host.TrimEnd('.').Equals(target.Host.TrimEnd('.'), StringComparison.OrdinalIgnoreCase) &&
                r.Port == target.Port && r.User == user && !r.ProvisioningNotStarted && File.Exists(r.KeyPath))
            .DistinctBy(r => r.KeyPath, OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal)
            .ToList();

    private string? Sudo(Remote r, Login login)
    {
        if (r.Kind != ServerKind.Linux || login.User == r.User || login.User == "root") return null;
        return _ui.Choose("Administrator elevation", ["Passwordless sudo", "Sudo with password"]) == 0
            ? "" : _ui.Text("Sudo password", secret: true);
    }

    private List<Remote> Replace(Snapshot snapshot, Remote candidate)
    {
        var list = snapshot.State.Connections.Where(r => r.Id != candidate.Id).ToList();
        if (candidate.OwnsHost)
        {
            var owner = ConnectionService.FindHostOwner(list, candidate.Host);
            if (owner is not null)
            {
                if (!_ui.Confirm($"Move raw-hostname ownership from '{owner.Alias}' to '{candidate.Alias}'?")) throw new OperationCanceledException();
                list = list.Select(r => r.Id == owner.Id ? r with { OwnsHost = false } : r).ToList();
            }
        }
        list.Add(candidate);
        return list;
    }

    private async Task CreateOrEdit(Snapshot snapshot, Remote? original)
    {
        var candidate = Fields(original, snapshot.State.Connections);
        var selected = SelectKey(candidate, original);
        candidate = selected.Remote;
        Validation.Remote(candidate);
        Remote? stagedKey = null;
        var pathComparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (candidate.OwnsKey && !snapshot.State.Connections.Concat(snapshot.State.PendingCleanup)
            .Any(r => r.KeyPath.Equals(candidate.KeyPath, pathComparison)))
        {
            stagedKey = candidate with { Id = Guid.NewGuid(), Enabled = false, OwnsHost = false, ProvisioningNotStarted = true };
            snapshot = _connections.Save(snapshot, snapshot.State with { PendingCleanup = [.. snapshot.State.PendingCleanup, stagedKey] });
            Message("New local key recorded in Pending remote cleanup until provisioning completes.");
        }
        var list = Replace(snapshot, candidate);
        var state = snapshot.State with
        {
            Connections = list,
            PendingCleanup = snapshot.State.PendingCleanup.Where(r => r.Id != stagedKey?.Id).ToList()
        };
        Validation.State(state, snapshot.Groups);
        var endpointChanged = original is null || original.Host != candidate.Host || original.Port != candidate.Port ||
            original.User != candidate.User || original.Kind != candidate.Kind;
        var keyChanged = original is null || Validation.KeyIdentity(original.PublicKey) != Validation.KeyIdentity(candidate.PublicKey);
        if (!endpointChanged && !keyChanged)
        {
            _connections.Save(snapshot, state);
            Message("Connection updated locally.");
            return;
        }
        if (!_ui.Confirm($"Provision {Describe(candidate)} with {KeyService.Fingerprint(candidate.PublicKey)}?"))
            throw new OperationCanceledException();
        var passphrase = selected.Changed ? selected.Passphrase : KeyPassphrase(candidate.KeyPath);
        KeyService.Validate(candidate, passphrase);
        var login = Bootstrap(candidate);
        var sudo = Sudo(candidate, login);
        var attempted = false;
        var phase = "Bootstrap connection";
        try
        {
            using var session = await _transport.Connect(candidate, login, Cancellation);
            phase = "Recording the provisioning attempt";
            if (stagedKey is not null)
            {
                stagedKey = stagedKey with { ProvisioningNotStarted = false };
                snapshot = _connections.Save(snapshot, snapshot.State with
                {
                    PendingCleanup = snapshot.State.PendingCleanup.Select(r => r.Id == stagedKey.Id ? stagedKey : r).ToList()
                });
            }
            attempted = true;
            phase = "Public-key installation";
            Message("Installing the public key...");
            if (candidate.Kind == ServerKind.Linux)
                await LinuxProvisioner.Apply(session, candidate, login, sudo, false, Cancellation);
            else candidate = await MikroTikProvisioner.Provision(session, candidate, Cancellation);
            phase = "Key-only authentication after public-key installation";
            Message("Public-key installation completed. Testing the target user's private key (not the bootstrap password)...");
            await _transport.Test(candidate, passphrase, Cancellation);
        }
        catch (Exception ex) when (Expected(ex) || ex is OperationCanceledException)
        {
            if (attempted)
            {
                var pending = candidate with { Id = stagedKey?.Id ?? Guid.NewGuid(), Enabled = false, OwnsHost = false };
                try
                {
                    _connections.Save(snapshot, snapshot.State with
                    {
                        PendingCleanup = [.. snapshot.State.PendingCleanup.Where(r => r.Id != pending.Id), pending]
                    });
                }
                catch (Exception persistenceError) when (Expected(persistenceError))
                {
                    throw new IOException($"Remote provisioning/testing failed: {ex.Message}. A remote key may remain for " +
                        $"{candidate.User}@{candidate.Host}:{candidate.Port}, fingerprint {KeyService.Fingerprint(candidate.PublicKey)}. " +
                        $"Key retained: {candidate.KeyPath}. Saving cleanup information also failed: {persistenceError.Message}", ex);
                }
                Message($"Provisioning/testing did not finish. A remote key may remain; saved Pending remote cleanup for {candidate.Alias}. Private key retained at {candidate.KeyPath}.", true);
            }
            if (ex is OperationCanceledException) throw;
            throw new IOException($"{phase} failed: {ex.Message}", ex);
        }
        var cleanup = snapshot.State.PendingCleanup.Where(r => r.Id != stagedKey?.Id).ToList();
        if (original is not null)
        {
            cleanup.Add(original with { Id = Guid.NewGuid(), Enabled = false, OwnsHost = false });
            Message("Old remote authorization remains. Use /remote > Pending remote cleanup to revoke it explicitly.");
        }
        state = state with
        {
            Connections = state.Connections.Select(r => r.Id == candidate.Id ? candidate : r).ToList(),
            PendingCleanup = cleanup
        };
        try { _connections.Save(snapshot, state); }
        catch (Exception ex) when (Expected(ex))
        {
            throw new IOException($"Remote provisioning and key-only login succeeded, but local saving failed. Remote access may remain. Key retained: {candidate.KeyPath}. {ex.Message}", ex);
        }
        Message("Provisioned and verified key-only authentication. Connection saved.");
    }

    private async Task Revoke(Remote remote)
    {
        var login = Bootstrap(remote);
        var sudo = Sudo(remote, login);
        using var session = await _transport.Connect(remote, login, Cancellation);
        if (remote.Kind == ServerKind.Linux) await LinuxProvisioner.Apply(session, remote, login, sudo, true, Cancellation);
        else await MikroTikProvisioner.Revoke(session, remote, Cancellation);
        Message("Managed remote public key revoked (or already absent).");
    }

    private async Task Delete(Snapshot snapshot, Remote remote)
    {
        var flags = _ui.Check($"Delete {Describe(remote)}? Choose optional destructive actions, then Enter.",
            ["Delete app-owned local private/public key files", "Revoke this public key on the remote server"]);
        if (flags.Contains(0) && !flags.Contains(1))
            throw new InputException("Revoke the remote key before deleting local key files, or retain the files for pending cleanup.");
        if (flags.Contains(0)) ConnectionService.GuardKeyDeletion(snapshot.State, remote);
        if (flags.Contains(1)) ConnectionService.GuardRevocation(snapshot.State, remote);
        if (!_ui.Confirm($"Remove '{remote.Alias}' from local config and all groups?")) return;
        if (flags.Contains(1)) await Revoke(remote);
        var state = snapshot.State with { Connections = snapshot.State.Connections.Where(r => r.Id != remote.Id).ToList() };
        if (!flags.Contains(1))
            state = state with { PendingCleanup = [.. state.PendingCleanup, remote with { Id = Guid.NewGuid(), Enabled = false, OwnsHost = false }] };
        _connections.Save(snapshot, state, snapshot.Groups.Select(g => g with
        { Connections = g.Connections.Where(id => id != remote.Id).ToList() }).ToList());
        if (flags.Contains(0))
        {
            File.Delete(remote.KeyPath + ".pub");
            File.Delete(remote.KeyPath);
        }
        Message(flags.Contains(1) ? "Connection deleted." : "Connection deleted locally. Remote authorization retained in Pending remote cleanup.");
    }

    private async Task Cleanup(Snapshot snapshot)
    {
        var list = snapshot.State.PendingCleanup;
        if (list.Count == 0) { Message("No pending keys or remote authorization cleanup."); return; }
        var remote = list[_ui.Choose("Pending keys / remote authorization cleanup",
            list.Select(r => $"{r.Alias} - {Path.GetFileName(r.KeyPath)} - {r.User}@{r.Host}:{r.Port}").ToArray())];
        Message($"{Describe(remote)}\nPrivate key: {remote.KeyPath}\nFingerprint: {KeyService.Fingerprint(remote.PublicKey)}\n" +
            $"Local file: {(File.Exists(remote.KeyPath) ? "present" : "missing")}; ownership: {(remote.OwnsKey ? "app-owned" : "external")}. " +
            (remote.ProvisioningNotStarted ? "Provisioning never started; this is a local-only key." : "Remote installation is not assumed."));
        var action = _ui.Choose("Pending key action",
            ["Test recorded private key", "Recover as a connection (test first)", "Revoke exact remote key",
                "Revoke remote key and delete app-owned files", "Forget record (retain keys and remote authorization)",
                remote.ProvisioningNotStarted ? "Delete unused app-owned local key files" : "Delete app-owned files after verifying remote key is absent",
                "Retry provisioning with recorded key"]);
        if (action == 0)
        {
            await _transport.Test(remote, KeyPassphrase(remote.KeyPath), Cancellation);
            Message("Pending key authentication succeeded. Use Recover as a connection to save it.");
            return;
        }
        if (action == 1)
        {
            var alias = Validation.Token(_ui.Text("Recovered connection alias", remote.Alias), "Alias");
            if (snapshot.State.Connections.Any(r => r.Alias.Equals(alias, StringComparison.OrdinalIgnoreCase)))
                throw new InputException("This alias already exists. Choose a different alias for the recovered connection.");
            await _transport.Test(remote, KeyPassphrase(remote.KeyPath), Cancellation);
            _connections.RecoverPending(snapshot, remote, alias);
            Message("Key-only authentication succeeded. Recovered connection saved disabled; add it to a group to enable it.");
            return;
        }
        if (action == 6) { await RetryPending(snapshot, remote); return; }
        var deleteKey = action is 3 or 5;
        if (deleteKey) ConnectionService.GuardKeyDeletion(snapshot.State, remote);
        if (action is 2 or 3)
        {
            ConnectionService.GuardRevocation(snapshot.State, remote);
            if (!_ui.Confirm($"Revoke {KeyService.Fingerprint(remote.PublicKey)} for {remote.User}@{remote.Host}" +
                (deleteKey ? " and delete its app-owned local key files?" : "? Local key files will be retained."))) return;
            await Revoke(remote);
        }
        else if (!_ui.Confirm(action == 5
            ? remote.ProvisioningNotStarted
                ? "Delete this unused app-owned local key pair? Provisioning never started."
                : $"Confirm remote key {KeyService.Fingerprint(remote.PublicKey)} for {remote.User}@{remote.Host} is absent (removed or never installed). Delete local files? No remote revocation will be performed."
            : "Forget this record? Local key files and remote authorization will remain.")) return;
        _connections.RemovePending(snapshot, remote, deleteKey);
        Message(deleteKey ? "Pending record and app-owned local key files removed." : "Cleanup record removed. Local key files were retained.");
    }

    private async Task RetryPending(Snapshot snapshot, Remote remote)
    {
        var alias = Validation.Token(_ui.Text("Recovered connection alias", remote.Alias), "Alias");
        if (snapshot.State.Connections.Any(r => r.Alias.Equals(alias, StringComparison.OrdinalIgnoreCase)))
            throw new InputException("This alias already exists. Choose a different alias for the recovered connection.");
        var passphrase = KeyPassphrase(remote.KeyPath);
        KeyService.Validate(remote, passphrase);
        if (!_ui.Confirm($"Retry provisioning {Describe(remote)} with its existing key {KeyService.Fingerprint(remote.PublicKey)}?")) return;
        var login = Bootstrap(remote);
        var sudo = Sudo(remote, login);
        var phase = "Bootstrap connection";
        try
        {
            using var session = await _transport.Connect(remote, login, Cancellation);
            phase = "Recording the provisioning attempt";
            remote = remote with { ProvisioningNotStarted = false };
            snapshot = _connections.Save(snapshot, snapshot.State with
            {
                PendingCleanup = snapshot.State.PendingCleanup.Select(r => r.Id == remote.Id ? remote : r).ToList()
            });
            phase = "Public-key installation";
            Message("Installing the recorded public key...");
            if (remote.Kind == ServerKind.Linux)
                await LinuxProvisioner.Apply(session, remote, login, sudo, false, Cancellation);
            else remote = await MikroTikProvisioner.Provision(session, remote, Cancellation);
            phase = "Saving pending key details after installation";
            snapshot = _connections.Save(snapshot, snapshot.State with
            {
                PendingCleanup = snapshot.State.PendingCleanup.Select(r => r.Id == remote.Id ? remote : r).ToList()
            });
            phase = "Key-only authentication after public-key installation";
            await _transport.Test(remote, passphrase, Cancellation);
            phase = "Saving the recovered connection";
            _connections.RecoverPending(snapshot, remote, alias);
        }
        catch (Exception ex) when (Expected(ex))
        {
            throw new IOException($"{phase} failed: {ex.Message}. Key retained at {remote.KeyPath}. " +
                "Check Pending remote cleanup or recover an interrupted local update; remote authorization may remain.", ex);
        }
        Message("Provisioning and key-only authentication succeeded. Recovered connection saved disabled, using the retained key.");
    }

    private void Import(Snapshot snapshot)
    {
        var home = Path.GetDirectoryName(_store.SshDirectory)!;
        var blocks = SshConfig.Discover(_store.ConfigPath, snapshot.Files[_store.ConfigPath], home)
            .Concat(SshConfig.Discover(_store.DisabledPath, snapshot.Files[_store.DisabledPath], home)).ToList();
        var block = blocks[_ui.Choose("Recognized legacy entries (extended/commented blocks require manual migration)",
            blocks.Select(b => $"{b.Alias} - {b.User}@{b.Host}:{b.Port} [{(b.File == _store.ConfigPath ? "enabled" : "disabled")}]").ToArray())];
        var partner = SshConfig.FindPartner(block, blocks);
        var adopted = new List<LegacyBlock> { block };
        if (partner is not null && _ui.Confirm($"Also adopt matching block '{partner.Alias}'? Both entries will follow this connection's state."))
            adopted.Add(partner);
        var canonical = adopted.FirstOrDefault(b => !b.Alias.Equals(b.Host, StringComparison.OrdinalIgnoreCase)) ?? block;
        var r = Fields(new Remote
        {
            Alias = canonical.Alias, Host = canonical.Host, Port = canonical.Port, User = canonical.User,
            Operator = Regex.Replace(Environment.UserName, @"[^A-Za-z0-9_.-]", "_"),
            Tag = Regex.Replace(block.Host, @"[^A-Za-z0-9_.-]", "-"),
            Enabled = canonical.File == _store.ConfigPath,
            OwnsHost = adopted.Count > 1 || block.Alias.Equals(block.Host, StringComparison.OrdinalIgnoreCase),
            Kind = (ServerKind)_ui.Choose("Legacy server type", ["Linux", "MikroTik"])
        }, snapshot.State.Connections);
        r = KeyService.Import(r, block.KeyPath, KeyPassphrase(block.KeyPath));
        var remotes = Replace(snapshot, r);
        if (!_ui.Confirm($"Import {Describe(r)} and replace {adopted.Count} legacy block(s)? Keys and remote authorization will not change."))
        {
            Message("Import canceled. No connection was saved.");
            return;
        }
        _connections.Save(snapshot, snapshot.State with { Connections = remotes }, imports: adopted);
        Message("Connection imported; source key retained and externally owned.");
    }
}
