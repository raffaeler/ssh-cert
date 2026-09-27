using System.Text.Json;
using SshCert.Models;

namespace SshCert.Storage;

public sealed record Snapshot(ConnectionFile State, List<Group> Groups, Dictionary<string, byte[]?> Files);
public sealed record FileChange(string Path, byte[]? Before, byte[]? After);

public sealed class StateStore
{
    public static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow
    };
    public string SshDirectory { get; }
    public string DataDirectory { get; }
    public string ConfigPath => Path.Combine(SshDirectory, "config");
    public string DisabledPath => Path.Combine(SshDirectory, "hosts-disabled.conf");
    public string StatePath => Path.Combine(DataDirectory, "connections.json");
    public string GroupsDirectory => Path.Combine(DataDirectory, "groups");
    public string TrustPath => Path.Combine(DataDirectory, "known-hosts.json");
    private string JournalPath => Path.Combine(DataDirectory, "transaction.json");

    public StateStore(string? home = null)
    {
        SshDirectory = Path.Combine(home ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh");
        DataDirectory = Path.Combine(SshDirectory, "ssh-cert");
    }

    public static byte[] Serialize<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, Json);
    public static T Deserialize<T>(byte[] data) =>
        JsonSerializer.Deserialize<T>(data, Json) ?? throw new InputException("JSON cannot contain null.");
    public static bool Same(byte[]? first, byte[]? second) =>
        first is null ? second is null : second is not null && first.AsSpan().SequenceEqual(second);
    public static byte[]? Read(string path)
    {
        PrivateFiles.RejectLink(path);
        return File.Exists(path) ? File.ReadAllBytes(path) : null;
    }

    public Snapshot Load()
    {
        if (File.Exists(JournalPath)) throw new IOException("An interrupted update needs recovery. Start the interactive application and choose recovery.");
        var files = new Dictionary<string, byte[]?>(StringComparer.Ordinal);
        byte[]? Capture(string path) => files[path] = Read(path);
        var data = Capture(StatePath);
        var state = data is null ? new ConnectionFile() : Deserialize<ConnectionFile>(data);
        var groups = new List<Group>();
        if (Directory.Exists(GroupsDirectory))
        {
            PrivateFiles.RejectLink(GroupsDirectory);
            foreach (var path in Directory.GetFiles(GroupsDirectory, "*.json").Order())
            {
                var group = Deserialize<Group>(Capture(path)!);
                if (path != GroupPath(group.Id)) throw new InputException($"Group filename does not match its ID: {path}");
                groups.Add(group);
            }
        }
        Capture(ConfigPath);
        Capture(DisabledPath);
        Validation.State(state, groups);
        return new Snapshot(state, groups, files);
    }

    public string GroupPath(Guid id) => Path.Combine(GroupsDirectory, $"{id:D}.json");
    public bool NeedsRecovery => File.Exists(JournalPath);

    private FileStream Lock()
    {
        PrivateFiles.RejectLink(SshDirectory);
        Directory.CreateDirectory(SshDirectory);
        PrivateFiles.Directory(DataDirectory);
        PrivateFiles.Directory(GroupsDirectory);
        var path = Path.Combine(DataDirectory, "lock");
        PrivateFiles.RejectLink(path);
        return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    }

    public Snapshot Commit(Snapshot original, ConnectionFile state, List<Group> groups, byte[]? config, byte[]? disabled,
        Action? beforeCommit = null)
    {
        Validation.State(state, groups);
        var desired = new Dictionary<string, byte[]?>
        {
            [StatePath] = Serialize(state), [ConfigPath] = config, [DisabledPath] = disabled
        };
        foreach (var old in original.Groups) desired[GroupPath(old.Id)] = null;
        foreach (var group in groups) desired[GroupPath(group.Id)] = Serialize(group);
        using var held = Lock();
        var currentGroupPaths = Directory.GetFiles(GroupsDirectory, "*.json").Order().ToArray();
        if (!currentGroupPaths.SequenceEqual(original.Groups.Select(g => GroupPath(g.Id)).Order()))
            throw new IOException("Groups changed in another process. Reload and retry.");
        CommitLocked(desired.Select(pair => new FileChange(pair.Key,
            original.Files.GetValueOrDefault(pair.Key), pair.Value)).ToList(), beforeCommit);
        return new Snapshot(state, groups, desired);
    }

    public void WriteTrust(byte[]? original, byte[] desired)
    {
        using var held = Lock();
        CommitLocked([new FileChange(TrustPath, original, desired)]);
    }

    private void CommitLocked(List<FileChange> changes, Action? beforeCommit = null)
    {
        if (NeedsRecovery) throw new IOException("Recover the interrupted update before making another change.");
        foreach (var change in changes)
            if (!Same(Read(change.Path), change.Before))
                throw new IOException($"File changed outside ssh-cert; reload before retrying: {change.Path}");
        beforeCommit?.Invoke();
        changes.RemoveAll(c => Same(c.Before, c.After));
        if (changes.Count == 0) return;
        PrivateFiles.WriteNew(JournalPath, Serialize(changes));
        foreach (var change in changes)
        {
            if (!Same(Read(change.Path), change.Before))
                throw new IOException($"Concurrent edit detected during update: {change.Path}. Recovery is required.");
            Replace(change.Path, change.After);
        }
        File.Delete(JournalPath);
    }

    public void Recover(bool rollForward)
    {
        using var held = Lock();
        var changes = Deserialize<List<FileChange>>(Read(JournalPath) ?? throw new IOException("No update to recover."));
        foreach (var change in changes)
        {
            var groupPath = Path.GetDirectoryName(change.Path) == GroupsDirectory &&
                Guid.TryParse(Path.GetFileNameWithoutExtension(change.Path), out _) &&
                Path.GetExtension(change.Path) == ".json";
            if (change.Path != ConfigPath && change.Path != DisabledPath && change.Path != StatePath &&
                change.Path != TrustPath && !groupPath)
                throw new IOException("Transaction contains an unexpected path; manual recovery required.");
            var actual = Read(change.Path);
            if (!Same(actual, change.Before) && !Same(actual, change.After))
                throw new IOException($"Recovery would overwrite an external edit: {change.Path}. Preserve it and recover manually.");
        }
        foreach (var change in changes) Replace(change.Path, rollForward ? change.After : change.Before);
        File.Delete(JournalPath);
    }

    private static void Replace(string path, byte[]? content)
    {
        PrivateFiles.RejectLink(path);
        if (content is null) { File.Delete(path); return; }
        var temporary = path + ".ssh-cert-" + Guid.NewGuid().ToString("N");
        try
        {
            PrivateFiles.WriteNew(temporary, content);
            File.Move(temporary, path, true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
