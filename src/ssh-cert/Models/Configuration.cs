using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace SshCert.Models;

[JsonConverter(typeof(JsonStringEnumConverter<ServerKind>))]
public enum ServerKind { Linux, MikroTik }

public sealed record Remote
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public string Alias { get; init; } = "";
    public ServerKind Kind { get; init; }
    public string Host { get; init; } = "";
    public int Port { get; init; } = 22;
    public string User { get; init; } = "";
    public string Operator { get; init; } = "";
    public string Actor { get; init; } = "ai";
    public string Tag { get; init; } = "";
    public string KeyPath { get; init; } = "";
    public string PublicKey { get; init; } = "";
    public bool OwnsKey { get; init; }
    public bool Enabled { get; init; }
    public bool OwnsHost { get; init; }
    public string? RouterKeyId { get; init; }
    public bool ProvisioningNotStarted { get; init; }
    public string Comment => $"{Operator}|{Actor}|{Tag}";
}

public sealed record ConnectionFile
{
    public int SchemaVersion { get; init; } = 1;
    public List<Remote> Connections { get; init; } = [];
    public List<Remote> PendingCleanup { get; init; } = [];
}

public sealed record Group
{
    public int SchemaVersion { get; init; } = 1;
    public Guid Id { get; init; } = Guid.NewGuid();
    public string Name { get; init; } = "";
    public List<Guid> Connections { get; init; } = [];
}

public sealed class InputException(string message) : Exception(message);

public static partial class Validation
{
    [GeneratedRegex(@"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")]
    private static partial Regex TokenPattern();
    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9.:%_-]*$")]
    private static partial Regex HostPattern();

    public static string Token(string value, string label)
    {
        if (value.Length > 128 || !TokenPattern().IsMatch(value))
            throw new InputException($"{label} must start with a letter, digit or underscore and contain only letters, digits, _, . or -.");
        return value;
    }

    public static string Name(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value != value.Trim() || value.Length > 128 || value.Any(char.IsControl))
            throw new InputException("Names must contain 1-128 printable characters, without leading/trailing whitespace.");
        return value;
    }

    public static void Remote(Remote r)
    {
        if (r is null || r.Alias is null || r.Host is null || r.User is null || r.Operator is null ||
            r.Actor is null || r.Tag is null || r.KeyPath is null || r.PublicKey is null)
            throw new InputException("Connection fields cannot be null.");
        if (r.Id == Guid.Empty || !Enum.IsDefined(r.Kind)) throw new InputException("Invalid connection ID or server type.");
        Token(r.Alias, "Alias");
        Token(r.User, "User");
        Token(r.Operator, "Operator");
        Token(r.Tag, "Target tag");
        if (r.Actor is not ("human" or "ai")) throw new InputException("Actor must be human or ai.");
        if (!HostPattern().IsMatch(r.Host) || r.Host.Length > 253)
            throw new InputException("Host must be a DNS name or IP address, without SSH configuration syntax.");
        if (r.Port is < 1 or > 65535) throw new InputException("Port must be between 1 and 65535.");
        if (!Path.IsPathFullyQualified(r.KeyPath) || r.KeyPath.Any(c => char.IsControl(c) || c is '"' or '%' or '$'))
            throw new InputException("Key path must be absolute and cannot contain control characters, quotes, % or $.");
        _ = KeyIdentity(r.PublicKey);
    }

    public static string KeyIdentity(string publicKey)
    {
        if (publicKey.Any(c => c is '\r' or '\n')) throw new InputException("Public key must be one line.");
        var fields = publicKey.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 2 || fields[0] is not ("ssh-ed25519" or "ssh-rsa"))
            throw new InputException("Only Ed25519 and RSA public keys are supported.");
        try { _ = Convert.FromBase64String(fields[1]); }
        catch (FormatException) { throw new InputException("Invalid public key encoding."); }
        return $"{fields[0]} {fields[1]}";
    }

    public static void State(ConnectionFile state, IReadOnlyList<Group> groups)
    {
        if (state.SchemaVersion != 1 || groups.Any(g => g is null || g.SchemaVersion != 1))
            throw new InputException("Unsupported JSON schema version.");
        if (state.Connections is null || state.PendingCleanup is null)
            throw new InputException("Connection lists cannot be null.");
        foreach (var remote in state.Connections.Concat(state.PendingCleanup)) Remote(remote);
        Unique(state.Connections.Select(r => r.Id.ToString()), "connection IDs");
        Unique(state.Connections.Select(r => r.Alias), "aliases");
        Unique(state.PendingCleanup.Select(r => r.Id.ToString()), "pending cleanup IDs");
        Unique(state.Connections.Where(r => r.OwnsHost).Select(r => r.Host.TrimEnd('.')), "raw-hostname owners");
        var aliases = state.Connections.ToDictionary(r => r.Alias, StringComparer.OrdinalIgnoreCase);
        foreach (var r in state.Connections.Where(r => r.OwnsHost))
            if (aliases.TryGetValue(r.Host, out var other) && other.Id != r.Id)
                throw new InputException($"Hostname '{r.Host}' conflicts with alias '{other.Alias}'.");
        Unique(groups.Select(g => g.Name), "group names");
        Unique(groups.Select(g => g.Id.ToString()), "group IDs");
        foreach (var group in groups)
        {
            if (group.Name is null) throw new InputException("Group name cannot be null.");
            Name(group.Name);
            if (group.Id == Guid.Empty || group.Connections is null) throw new InputException("Invalid group.");
            Unique(group.Connections.Select(id => id.ToString()), "group members");
            if (group.Connections.Any(id => state.Connections.All(r => r.Id != id)))
                throw new InputException($"Group '{group.Name}' refers to a missing connection.");
        }
    }

    private static void Unique(IEnumerable<string> values, string label)
    {
        if (values.GroupBy(v => v, StringComparer.OrdinalIgnoreCase).Any(g => g.Count() > 1))
            throw new InputException($"Duplicate {label}.");
    }
}
