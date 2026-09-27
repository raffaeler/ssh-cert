using System.Text;
using System.Text.RegularExpressions;
using SshCert.Models;

namespace SshCert.Storage;

public sealed class ConfigDocument
{
    public string Text { get; }
    private readonly Encoding _encoding;
    private readonly byte[] _preamble;
    public string NewLine => Text.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";

    public ConfigDocument(byte[]? bytes)
    {
        bytes ??= [];
        if (bytes.AsSpan().StartsWith(new byte[] { 0xff, 0xfe }))
            _encoding = new UnicodeEncoding(false, true, true);
        else if (bytes.AsSpan().StartsWith(new byte[] { 0xfe, 0xff }))
            _encoding = new UnicodeEncoding(true, true, true);
        else _encoding = new UTF8Encoding(bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }), true);
        _preamble = _encoding.GetPreamble();
        Text = _encoding.GetString(bytes, _preamble.Length, bytes.Length - _preamble.Length);
    }
    public byte[] Encode(string value) => [.. _preamble, .. _encoding.GetBytes(value)];
}

public sealed record LegacyBlock(string File, string Text, string Alias, string Host, string User, int Port, string KeyPath);

public static partial class SshConfig
{
    public const string Begin = "# BEGIN ssh-cert managed";
    public const string End = "# END ssh-cert managed";
    [GeneratedRegex(@"(?im)^[ \t]*(Host|Match)[ \t=]+[^\r\n]*(?:\r?\n|\z)")]
    private static partial Regex Headers();
    [GeneratedRegex("""^(?:"([^"]*)"|(\S+))$""")]
    private static partial Regex ValuePattern();

    public static LegacyBlock? FindPartner(LegacyBlock selected, IEnumerable<LegacyBlock> blocks)
    {
        var selectedIsHost = selected.Alias.Equals(selected.Host, StringComparison.OrdinalIgnoreCase);
        var pathComparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var partners = blocks.Where(b => b != selected &&
            b.Host.Equals(selected.Host, StringComparison.OrdinalIgnoreCase) &&
            b.User == selected.User && b.Port == selected.Port && b.KeyPath.Equals(selected.KeyPath, pathComparison) &&
            (selectedIsHost || b.Alias.Equals(selected.Host, StringComparison.OrdinalIgnoreCase))).ToList();
        if (partners.Count > 1)
            throw new InputException("Multiple matching legacy alias/hostname blocks; resolve duplicates before import.");
        return partners.SingleOrDefault();
    }

    public static string Unmanaged(string text)
    {
        var start = text.IndexOf(Begin, StringComparison.Ordinal);
        var end = text.IndexOf(End, StringComparison.Ordinal);
        if (start < 0 && end < 0) return text;
        if (start != 0 || end < start || text.IndexOf(Begin, Begin.Length, StringComparison.Ordinal) >= 0 ||
            text.IndexOf(End, end + End.Length, StringComparison.Ordinal) >= 0)
            throw new InputException("Malformed or moved ssh-cert managed section; restore it before proceeding.");
        var after = end + End.Length;
        if (after < text.Length && text[after] == '\r') after++;
        if (after < text.Length && text[after] == '\n') after++;
        return text[after..];
    }

    public static byte[] Render(byte[]? original, IEnumerable<Remote> connections) =>
        Render(original, connections, legacyHostRules: false);

    public static bool IsManagedUnchanged(byte[]? original, IEnumerable<Remote> connections)
    {
        var remotes = connections.ToArray();
        var actual = original ?? [];
        return actual.AsSpan().SequenceEqual(Render(original, remotes)) ||
            actual.AsSpan().SequenceEqual(Render(original, remotes, legacyHostRules: true));
    }

    private static byte[] Render(byte[]? original, IEnumerable<Remote> connections, bool legacyHostRules)
    {
        var document = new ConfigDocument(original);
        var unmanaged = Unmanaged(document.Text);
        var remotes = connections.OrderBy(r => r.Alias, StringComparer.OrdinalIgnoreCase).ToArray();
        foreach (var remote in remotes)
        {
            foreach (Match header in Headers().Matches(unmanaged))
            {
                if (!header.Groups[1].Value.Equals("Host", StringComparison.OrdinalIgnoreCase)) continue;
                var names = Regex.Split(header.Value.Trim()[4..].TrimStart(' ', '\t', '='), @"\s+");
                if (names.Any(n => n.Equals(remote.Alias, StringComparison.OrdinalIgnoreCase) ||
                    remote.OwnsHost && n.Equals(remote.Host, StringComparison.OrdinalIgnoreCase)))
                    throw new InputException($"Unmanaged Host entry conflicts with '{remote.Alias}'. Import it explicitly or resolve the conflict.");
            }
        }
        if (remotes.Length == 0) return document.Encode(unmanaged);
        var nl = document.NewLine;
        var result = new StringBuilder().Append(Begin).Append(nl);
        foreach (var remote in remotes)
        {
            result.Append("# connection ").Append(remote.Id).Append(nl);
            Block(remote.Alias, remote);
            if (remote.OwnsHost && !remote.Alias.Equals(remote.Host, StringComparison.OrdinalIgnoreCase))
                Block(remote.Host, remote);
        }
        result.Append("Host *").Append(nl).Append(End).Append(nl).Append(unmanaged);
        return document.Encode(result.ToString());

        void Block(string name, Remote r) => result
            .Append(legacyHostRules ? "Host " : "Match originalhost ")
            .Append(legacyHostRules ? name : name.ToLowerInvariant()).Append(nl)
            .Append("    HostName ").Append(r.Host).Append(nl)
            .Append("    User ").Append(r.User).Append(nl)
            .Append("    Port ").Append(r.Port).Append(nl)
            .Append("    IdentitiesOnly yes").Append(nl)
            .Append("    IdentityFile \"").Append(r.KeyPath.Replace('\\', '/')).Append('"').Append(nl);
    }

    public static List<LegacyBlock> Discover(string path, byte[]? bytes, string home)
    {
        var text = Unmanaged(new ConfigDocument(bytes).Text);
        var headers = Headers().Matches(text);
        var blocks = new List<LegacyBlock>();
        for (var i = 0; i < headers.Count; i++)
        {
            var header = headers[i];
            if (!header.Groups[1].Value.Equals("Host", StringComparison.OrdinalIgnoreCase)) continue;
            var alias = header.Value.Trim()[4..].TrimStart(' ', '\t', '=');
            if (!Regex.IsMatch(alias, @"^[A-Za-z0-9_][A-Za-z0-9_.:-]*$")) continue;
            var end = i + 1 < headers.Count ? headers[i + 1].Index : text.Length;
            var block = text[header.Index..end];
            var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var compatible = true;
            foreach (var line in block.Split('\n').Skip(1))
            {
                var trimmed = line.Trim();
                if (trimmed.Length == 0) continue;
                // Leave commented/extended blocks untouched rather than discarding unknown intent.
                var parts = Regex.Split(trimmed, @"[\t =]+", RegexOptions.None, TimeSpan.FromSeconds(1));
                if (parts.Length < 2 || parts[0].StartsWith('#')) { compatible = false; break; }
                var value = trimmed[parts[0].Length..].TrimStart(' ', '\t', '=');
                if (!fields.TryAdd(parts[0], value)) { compatible = false; break; }
            }
            if (!compatible || fields.Count != 5 ||
                !fields.TryGetValue("HostName", out var host) || !fields.TryGetValue("User", out var user) ||
                !fields.TryGetValue("Port", out var port) || !int.TryParse(port, out var number) ||
                !fields.TryGetValue("IdentitiesOnly", out var only) || !only.Equals("yes", StringComparison.OrdinalIgnoreCase) ||
                !fields.TryGetValue("IdentityFile", out var identity)) continue;
            var valueMatch = ValuePattern().Match(identity);
            // The reference PowerShell script also writes unquoted absolute paths containing spaces.
            if (valueMatch.Success) identity = valueMatch.Groups[1].Success ? valueMatch.Groups[1].Value : valueMatch.Groups[2].Value;
            if (identity.StartsWith("~/", StringComparison.Ordinal)) identity = Path.Combine(home, identity[2..]);
            if (!Path.IsPathFullyQualified(identity) || identity.Contains('"')) continue;
            blocks.Add(new LegacyBlock(path, block, alias, host, user, number, Path.GetFullPath(identity)));
        }
        return blocks;
    }

    public static byte[] RemoveLegacy(byte[]? original, IEnumerable<LegacyBlock> blocks)
    {
        var document = new ConfigDocument(original);
        var text = document.Text;
        foreach (var block in blocks)
        {
            var index = text.IndexOf(block.Text, StringComparison.Ordinal);
            if (index < 0 || text.IndexOf(block.Text, index + block.Text.Length, StringComparison.Ordinal) >= 0)
                throw new InputException("Import block is missing or ambiguous; reload first.");
            text = text.Remove(index, block.Text.Length);
        }
        return document.Encode(text);
    }
}
