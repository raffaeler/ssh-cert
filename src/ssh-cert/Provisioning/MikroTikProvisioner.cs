using System.Text;
using System.Text.RegularExpressions;
using SshCert.Models;
using SshCert.Ssh;

namespace SshCert.Provisioning;

public static class MikroTikProvisioner
{
    public static string Quote(string value)
    {
        if (value.Any(char.IsControl)) throw new InputException("RouterOS values cannot contain control characters.");
        return "\"" + value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("$", "\\$", StringComparison.Ordinal) + "\"";
    }

    public static async Task<Remote> Provision(IRemoteSession session, Remote remote, CancellationToken cancellation)
    {
        var version = (await session.Run(":put [/system resource get version]", null, true, cancellation)).Trim();
        var match = Regex.Match(version, @"^(?<major>[0-9]+)\.");
        if (!match.Success || !int.TryParse(match.Groups["major"].Value, out var major))
            throw new IOException($"Cannot determine RouterOS version from '{version}'; no public key was uploaded.");
        if (major < 7 && Validation.KeyIdentity(remote.PublicKey).StartsWith("ssh-ed25519 ", StringComparison.Ordinal))
            throw new InputException($"RouterOS {version} does not support Ed25519 SSH user keys. " +
                "Create a connection with RSA-4096 instead. An Ed25519 key cannot be converted to RSA. " +
                "No public key was uploaded; the retained local key can be managed in Pending remote cleanup.");
        var user = Quote(remote.User);
        await session.Run($":if ([:len [/user find where name={user}]] != 1) do={{ :error \"Target user missing\" }}", null, true, cancellation);
        var before = await Keys(session, remote, cancellation);
        var fingerprint = KeyService.Fingerprint(remote.PublicKey);
        var same = before.Where(p => Matches(p.Value, fingerprint)).ToArray();
        if (same.Length > 0) return remote with { RouterKeyId = same[0].Key };
        var name = "ssh-cert-" + Guid.NewGuid().ToString("N") + ".pub";
        Exception? operationFailure = null;
        try
        {
            await session.Upload(Encoding.UTF8.GetBytes(remote.PublicKey + "\n"), name, cancellation);
            await session.Run($"/user ssh-keys import user={user} public-key-file={Quote(name)}", null, true, cancellation);
            var after = await Keys(session, remote, cancellation);
            var added = after.Where(p => !before.ContainsKey(p.Key)).ToArray();
            if (added.Length != 1) throw new IOException("RouterOS import completed, but the added key could not be identified uniquely. Inspect remote keys before retrying.");
            return remote with { RouterKeyId = added[0].Key };
        }
        catch (Exception ex) { operationFailure = ex; throw; }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            try { await session.Run($"/file remove [/file find where name={Quote(name)}]", null, true, cleanup.Token); }
            catch (Exception ex) when (ex is IOException or Renci.SshNet.Common.SshException or OperationCanceledException)
            {
                throw new IOException($"Router temporary public file '{name}' could not be cleaned up. Original operation: {operationFailure?.Message ?? "import completed"}. Cleanup: {ex.Message}", operationFailure ?? ex);
            }
        }
    }

    public static async Task Revoke(IRemoteSession session, Remote remote, CancellationToken cancellation)
    {
        var keys = await Keys(session, remote, cancellation);
        var fingerprint = KeyService.Fingerprint(remote.PublicKey);
        if (keys.Count > 0 && keys.Values.Any(v => v.Length == 0))
            throw new IOException("This RouterOS version does not expose user-key fingerprints. Safe automatic revocation requires fingerprint support (RouterOS 7.20+); remove the exact key manually.");
        if (keys.Values.Any(v => !Regex.IsMatch(v, @"^(SHA256:)?[A-Za-z0-9+/]{43}=?$")))
            throw new IOException("RouterOS returned an unsupported fingerprint format; no keys were removed.");
        foreach (var pair in keys.Where(p => Matches(p.Value, fingerprint)))
        {
            if (!Regex.IsMatch(pair.Key, @"^\*[A-Fa-f0-9]+$")) throw new IOException("Unexpected RouterOS key ID.");
            await session.Run($":if ([/user ssh-keys get {pair.Key} fingerprint] != {Quote(pair.Value)}) do={{ :error \"Key changed\" }}; /user ssh-keys remove {pair.Key}", null, true, cancellation);
        }
    }

    private static bool Matches(string actual, string expected) =>
        actual.Trim().TrimEnd('=').Equals(expected, StringComparison.Ordinal) ||
        ("SHA256:" + actual.Trim().TrimEnd('=')).Equals(expected, StringComparison.Ordinal);

    private static async Task<Dictionary<string, string>> Keys(IRemoteSession session, Remote remote, CancellationToken cancellation)
    {
        var output = await session.Run(
            $":foreach k in=[/user ssh-keys find where user={Quote(remote.User)}] do={{ :local fp \"\"; :do {{ :set fp [/user ssh-keys get $k fingerprint] }} on-error={{ :set fp \"\" }}; :put ($k . \"\\t\" . $fp) }}",
            null, true, cancellation);
        var result = new Dictionary<string, string>();
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var fields = line.TrimEnd('\r').Split('\t', 2);
            if (fields.Length != 2 || !Regex.IsMatch(fields[0], @"^\*[A-Fa-f0-9]+$"))
                throw new IOException("Unable to parse RouterOS key inventory; no keys were removed.");
            result.Add(fields[0], fields[1]);
        }
        return result;
    }
}
