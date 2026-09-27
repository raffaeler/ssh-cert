using System.Security.Cryptography;
using SshCert.Models;
using SshCert.Storage;

namespace SshCert.Ssh;

public sealed record TrustedHost(string Host, int Port, string Algorithm, string Key);
public sealed record TrustFile(int SchemaVersion, List<TrustedHost> Hosts);

public sealed class HostTrust(StateStore store, Func<string, bool> confirm)
{
    private readonly StateStore _store = store;
    private readonly Func<string, bool> _confirm = confirm;

    public void Verify(string host, int port, string algorithm, byte[] key, bool review = false)
    {
        var original = StateStore.Read(_store.TrustPath);
        var file = original is null ? new TrustFile(1, []) : StateStore.Deserialize<TrustFile>(original);
        if (file.SchemaVersion != 1 || file.Hosts is null) throw new InputException("Unsupported host trust file.");
        var existing = file.Hosts.Where(h => h.Host.Equals(host, StringComparison.OrdinalIgnoreCase) && h.Port == port).ToList();
        if (existing.Count > 1) throw new InputException("Duplicate host trust entries.");
        var known = existing.SingleOrDefault();
        var encoded = Convert.ToBase64String(key);
        if (known?.Key == encoded && known.Algorithm == algorithm) return;
        static string Fingerprint(byte[] bytes) => "SHA256:" + Convert.ToBase64String(SHA256.HashData(bytes)).TrimEnd('=');
        var fingerprint = Fingerprint(key);
        if (known is not null && !review)
            throw new IOException($"HOST KEY CHANGED for {host}:{port}. Received {fingerprint}. Use the remote's Review host trust action after verifying the change independently.");
        var prompt = known is null
            ? $"Trust {host}:{port} {algorithm} {fingerprint}? Verify this fingerprint independently."
            : $"Replace trusted key for {host}:{port}? OLD {Fingerprint(Convert.FromBase64String(known.Key))}; NEW {fingerprint}. Verify independently.";
        if (!_confirm(prompt)) throw new OperationCanceledException("Host trust was not approved.");
        file.Hosts.RemoveAll(h => h.Host.Equals(host, StringComparison.OrdinalIgnoreCase) && h.Port == port);
        file.Hosts.Add(new TrustedHost(host, port, algorithm, encoded));
        _store.WriteTrust(original, StateStore.Serialize(file));
    }
}
