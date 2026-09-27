using System.Security.Cryptography;
using System.Text;
using Renci.SshNet;
using SshNet.Keygen;
using SshNet.Keygen.Extensions;
using SshNet.Keygen.SshKeyEncryption;
using SshCert.Models;
using SshCert.Storage;

namespace SshCert.Ssh;

public sealed class KeyService(StateStore store)
{
    private readonly StateStore _store = store;

    public static string Public(PrivateKeyFile key) => key.ToPublic().Trim();
    public static void Validate(Remote remote, string? passphrase)
    {
        using var key = new PrivateKeyFile(remote.KeyPath, passphrase ?? "");
        if (Validation.KeyIdentity(Public(key)) != Validation.KeyIdentity(remote.PublicKey))
            throw new InputException("The private key no longer matches this connection's recorded public key.");
    }

    public static string Fingerprint(string publicKey)
    {
        var identity = Validation.KeyIdentity(publicKey);
        return "SHA256:" + Convert.ToBase64String(SHA256.HashData(
            Convert.FromBase64String(identity.Split(' ')[1]))).TrimEnd('=');
    }

    public Remote Generate(Remote remote, bool rsa, string? passphrase)
    {
        Validation.Token(remote.Operator, "Operator");
        Validation.Token(remote.Tag, "Target tag");
        PrivateFiles.Directory(_store.DataDirectory);
        var prefix = rsa ? "id_rsa" : "id_ed25519";
        var path = Path.Combine(_store.SshDirectory, $"{prefix}_{remote.Operator}_{remote.Actor}_{remote.Tag}");
        if (File.Exists(path) || File.Exists(path + ".pub")) path += "_" + Guid.NewGuid().ToString("N")[..8];
        var info = new SshKeyGenerateInfo(rsa ? SshKeyType.RSA : SshKeyType.ED25519);
        if (rsa) info.KeyLength = 4096;
        if (!string.IsNullOrEmpty(passphrase)) info.Encryption = new SshKeyEncryptionAes256(passphrase);
        var key = SshKey.Generate(info);
        var publicKey = Validation.KeyIdentity(key.ToPublic().Trim()) + " " + remote.Comment;
        PrivateFiles.WriteNew(path, Encoding.UTF8.GetBytes(string.IsNullOrEmpty(passphrase)
            ? key.ToOpenSshFormat() : key.ToOpenSshFormat(passphrase)));
        try { PrivateFiles.WriteNew(path + ".pub", Encoding.UTF8.GetBytes(publicKey + "\n")); }
        catch (IOException) { File.Delete(path); throw; }
        return remote with { KeyPath = path, PublicKey = publicKey, OwnsKey = true };
    }

    public static Remote Import(Remote remote, string path, string? passphrase)
    {
        path = Path.GetFullPath(path);
        PrivateFiles.RejectLink(path);
        using var key = new PrivateKeyFile(path, passphrase ?? "");
        var publicKey = Validation.KeyIdentity(key.ToPublic().Trim()) + " " + remote.Comment;
        if (File.Exists(path + ".pub") &&
            Validation.KeyIdentity(File.ReadAllText(path + ".pub").Trim()) != Validation.KeyIdentity(publicKey))
            throw new InputException("The public key alongside this private key does not match.");
        var header = File.ReadLines(path).FirstOrDefault() ?? "";
        if (header is not ("-----BEGIN OPENSSH PRIVATE KEY-----" or "-----BEGIN RSA PRIVATE KEY-----" or
            "-----BEGIN PRIVATE KEY-----" or "-----BEGIN ENCRYPTED PRIVATE KEY-----"))
            throw new InputException("Import an OpenSSH/PEM key, or use Convert to OpenSSH to create a separate compatible copy.");
        if (publicKey.StartsWith("ssh-ed25519 ", StringComparison.Ordinal) && !header.Contains("OPENSSH"))
            throw new InputException("Convert Ed25519 PEM to OpenSSH for external SSH client compatibility.");
        return remote with { KeyPath = path, PublicKey = publicKey, OwnsKey = false };
    }

    public Remote ConvertKey(Remote remote, string source, string? passphrase)
    {
        using var key = new PrivateKeyFile(source, passphrase ?? "");
        PrivateFiles.Directory(_store.DataDirectory);
        var path = Path.Combine(_store.SshDirectory, $"id_import_{Guid.NewGuid():N}");
        var publicKey = Validation.KeyIdentity(key.ToPublic().Trim()) + " " + remote.Comment;
        PrivateFiles.WriteNew(path, Encoding.UTF8.GetBytes(string.IsNullOrEmpty(passphrase)
            ? key.ToOpenSshFormat() : key.ToOpenSshFormat(passphrase)));
        PrivateFiles.WriteNew(path + ".pub", Encoding.UTF8.GetBytes(publicKey + "\n"));
        return remote with { KeyPath = path, PublicKey = publicKey, OwnsKey = true };
    }
}
