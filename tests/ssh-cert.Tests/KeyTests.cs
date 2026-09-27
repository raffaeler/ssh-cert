using Renci.SshNet;
using SshCert.Models;
using SshCert.Ssh;
using SshCert.Storage;
using System.Diagnostics;

namespace SshCert.Tests;

public sealed class TestHome : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ssh-cert-test-" + Guid.NewGuid());
    public StateStore Store { get; }
    public TestHome() { Directory.CreateDirectory(Path); Store = new StateStore(Path); }
    public void Dispose() => Directory.Delete(Path, true);
}

public class KeyTests
{
    [Theory]
    [InlineData(false, "")]
    [InlineData(false, "test passphrase")]
    [InlineData(true, "")]
    [InlineData(true, "test passphrase")]
    public void KeysRoundTripThroughSshNetAndOpenSsh(bool rsa, string passphrase)
    {
        using var home = new TestHome();
        var remote = new KeyService(home.Store).Generate(new Remote
        {
            Alias = "test", Host = "localhost", User = "test", Operator = "test", Tag = "test"
        }, rsa, passphrase);
        using var key = new PrivateKeyFile(remote.KeyPath, passphrase);
        Assert.Equal(Validation.KeyIdentity(remote.PublicKey), Validation.KeyIdentity(KeyService.Public(key)));
        var start = new ProcessStartInfo("ssh-keygen") { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in new[] { "-y", "-P", passphrase, "-f", remote.KeyPath }) start.ArgumentList.Add(arg);
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        Assert.True(process.WaitForExit(30000), "ssh-keygen timed out");
        Assert.True(process.ExitCode == 0, error);
        Assert.Equal(Validation.KeyIdentity(remote.PublicKey), Validation.KeyIdentity(output.Trim()));
        if (passphrase.Length > 0) Assert.ThrowsAny<Exception>(() => new PrivateKeyFile(remote.KeyPath, "wrong"));
    }
}
