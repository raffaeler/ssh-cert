using System.Diagnostics;
using System.Text;
using SshCert.Models;
using SshCert.Storage;

namespace SshCert.Tests;

public class ConfigTests
{
    private static string SshExecutable
    {
        get
        {
            var systemSsh = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "OpenSSH", "ssh.exe");
            return OperatingSystem.IsWindows() && File.Exists(systemSsh) ? systemSsh : "ssh";
        }
    }

    private static string[] EffectiveConfig(string path, string name)
    {
        var start = new ProcessStartInfo(SshExecutable) { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in new[] { "-G", "-F", path, name }) start.ArgumentList.Add(arg);
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(15000), "OpenSSH configuration query timed out.");
        Assert.True(process.ExitCode == 0, error.GetAwaiter().GetResult());
        return output.GetAwaiter().GetResult().Split('\n').Select(line => line.TrimEnd('\r')).ToArray();
    }

    [Fact]
    public void EveryCasingSelectsExactlyOneIdentityInAMultiConnectionGroup()
    {
        using var home = new TestHome();
        var remotes = new[]
        {
            StateTests.Remote(home, "MikroTik-One") with { User = "AdminOne", Port = 2201 },
            StateTests.Remote(home, "MikroTik-Two") with { User = "AdminTwo", Port = 2202 },
            StateTests.Remote(home, "MikroTik-Three") with { User = "AdminThree", Port = 2203 }
        };
        var service = new ConnectionService(home.Store);
        service.Save(home.Store.Load(), new ConnectionFile { Connections = remotes.ToList() },
            [new Group { Name = "All", Connections = remotes.Select(r => r.Id).ToList() }, new Group { Name = "None" }]);
        service.Apply("All");
        foreach (var remote in remotes)
        {
            foreach (var name in new[] { remote.Alias, remote.Host })
            {
                var mixed = string.Concat(name.Select((c, i) => i % 2 == 0 ? char.ToUpperInvariant(c) : char.ToLowerInvariant(c)));
                foreach (var variant in new[] { name, name.ToLowerInvariant(), name.ToUpperInvariant(), mixed })
                {
                    var settings = EffectiveConfig(home.Store.ConfigPath, variant);
                    Assert.Contains("hostname " + remote.Host.ToLowerInvariant(), settings);
                    Assert.Contains("user " + remote.User, settings);
                    Assert.Contains("port " + remote.Port, settings);
                    Assert.Contains("identitiesonly yes", settings);
                    Assert.Equal(["identityfile " + remote.KeyPath.Replace('\\', '/')],
                        settings.Where(line => line.StartsWith("identityfile ")).ToArray());
                }
            }
        }
        var unrelated = EffectiveConfig(home.Store.ConfigPath, "Not-MikroTik-One");
        Assert.DoesNotContain(unrelated, line => remotes.Any(r => line.Contains(r.KeyPath.Replace('\\', '/'))));
        service.Apply("None");
        foreach (var remote in remotes)
        {
            var settings = EffectiveConfig(home.Store.ConfigPath, remote.Alias.ToUpperInvariant());
            Assert.DoesNotContain(settings, line => line.Contains(remote.KeyPath.Replace('\\', '/')));
        }
        Assert.Equal(remotes.Select(r => r.Alias), home.Store.Load().State.Connections.Select(r => r.Alias));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OldManagedRulesMigrateButExternalEditsRemainRejected(bool edited)
    {
        using var home = new TestHome();
        var first = StateTests.Remote(home, "Mixed-Case", enabled: true);
        var second = StateTests.Remote(home, "Another-Case");
        var remotes = new[] { first, second };
        var service = new ConnectionService(home.Store);
        const string unmanaged = "# preserve\nHost unrelated\n    User other\n";
        File.WriteAllText(home.Store.ConfigPath, unmanaged);
        service.Save(home.Store.Load(), new ConnectionFile { Connections = remotes.ToList() },
            [new Group { Name = "All", Connections = remotes.Select(r => r.Id).ToList() }]);
        foreach (var path in new[] { home.Store.ConfigPath, home.Store.DisabledPath })
        {
            var text = File.ReadAllText(path);
            foreach (var remote in remotes)
                foreach (var name in new[] { remote.Alias, remote.Host })
                    text = text.Replace("Match originalhost " + name.ToLowerInvariant() + "\n", "Host " + name + "\n");
            File.WriteAllText(path, text);
        }
        if (edited)
        {
            File.WriteAllText(home.Store.ConfigPath, File.ReadAllText(home.Store.ConfigPath).Replace("Port 22", "Port 2222"));
            var original = File.ReadAllBytes(home.Store.ConfigPath);
            Assert.Throws<IOException>(() => service.Apply("All"));
            Assert.Equal(original, File.ReadAllBytes(home.Store.ConfigPath));
            return;
        }

        service.Apply("All");
        var config = File.ReadAllText(home.Store.ConfigPath);
        Assert.Equal(unmanaged, SshConfig.Unmanaged(config));
        Assert.DoesNotContain("Host Mixed-Case", config);
        Assert.Contains("Match originalhost mixed-case\n", config);
        Assert.Contains("Match originalhost another-case.example\n", config);
        Assert.All(home.Store.Load().State.Connections, remote => Assert.True(remote.Enabled));
        Assert.All(remotes, remote => Assert.True(File.Exists(remote.KeyPath)));
        service.Apply("All");
        Assert.Equal(config, File.ReadAllText(home.Store.ConfigPath));
    }

    [Fact]
    public void LegacyPairingWorksWhenSelectingAliasOrHostname()
    {
        using var home = new TestHome();
        var key = Path.Combine(home.Path, "key");
        var alias = new LegacyBlock(home.Store.DisabledPath, "alias", "office", "server.example", "alice", 22, key);
        var host = new LegacyBlock(home.Store.ConfigPath, "hostname", "server.example", "server.example", "alice", 22, key);
        Assert.Equal(host, SshConfig.FindPartner(alias, [alias, host]));
        Assert.Equal(alias, SshConfig.FindPartner(host, [alias, host]));
        var differentUser = alias with { Alias = "bob", User = "bob" };
        Assert.Equal(alias, SshConfig.FindPartner(host, [alias, host, differentUser]));
        Assert.Throws<InputException>(() => SshConfig.FindPartner(host, [alias, host, alias with { Alias = "duplicate" }]));
    }

    [Theory]
    [InlineData("\n", false)]
    [InlineData("\r\n", false)]
    [InlineData("\r\n", true)]
    public void PreserveUnrelatedContentEncodingAndLineEndings(string nl, bool utf16)
    {
        using var home = new TestHome();
        var r = StateTests.Remote(home, "office", true);
        var original = "# original" + nl + "Host *" + nl + "    ServerAliveInterval 12" + nl +
            "Match host example" + nl + "    ForwardAgent no" + nl;
        Encoding encoding = utf16 ? new UnicodeEncoding(false, true) : new UTF8Encoding(true);
        byte[] bytes = [.. encoding.GetPreamble(), .. encoding.GetBytes(original)];
        var rendered = SshConfig.Render(bytes, [r]);
        var document = new ConfigDocument(rendered);
        Assert.Equal(original, SshConfig.Unmanaged(document.Text));
        Assert.Equal(bytes, SshConfig.Render(rendered, []));
        Assert.Equal(rendered, SshConfig.Render(rendered, [r]));
        Assert.Contains("Host *" + nl + SshConfig.End + nl + original, document.Text);
    }

    [Fact]
    public void DetectExactUnmanagedCollisionsAndMalformedMarkers()
    {
        using var home = new TestHome();
        var r = StateTests.Remote(home, "office");
        Assert.Throws<InputException>(() => SshConfig.Render("Host office\n User someone\n"u8.ToArray(), [r]));
        Assert.Throws<InputException>(() => SshConfig.Unmanaged("# header\n" + SshConfig.Begin + "\n" + SshConfig.End));
        Assert.Throws<InputException>(() => SshConfig.Unmanaged(SshConfig.Begin));
    }

    [Fact]
    public void ImportRecognizesOnlyConservativeReferenceBlocksAndPairsAcrossFiles()
    {
        using var home = new TestHome();
        var path = Path.Combine(home.Path, "key with spaces");
        var text = $"# keep me\nHost office\n    HostName server.example\n    User alice\n    Port 2222\n    IdentitiesOnly yes\n    IdentityFile {path}\n\n" +
            "Host extended\n    HostName example\n    ProxyCommand custom\n";
        var blocks = SshConfig.Discover(home.Store.ConfigPath, Encoding.UTF8.GetBytes(text), home.Path);
        var block = Assert.Single(blocks);
        Assert.Equal(path, block.KeyPath);
        Assert.Equal(2222, block.Port);
        Assert.Equal("# keep me\nHost extended\n    HostName example\n    ProxyCommand custom\n",
            new ConfigDocument(SshConfig.RemoveLegacy(Encoding.UTF8.GetBytes(text), blocks)).Text);
    }

    [Fact]
    public void GeneratedConfigurationIsAcceptedByOpenSshWithSpacesInIdentityPath()
    {
        using var home = new TestHome();
        var r = StateTests.Remote(home, "office", true);
        var rWithSpaces = r with { KeyPath = Path.Combine(home.Path, "key with spaces") };
        var bytes = SshConfig.Render(null, [rWithSpaces]);
        File.WriteAllBytes(home.Store.ConfigPath, bytes);
        var start = new ProcessStartInfo("ssh") { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in new[] { "-G", "-F", home.Store.ConfigPath, "office" }) start.ArgumentList.Add(arg);
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        Assert.True(process.WaitForExit(15000));
        Assert.True(process.ExitCode == 0, error);
        Assert.Contains("hostname office.example", output);
        Assert.Contains("user operator", output);
        Assert.Contains("identityfile " + rWithSpaces.KeyPath.Replace('\\', '/'), output);
    }
}
