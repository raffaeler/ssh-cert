using System.Text;
using Renci.SshNet;
using Renci.SshNet.Common;
using SshCert.Models;

namespace SshCert.Ssh;

public sealed record Login(string User, string? Password = null, string? KeyPath = null, string? Passphrase = null);

public interface IRemoteSession : IDisposable
{
    Task<string> Run(string command, string? input, bool router, CancellationToken cancellation);
    Task Upload(byte[] content, string name, CancellationToken cancellation);
}

public sealed class SshTransport(HostTrust trust, Func<string, string> secretPrompt)
{
    private readonly HostTrust _trust = trust;
    private readonly Func<string, string> _secretPrompt = secretPrompt;

    public async Task<IRemoteSession> Connect(Remote remote, Login login, CancellationToken cancellation, bool review = false)
    {
        PrivateKeyFile? key = null;
        List<AuthenticationMethod> methods = [];
        if (login.KeyPath is not null)
        {
            key = new PrivateKeyFile(login.KeyPath, login.Passphrase ?? "");
            methods.Add(new PrivateKeyAuthenticationMethod(login.User, key));
        }
        else
        {
            methods.Add(new PasswordAuthenticationMethod(login.User, login.Password ?? ""));
            var interactive = new KeyboardInteractiveAuthenticationMethod(login.User);
            interactive.AuthenticationPrompt += (_, args) =>
            {
                foreach (var prompt in args.Prompts)
                    prompt.Response = prompt.Request.Contains("password", StringComparison.OrdinalIgnoreCase)
                        ? login.Password ?? "" : _secretPrompt(prompt.Request);
            };
            methods.Add(interactive);
        }
        var info = new ConnectionInfo(remote.Host, remote.Port, login.User, methods.ToArray())
        { Timeout = TimeSpan.FromSeconds(20) };
        var client = new SshClient(info) { KeepAliveInterval = TimeSpan.FromSeconds(10) };
        void Attach(BaseClient target) => target.HostKeyReceived += (_, args) =>
        {
            args.CanTrust = false;
            _trust.Verify(remote.Host, remote.Port, args.HostKeyName, args.HostKey, review);
            args.CanTrust = true;
        };
        Attach(client);
        try
        {
            try { await client.ConnectAsync(cancellation); }
            catch (SshAuthenticationException ex)
            {
                throw new SshAuthenticationException(AuthenticationFailureMessage(remote, login.User, key is not null, ex.Message), ex);
            }
            return new Session(client, info, key, methods, Attach);
        }
        catch
        {
            client.Dispose();
            key?.Dispose();
            foreach (var method in methods) method.Dispose();
            throw;
        }
    }

    public static string AuthenticationFailureMessage(Remote remote, string user, bool privateKey, string detail)
    {
        var message = $"SSH {(privateKey ? "private-key" : "password")} authentication failed for {user}@{remote.Host}:{remote.Port}. {detail}";
        if (remote.Kind == ServerKind.MikroTik && !privateKey)
            message += " RouterOS can reject a correct password when this user has an SSH key " +
                "(password-authentication=yes-if-no-key). Select a recorded/existing private key, " +
                "or a separate administrator account that still permits password login. ssh-cert does not change this policy.";
        return message;
    }

    public async Task Test(Remote remote, string? passphrase, CancellationToken cancellation, bool review = false)
    {
        KeyService.Validate(remote, passphrase);
        using var session = await Connect(remote, new Login(remote.User, KeyPath: remote.KeyPath, Passphrase: passphrase), cancellation, review);
    }

    private sealed class Session(SshClient client, ConnectionInfo info, PrivateKeyFile? key,
        List<AuthenticationMethod> methods, Action<BaseClient> attach) : IRemoteSession
    {
        private readonly SshClient _client = client;
        private readonly ConnectionInfo _info = info;
        private readonly PrivateKeyFile? _key = key;
        private readonly List<AuthenticationMethod> _methods = methods;
        private readonly Action<BaseClient> _attach = attach;

        public async Task<string> Run(string command, string? input, bool router, CancellationToken cancellation)
        {
            var marker = "ssh-cert-ok-" + Guid.NewGuid().ToString("N");
            if (router) command = $":do {{ {command}; :put \"{marker}\" }} on-error={{ :error \"ssh-cert RouterOS operation failed\" }}";
            using var cmd = _client.CreateCommand(command);
            cmd.CommandTimeout = TimeSpan.FromSeconds(45);
            var executing = cmd.ExecuteAsync(cancellation);
            if (input is not null)
            {
                using var stream = cmd.CreateInputStream();
                var data = Encoding.UTF8.GetBytes(input);
                try { await stream.WriteAsync(data, cancellation); }
                finally { Array.Clear(data); }
            }
            await executing;
            if ((!router && cmd.ExitStatus != 0) || (router && !cmd.Result.Split('\n').Any(l => l.Trim() == marker)))
                throw new IOException($"Remote operation failed (exit {cmd.ExitStatus}): {cmd.Error} {cmd.Result}");
            return router ? cmd.Result.Replace(marker, "", StringComparison.Ordinal).Trim('\r', '\n') : cmd.Result;
        }

        public async Task Upload(byte[] content, string name, CancellationToken cancellation)
        {
            if (!System.Text.RegularExpressions.Regex.IsMatch(name, @"^ssh-cert-[a-f0-9]{32}\.pub$"))
                throw new InputException("Only generated temporary public-key filenames may be uploaded.");
            using var scp = new ScpClient(_info, RemotePathTransformation.None) { OperationTimeout = TimeSpan.FromSeconds(45) };
            _attach(scp);
            await scp.ConnectAsync(cancellation);
            using var data = new MemoryStream(content, false);
            cancellation.ThrowIfCancellationRequested();
            // SCP upload is synchronous in SSH.NET; disposal interrupts it on cancellation.
            using var registration = cancellation.Register(scp.Dispose);
            await Task.Run(() => scp.Upload(data, name), CancellationToken.None);
            cancellation.ThrowIfCancellationRequested();
        }

        public void Dispose()
        {
            _client.Dispose();
            _key?.Dispose();
            foreach (var method in _methods) method.Dispose();
        }
    }
}
