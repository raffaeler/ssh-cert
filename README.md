# ssh-cert

A .NET 10 console application for provisioning SSH public keys and selecting
which managed connections appear in your local OpenSSH configuration.

Supports **Windows x64, Linux x64, and Linux ARM64**. Each release target is a
single self-contained executable; an installed .NET runtime is not required.
Application operations use SSH.NET, not local `ssh`, `scp`, `ssh-keygen`,
PowerShell, or Bash processes.

Despite the name, this application manages **SSH key pairs, not CA-signed SSH
certificates**. Use your normal SSH client outside the application to open a
remote shell.

## Usage

```text
ssh-cert
ssh-cert --group "Office machines"
ssh-cert --help
ssh-cert --version
```

Type `/` at the prompt to open the command menu. Use Up/Down to select, Enter
to confirm, and Space to toggle `[X]` / `[ ]` checkboxes. Type to filter lists;
selections survive filtering. Escape goes back without accepting the current
form. Ctrl+C cancels the current operation (at the root prompt, it exits).
Text fields are prefilled when editing; `|` indicates the insertion position.
On confirmation screens, **Enter confirms and Esc cancels**, without an extra
checkbox. Space is only for selecting list items and optional flags.

Menus are inline and preserve terminal history. Long lists scroll within the
available viewport; menus reserve additional lines at the bottom of the
terminal. Resize to at least 16 columns and 4 rows. Interactive commands need
terminal input and output; redirected use supports `--group`, `--help`, and
`--version`.

| Command | Behavior |
|---|---|
| `/remote` | Create/import a connection, or select one to Edit, Test, Delete, or review host trust. Also exposes pending remote cleanup. |
| `/group` | Create a group, select an existing group to apply it, or choose the separate Edit/Delete actions. |
| `/group <name>` | Apply a group immediately. Names can be quoted and are compared case-insensitively. |
| `/help` | Show command help. |
| `/exit` | Exit. |

`--group <name>` applies the saved group **locally and exits**, without contacting
servers or asking for credentials. It enables every group member and disables
every other **app-managed** connection. An empty group disables all managed
connections. Creating/editing group membership does not apply it unless you
choose Apply; deleting a group leaves the current enabled set unchanged.

To add connections to an existing group, choose `/group` > **Edit group** >
the group, then press Space beside each connection and Enter to save. Simply
highlighting a connection does not select it. The membership list shows all saved
connections, including imported ones, and reports the selected count. An empty
list means no connection has been saved yet; complete `/remote` > **Import script
connections** or **Create** first. You can still intentionally save an empty group.

Exit codes: `0` success, `1` operational failure, `2` invalid input, `130` canceled.

Every invocation starts with `ssh-cert <version>`, including help, group commands,
and errors. `--version` prints that banner once. The version is defined only in
the application project and read from assembly metadata at runtime.
Interactive startup also prints `Active group: <name>`, based on the exact set
of enabled connections. A custom selection is reported when no group matches;
if several groups have identical membership, all matching names are shown.
This display does not change or reapply the current selection.

## What enabled and disabled mean

Enabled entries are in `~/.ssh/config`; disabled entries are parked in
`~/.ssh/hosts-disabled.conf`, which must **not** be included by your SSH config.
Both the connection alias and its owned raw-hostname entry move together.

Managed aliases and owned raw hostnames are **case-insensitive**: `ssh Office`,
`ssh office`, and `ssh OFFICE` select the same connection. Display names,
remote usernames, and key-file paths retain their original casing. Generated
configuration uses `Match originalhost`, without helper scripts or shell commands.
Use a current OpenSSH client (verified with Linux OpenSSH 8.2 and Windows 9.5);
obsolete clients such as the 2015 Windows OpenSSH 7.1 port do not implement this
matching correctly. If an old installation shadows Windows' built-in client,
use `%WINDIR%\System32\OpenSSH\ssh.exe` or put that directory first in `PATH`.

To select that client for the **current Command Prompt** session:

```cmd
set "PATH=%SystemRoot%\System32\OpenSSH;%PATH%"
```

For the **current PowerShell** session instead:

```powershell
$env:Path = "$env:WINDIR\System32\OpenSSH;$env:Path"
```

These commands are shell-specific and do not change the persistent system PATH.
In Command Prompt, `where ssh` shows which executable will be selected first.

After upgrading, reapply a group once to refresh existing managed rules.
Unmodified older `Host` sections are migrated automatically during that update;
externally edited managed sections are still rejected. Raw hostnames only select
a connection when its **Own raw-hostname entry** flag is enabled.

**This is a convenience toggle, not access revocation.** Explicit `ssh -i`,
agent-held keys, other configuration files, other authorized keys, and existing
sessions can still work. The application does not remove agent keys or change
remote authorization when applying groups. Test explicitly tries the recorded
private key even if the connection is disabled.

Several aliases may address the same hostname, user, or port. Only one
connection may own the unqualified `ssh hostname` mapping, chosen explicitly
with the raw-hostname checkbox. Disabling its owner does not assign that mapping
to another connection automatically. Prefer distinct aliases for distinct
users/actors.

Unrelated SSH settings are preserved. Managed blocks are placed before other
settings and end with a `Host *` boundary. OpenSSH `IdentityFile` directives are
additive; wildcard/Include/Match settings can affect behavior outside what this
tool manages. Resolve conflicting explicit Host entries instead of assuming
this tool overrides every possible SSH configuration.

## Provisioning

Create asks for the server type, address, existing target user, and alias.
Choose fields to change the port (default 22), operator, actor (`ai` or `human`),
target tag, and flags. New connections are **disabled by default**.
For an unclaimed hostname, **Own raw-hostname entry** starts checked, so enabling
the connection supports both `ssh alias` and `ssh hostname`. Uncheck it for an
alias-only connection. An existing owner (even disabled) is never taken over
automatically, and editing an existing connection preserves its ownership choice.

Generate an Ed25519 key (default) or RSA-4096 key, import an existing private key,
or convert it into a separate OpenSSH-format copy. Generated filenames follow
`id_ed25519_<operator>_<actor>_<target>` or `id_rsa_...`; collisions receive a
unique suffix and never overwrite existing keys. The public-key comment is
`operator|actor|target`. Original imported keys remain externally owned.

Passphrase protection is optional. Passwords and passphrases are masked and
never written to JSON or logs. A protected key can still prompt for its local
passphrase: passwordless server authentication does not mean passphrase-free
key use. Supported imports are RSA/Ed25519 private keys; use Convert for PuTTY
keys or Ed25519 PEM that an external OpenSSH client cannot directly use.

Bootstrap login supports a password (including keyboard-interactive challenges)
or an existing private key. Matching saved/pending keys are offered directly;
selecting one is explicit, with no automatic fallback to another identity.
On first contact, verify and accept the displayed
SHA-256 **server host-key fingerprint**. Changed host keys are rejected; the
selected remote's Review host trust action requires explicit replacement
approval. App trust is separate from your SSH client's `known_hosts` file.

### Linux / OpenSSH

The target account must already exist. Log in as that user, as root, or as an
administrator allowed to use sudo for the installation. Both passwordless and
password-required sudo are supported; policies that require a TTY or disallow
the necessary command fail explicitly. Administrators use `sudo -u <target>`;
root bootstrap uses `runuser -u <target>`. Filesystem changes run as the target
account rather than granting root privileges to user-controlled paths.

The application uses a remote POSIX shell and standard Linux tools (`getent`,
`readlink`, `stat`, `awk`, `mktemp`, `cmp`, and core utilities; root bootstrap
also needs `runuser`). No local shell
executable is needed. It resolves the user's real home, updates
`.ssh/authorized_keys`, preserves other entries and key restrictions, and sets
appropriate ownership and permissions. Unsafe symlinks, hard-linked key files,
or writable-by-others SSH directories are rejected for manual review.

It does not create accounts or change `sshd_config`. Servers using a custom
`AuthorizedKeysFile`, external authorized-key commands, or restrictive
authentication policy may need manual administration. The final key-only test
must succeed before the connection is committed.

### MikroTik / RouterOS

The bootstrap account must be allowed to upload a public-key file and import it
into the existing RouterOS target user. The application uses SCP and RouterOS
commands, then removes only its generated temporary upload.

It does not broadly delete a user's keys or assume a matching comment proves
key ownership. Routers exposing user-key SHA-256 fingerprints support precise
idempotent lookup and revocation. **Automatic revocation requires fingerprint
support (RouterOS 7.20+); older firmware requires manual exact-key removal.**
On versions without fingerprints, importing an existing key may report a
duplicate; the application does not remove a working key to force replacement.
Choose RSA-4096 explicitly when a router does not support Ed25519.
RouterOS 6 (including 6.45.9) requires RSA; its SSH user authentication does not
support Ed25519. The app checks the firmware version before uploading a public
key and rejects this unsupported combination with an RSA-4096 instruction.
An existing Ed25519 key cannot be converted to RSA: generate a new RSA-4096 pair.
Automatic fingerprint-based revocation remains limited to RouterOS 7.20+;
older routers require independently verified remote cleanup.

RouterOS interoperability requires verification on your supported firmware.
The repository includes command-level tests and an opt-in live integration
test, but no bundled CHR appliance or live-router credentials. For a dedicated,
authorized RouterOS 7.20+ lab account, supply these environment variables:
`SSHCERT_ROUTER_TEST_HOST`, `SSHCERT_ROUTER_TEST_USER` (existing target),
`SSHCERT_ROUTER_TEST_ADMIN`, `SSHCERT_ROUTER_TEST_PASSWORD`, and
`SSHCERT_ROUTER_TEST_HOST_FINGERPRINT` (independently verified `SHA256:...`).
`SSHCERT_ROUTER_TEST_PORT` defaults to 22. Run
`dotnet test --filter FullyQualifiedName~RouterOsIntegrationTests`.
This deliberately provisions a new test key, checks idempotence and key-only
login, and revokes that exact key; do not point it at an unauthorized account.
Without those settings, the test is explicitly skipped.

## Import, edit, delete, and recovery

Import discovers conservative reference-script blocks in `config` and
`hosts-disabled.conf`, previews alias/hostname pairing and placement, and asks
for missing metadata. Pairing works whether you select the alias or hostname
entry first; the friendly alias's state is proposed for the combined connection.
Confirm before converting them into managed blocks.
The import is complete only when the application reports **Connection imported**.
Continuing past the details form is not the final save: press Enter on the
import confirmation to save, or Esc to cancel. Canceling reports that no
connection was saved.
Commented, extended, duplicate, or ambiguous blocks need manual review.
Import validates private/public key consistency; it never provisions the server
or deletes the source key.

Editing local metadata is local. Changing the server, user, or key requires
explicit provisioning and key-only validation before switching the record.
Old authorization is retained in **Pending remote cleanup** until explicitly
revoked or forgotten. A failed provisioning attempt may also create a cleanup
record; inspect it before retrying. Generated private keys are retained on
failure/cancellation, with their paths displayed, rather than silently destroyed.

Delete removes local configuration and group membership. Additional unchecked
options request remote revocation and deletion of app-owned local key files.
Imported originals and shared keys cannot be deleted. Revoke first before
deleting local keys; otherwise the key is retained for pending cleanup.
A failed revocation stops deletion. Local-only deletion leaves a cleanup record.
Remote revocation does not terminate already-open SSH sessions.

**Pending remote cleanup** also manages retained local keys. Select a record to
see its path, fingerprint, and ownership; test its recorded key; retry provisioning
without generating another key; or recover it as a disabled connection after a
successful key-only test. Recovery does not
overwrite an existing alias, enable raw-hostname ownership, or add group membership.
You can revoke and retain the files, revoke and delete app-owned files, or forget
the record while retaining the files. If your router cannot revoke by fingerprint,
remove the exact remote key independently, then use the explicit verified-absence
cleanup action. That action also covers old failures where the key was never
installed. Imported/shared key files remain protected.

New app-owned keys are tracked before provisioning confirmation and bootstrap
login, so cancellation or a rejected password no longer leaves them unlisted.
Keys whose provisioning never started can be deleted locally through the pending
menu. Once provisioning is attempted, cleanup conservatively assumes remote
authorization might remain. File-deletion failures retain the pending record.

### MikroTik password troubleshooting

`expected command name` during **Installing the public key** is a RouterOS
command-syntax error, not a rejected password. Commands use classic,
space-separated paths such as `/user find` and `/user ssh-keys import` for
compatibility with older RouterOS parsers.

RouterOS defaults to allowing passwords only when the login user has no SSH
keys (`password-authentication=yes-if-no-key`; older releases expose
`always-allow-password-login`). A **correct password may be rejected after a key
is installed**. Choose a matching recorded key in Bootstrap authentication, or
use a separate administrator account that still permits password login.
The application never changes this router policy automatically.
See the [RouterOS SSH server documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/132350014/SSH).

Errors distinguish the bootstrap connection, public-key installation, and the
subsequent target-user key-only test. A failure in that last stage does not mean
the bootstrap password was wrong. Preserve the exact error and RouterOS version
when troubleshooting; DNS, SSH permissions, and key support can also cause failures.
Older RouterOS releases may also offer only `hmac-sha1,hmac-md5`, causing
`no matching MAC found` with modern Windows OpenSSH. This is separate from
hostname matching and authentication. Update RouterOS or explicitly review a
per-host compatibility exception; do not enable legacy algorithms globally or
disable host-key verification.

State lives under your home directory:

```text
.ssh/
  config
  hosts-disabled.conf
  id_ed25519_...             # private key
  id_ed25519_....pub         # public key
  ssh-cert/
    connections.json
    groups/<group-id>.json
    known-hosts.json
```

Schema-versioned JSON uses stable connection IDs. Do not put private keys,
passwords, or passphrases in group files. Data/key files use private permissions;
paths containing symlinks/reparse points are rejected.

Writes use a cross-process lock and a recovery journal containing before/after
images of local configuration and metadata. If interrupted, restart
interactively and choose to complete or roll back the saved update. Recovery
refuses to overwrite a subsequently edited file. Back up conflicting files
and inspect `~/.ssh/ssh-cert/transaction.json` before manual repair. Files are
replaced individually, not as a filesystem-wide atomic transaction.

External modifications to managed blocks are rejected rather than silently
overwritten. Restore the original managed section before continuing. A remote
effect cannot be rolled back by recovering local files; error messages and
pending cleanup records distinguish these cases.

## Build, verify, and publish

Contributor requirements are in [the repository instructions](.github/copilot-instructions.md).
Private fields use `_camelCase`, enforced by `.editorconfig` and regression
coverage. Increment the project's semantic version for application-code changes;
do not maintain separate hard-coded CLI versions or increment on every build.

Requires the .NET 10 SDK for development:

```text
dotnet build ssh-cert.slnx
dotnet test ssh-cert.slnx
dotnet format style ssh-cert.slnx --diagnostics IDE1006 --verify-no-changes
dotnet publish src/ssh-cert -c Release -r win-x64 --self-contained true -o artifacts/win-x64
dotnet publish src/ssh-cert -c Release -r linux-x64 --self-contained true -o artifacts/linux-x64
dotnet publish src/ssh-cert -c Release -r linux-arm64 --self-contained true -o artifacts/linux-arm64
```

Use your shell's path separators. Tests use OpenSSH tools as an independent
compatibility oracle; those tools are **not application runtime dependencies**.
Linux CI creates loopback-only, disposable SSH users to test same-user and
sudo provisioning and exact revocation. Without that explicitly configured
fixture, the live SSH integration test is reported as skipped.

CI targets each supported architecture, tests, and uploads one executable per
target. Linux also uses Python's standard-library pseudoterminal support to
exercise the published UI at the bottom of the screen, resize it, create an
empty group, and apply that group through the CLI. Python is test-only.
The binary bundles the .NET runtime; native runtime files may be
extracted to .NET's per-user temporary cache on launch. Standard OS native
prerequisites for .NET 10 still apply. Trimming and Native AOT are not enabled.

Runtime dependencies are SSH.NET and SshNet.Keygen (MIT), with managed
transitive dependencies including BouncyCastle, Konscious cryptography, and
Microsoft abstractions. See the packages' licenses for redistribution details.
