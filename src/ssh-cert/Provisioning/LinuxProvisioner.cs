using SshCert.Models;
using SshCert.Ssh;

namespace SshCert.Provisioning;

public static class LinuxProvisioner
{
    public static string Quote(string value) => "'" + value.Replace("'", "'\"'\"'", StringComparison.Ordinal) + "'";

    public static async Task Apply(IRemoteSession session, Remote remote, Login login, string? sudoPassword,
        bool revoke, CancellationToken cancellation)
    {
        var script = Script(remote, revoke);
        var elevate = login.User != remote.User && login.User != "root";
        // Mutate user-controlled paths as that user, not with the administrator's privileges.
        var prefix = elevate ? "sudo -S -p '' -u " + Quote(remote.User) + " -- "
            : login.User != remote.User ? "runuser -u " + Quote(remote.User) + " -- " : "";
        var command = prefix + "sh -c " + Quote(script);
        await session.Run(command, elevate ? (sudoPassword ?? "") + "\n" : null, false, cancellation);
    }

    public static string Script(Remote remote, bool revoke)
    {
        Validation.Remote(remote);
        var identity = Validation.KeyIdentity(remote.PublicKey).Split(' ');
        return $$"""
            set -eu
            umask 077
            fail() { printf '%s\n' "$1" >&2; exit 1; }
            entry=$(getent passwd {{Quote(remote.User)}}) || fail 'Target user does not exist'
            [ "$(printf '%s\n' "$entry" | wc -l)" -eq 1 ] || fail 'Ambiguous target account'
            IFS=: read -r name password uid gid gecos home shell <<SSH_CERT_ACCOUNT
            $entry
            SSH_CERT_ACCOUNT
            [ -n "$home" ] && [ -d "$home" ] || fail 'Target home is missing'
            [ "$(readlink -f -- "$home")" = "$home" ] || fail 'Symlinked home path requires manual review'
            me=$(id -u)
            [ "$me" = 0 ] || [ "$me" = "$uid" ] || fail 'Insufficient permissions for target account'
            dir="$home/.ssh"
            [ ! -L "$dir" ] || fail 'Refusing symlinked .ssh'
            if [ ! -e "$dir" ]; then
                mkdir -- "$dir"
                if [ "$me" = 0 ]; then chown "$uid:$gid" "$dir"; fi
            fi
            [ -d "$dir" ] && [ "$(stat -c %u "$dir")" = "$uid" ] || fail 'Unsafe .ssh ownership'
            mode=$(stat -c %a "$dir")
            [ $((0$mode & 0022)) -eq 0 ] || fail '.ssh is group/world writable'
            lock="$dir/.ssh-cert.lock"
            mkdir -- "$lock" || fail 'Another update is in progress; inspect .ssh-cert.lock if an earlier session was interrupted'
            before=''
            after=''
            cleanup() { [ -z "$before" ] || rm -f -- "$before"; [ -z "$after" ] || rm -f -- "$after"; rmdir -- "$lock"; }
            trap cleanup EXIT
            trap 'exit 130' INT TERM HUP
            file="$dir/authorized_keys"
            [ ! -L "$file" ] || fail 'Refusing symlinked authorized_keys'
            existed=0
            before=$(mktemp "$dir/.ssh-cert-before.XXXXXXXX")
            after=$(mktemp "$dir/.ssh-cert-after.XXXXXXXX")
            if [ -e "$file" ]; then
                [ -f "$file" ] && [ "$(stat -c %u "$file")" = "$uid" ] || fail 'Unsafe authorized_keys ownership'
                [ "$(stat -c %h "$file")" = 1 ] || fail 'Refusing hard-linked authorized_keys'
                mode=$(stat -c %a "$file")
                [ $((0$mode & 0022)) -eq 0 ] || fail 'authorized_keys is group/world writable'
                cp -- "$file" "$before"
                existed=1
            fi
            awk -v type={{Quote(identity[0])}} -v blob={{Quote(identity[1])}} -v revoke={{(revoke ? "1" : "0")}} -v line={{Quote(remote.PublicKey)}} '
            function matches(s,    i,c,q,e,n,t) {
                if (s ~ /^[ \t]*#/) return 0;
                n=1; q=0; e=0;
                for(i=1;i<=length(s);i++) {
                    c=substr(s,i,1);
                    if(e) {t[n]=t[n] c; e=0; continue}
                    if(c=="\\") {t[n]=t[n] c; e=1; continue}
                    if(c=="\"") {q=!q; t[n]=t[n] c; continue}
                    if(c ~ /[ \t]/ && !q) {if(length(t[n])) n++; if(n>3) break; continue}
                    t[n]=t[n] c
                }
                return (t[1]==type && t[2]==blob) || (t[2]==type && t[3]==blob)
            }
            { hit=matches($0); if(hit) found=1; if(!revoke || !hit) print }
            END {if(!revoke && !found) print line}
            ' "$before" > "$after"
            [ ! -L "$file" ] || fail 'authorized_keys changed to a symlink'
            if [ "$existed" = 1 ]; then
                cmp -s -- "$file" "$before" || fail 'authorized_keys changed concurrently'
            else
                [ ! -e "$file" ] || fail 'authorized_keys appeared concurrently'
            fi
            chmod 700 "$dir"
            chmod 600 "$after"
            if [ "$me" = 0 ]; then chown "$uid:$gid" "$after"; fi
            mv -f -- "$after" "$file"
            after=''
            """.ReplaceLineEndings("\n");
    }
}
