using System.Security.AccessControl;
using System.Security.Principal;

namespace SshCert.Storage;

public static class PrivateFiles
{
    public static void RejectLink(string path)
    {
        for (var current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
            if ((File.Exists(current) || System.IO.Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new IOException($"Refusing symbolic link/reparse point: {current}");
    }

    public static void Directory(string path)
    {
        RejectLink(path);
        if (OperatingSystem.IsWindows())
        {
            var security = new DirectorySecurity();
            var sid = WindowsIdentity.GetCurrent().User ?? throw new IOException("Cannot determine current user.");
            security.SetOwner(sid);
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(path).Create(security);
            new DirectoryInfo(path).SetAccessControl(security);
        }
        else
        {
            System.IO.Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    public static void WriteNew(string path, byte[] data)
    {
        RejectLink(path);
        using var stream = Create(path);
        stream.Write(data);
        stream.Flush(true);
    }

    public static FileStream Create(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            var security = new FileSecurity();
            var sid = WindowsIdentity.GetCurrent().User ?? throw new IOException("Cannot determine current user.");
            security.SetOwner(sid);
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
            return new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.FullControl,
                FileShare.None, 4096, FileOptions.None, security);
        }
        return new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.CreateNew, Access = FileAccess.ReadWrite, Share = FileShare.None,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
        });
    }
}
