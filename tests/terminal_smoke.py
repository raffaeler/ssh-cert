import codecs
import errno
import fcntl
import json
import os
import pathlib
import pty
import re
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
import xml.etree.ElementTree as ET

command = [os.path.abspath(sys.argv[1]), *sys.argv[2:]]
project = pathlib.Path(__file__).resolve().parent.parent / "src" / "ssh-cert" / "ssh-cert.csproj"
banner = "ssh-cert " + ET.parse(project).findtext("./PropertyGroup/Version")
home = tempfile.mkdtemp(prefix="ssh-cert-terminal-")
startup_groups = pathlib.Path(home) / ".ssh" / "ssh-cert" / "groups"
startup_groups.mkdir(parents=True, mode=0o700)
startup_group = {"schemaVersion": 1, "id": "11111111-1111-1111-1111-111111111111",
                 "name": "Startup", "connections": []}
(startup_groups / (startup_group["id"] + ".json")).write_text(json.dumps(startup_group))
height, width = 10, 60
row, col = height - 1, 0
screen = [[" "] * width for _ in range(height)]
scrolls = 0
pending = ""
decoder = codecs.getincrementaldecoder("utf-8")("replace")
pid, fd = pty.fork()
if pid == 0:
    os.environ["HOME"] = home
    os.environ["TERM"] = "xterm-256color"
    os.execv(command[0], command)
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))

def newline():
    global row, screen, scrolls
    if row == height - 1:
        screen = screen[1:] + [[" "] * width]
        scrolls += 1
    else:
        row += 1

def consume(text):
    global pending, row, col
    pending += text
    while pending:
        if pending[0] == "\x1b":
            match = re.match(r"\x1b\[([0-9;?]*)([@-~])", pending)
            if not match:
                if len(pending) < 3 or pending.startswith("\x1b["):
                    return
                pending = pending[2:]
                continue
            params, command = match.groups()
            pending = pending[match.end():]
            values = [int(v or "1") for v in params.lstrip("?").split(";")]
            if command == "n" and params == "6":
                os.write(fd, ("\x1b[%d;%dR" % (row + 1, col + 1)).encode())
            elif command in "Hf":
                row = values[0] - 1
                col = (values[1] if len(values) > 1 else 1) - 1
                assert 0 <= row < height and 0 <= col < width, (row, col, height, width)
            elif command == "A": row = max(0, row - values[0])
            elif command == "B": row = min(height - 1, row + values[0])
            elif command == "C": col = min(width - 1, col + values[0])
            elif command == "D": col = max(0, col - values[0])
            elif command == "G": col = values[0] - 1
            continue
        c, pending = pending[0], pending[1:]
        if c == "\r": col = 0
        elif c == "\n": newline()
        elif c == "\b": col = max(0, col - 1)
        elif ord(c) >= 32:
            if col >= width:
                col = 0
                newline()
            screen[row][col] = c
            col += 1

def pump(seconds=0.5):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        readable, _, _ = select.select([fd], [], [], 0.03)
        if not readable: continue
        try:
            data = os.read(fd, 65536)
            if not data: break
            consume(decoder.decode(data))
        except OSError as ex:
            if ex.errno != errno.EIO: raise
            break

def text():
    return "\n".join("".join(line) for line in screen)

def send(keys):
    os.write(fd, keys.encode())
    pump()

def expect(predicate):
    end = time.monotonic() + 15
    while not predicate():
        if time.monotonic() >= end:
            raise AssertionError(text())
        pump(0.1)

def import_connection(confirm):
    send("/remote\r")
    expect(lambda: "Remote connections" in text())
    send("Import\r")
    expect(lambda: "Recognized legacy entries" in text())
    send("fixture -\r")
    expect(lambda: "Also adopt matching block" in text())
    send("\r")
    expect(lambda: "Legacy server type" in text())
    send("\r")
    expect(lambda: "Connection details" in text())
    send("\r")
    expect(lambda: "Import fixture" in text() and "Enter: confirm" in text())
    assert "[X] Confirm" not in text() and "[ ] Confirm" not in text(), text()
    send("\r" if confirm else "\x1b")
    expect(lambda: ("Connection imported" if confirm else "Import canceled") in text())

def saved_group(name):
    groups = pathlib.Path(home) / ".ssh" / "ssh-cert" / "groups"
    matches = [group for path in groups.glob("*.json")
               if (group := json.loads(path.read_text()))["name"] == name]
    assert len(matches) == 1, matches
    return matches[0]

def select_fixture_membership():
    expect(lambda: "Group membership" in text() and "[ ] fixture" in text())
    send(" ")
    expect(lambda: "[X] fixture" in text() and "1 selected" in text())
    send("\r")
    expect(lambda: "Apply this group now" in text())
    send("\x1b")

def pending_menu():
    send("/remote\r")
    expect(lambda: "Remote connections" in text())
    send("Pending\r")
    expect(lambda: "Pending keys /" in text())
    send("\r")
    expect(lambda: "Pending key action" in text())

def cancel_provisioning_and_remove_unused_key():
    send("/remote\r")
    expect(lambda: "Remote connections" in text())
    send("Create\r")
    expect(lambda: "Server type" in text())
    send("MikroTik\r")
    expect(lambda: "Server hostname or IP" in text())
    send("unused.invalid\r")
    expect(lambda: "Existing target username" in text())
    send("fixture\r")
    expect(lambda: "SSH alias" in text())
    send("\r")
    expect(lambda: "Connection details" in text())
    send("Flags\r")
    expect(lambda: "Connection flags" in text())
    assert "[X] Own raw-hostname entry" in text(), text()
    assert "[ ] Enabled" in text(), text()
    send("\x1b[B \r")
    expect(lambda: "Connection details" in text())
    send("Flags\r")
    expect(lambda: "Connection flags" in text())
    assert "[ ] Own raw-hostname entry" in text(), text()
    send("\r")
    expect(lambda: "Connection details" in text())
    send("\r")
    expect(lambda: "Private key" in text())
    send("\r")
    expect(lambda: "Key algorithm" in text())
    send("\r")
    expect(lambda: "Key protection" in text())
    send("\r")
    expect(lambda: "Provision unused-invalid" in text())
    send("\x1b")
    expect(lambda: "ssh-cert >" in text())
    state_path = pathlib.Path(home) / ".ssh" / "ssh-cert" / "connections.json"
    state = json.loads(state_path.read_text())
    pending = state["pendingCleanup"]
    assert len(pending) == 1 and pending[0]["provisioningNotStarted"], pending
    key_path = pathlib.Path(pending[0]["keyPath"])
    assert key_path.exists() and pathlib.Path(str(key_path) + ".pub").exists()
    pending_menu()
    send("Retry\r")
    expect(lambda: "Recovered connection alias" in text())
    send("\r")
    expect(lambda: "Retry provisioning" in text())
    send("\r")
    expect(lambda: "Bootstrap login user" in text())
    send("\r")
    expect(lambda: "Bootstrap authentication" in text())
    assert "Pending key:" not in text(), text()
    send("\r")
    expect(lambda: "Bootstrap password" in text())
    send("\x1b")
    assert json.loads(state_path.read_text())["pendingCleanup"] == pending
    pending_menu()
    send("unused\r")
    expect(lambda: "Delete this unused app-owned" in text())
    send("\x1b")
    assert key_path.exists() and len(json.loads(state_path.read_text())["pendingCleanup"]) == 1
    pending_menu()
    send("unused\r")
    expect(lambda: "Delete this unused app-owned" in text())
    send("\r")
    expect(lambda: "Pending record and app-owned" in text())
    assert json.loads(state_path.read_text())["pendingCleanup"] == []
    assert not key_path.exists() and not pathlib.Path(str(key_path) + ".pub").exists()
    assert json.loads(state_path.read_text())["connections"] == state["connections"]

try:
    pump(1)
    expect(lambda: "ssh-cert >" in text())
    assert next(line.strip() for line in text().splitlines() if line.strip()) == banner, text()
    assert "Active group: Startup" in text(), text()
    assert not (pathlib.Path(home) / ".ssh" / "ssh-cert" / "connections.json").exists()
    env = dict(os.environ, HOME=home)
    version = subprocess.run(command + ["--version"], env=env, capture_output=True, text=True, timeout=30)
    assert version.returncode == 0 and version.stdout.splitlines() == [banner], version
    help_output = subprocess.run(command + ["--help"], env=env, capture_output=True, text=True, timeout=30)
    assert help_output.returncode == 0 and help_output.stdout.splitlines()[0] == banner, help_output
    ssh = pathlib.Path(home) / ".ssh"
    ssh.mkdir(mode=0o700, exist_ok=True)
    key = ssh / "id_ed25519_fixture"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "fixture|ai|target",
                    "-f", str(key)], check=True, capture_output=True, timeout=30)
    (ssh / "config").write_text("".join(
        f'Host {alias}\n    HostName fixture.invalid\n    User fixture\n    Port 22\n'
        f'    IdentitiesOnly yes\n    IdentityFile "{key}"\n'
        for alias in ("fixture", "fixture.invalid")))
    send("/")
    expect(lambda: "/remote" in text() and "/group" in text() and "/exit" in text())
    assert scrolls > 0
    send("\x1b[B\r")
    expect(lambda: "Groups" in text() and "Create" in text())
    send("\r")
    send("Empty\r")
    expect(lambda: "Group membership" in text())
    assert "No saved connections" in text(), text()
    send("\r")
    expect(lambda: "Apply this group now" in text())
    send("\x1b")
    groups = os.path.join(home, ".ssh", "ssh-cert", "groups")
    assert len(os.listdir(groups)) == 2
    group = saved_group("Empty")
    assert group["name"] == "Empty" and group["connections"] == []
    applied = subprocess.run(command + ["--group", "Empty"], env=env, capture_output=True, text=True, timeout=30)
    assert applied.returncode == 0, applied.stderr
    assert applied.stdout.splitlines()[0] == banner, applied.stdout
    unknown = subprocess.run(command + ["--group", "Missing"], env=env, capture_output=True, text=True, timeout=30)
    assert unknown.returncode == 2, unknown.stderr
    assert unknown.stdout.splitlines() == [banner], unknown.stdout

    import_connection(False)
    state_path = ssh / "ssh-cert" / "connections.json"
    assert json.loads(state_path.read_text())["connections"] == []
    import_connection(True)
    connections = json.loads(state_path.read_text())["connections"]
    assert len(connections) == 1 and connections[0]["alias"] == "fixture", connections
    connection_id = connections[0]["id"]

    send("/group\r")
    expect(lambda: "Groups (1 saved connections)" in text())
    send("Delete\r")
    expect(lambda: "Select group" in text())
    send("Empty\r")
    expect(lambda: "Delete group 'Empty'?" in text())
    send("\x1b")
    assert saved_group("Empty")["connections"] == []

    send("/group\r")
    expect(lambda: "Groups (1 saved connections)" in text())
    send("\r")
    send("Selected\r")
    select_fixture_membership()
    assert saved_group("Selected")["connections"] == [connection_id]

    send("/group\r")
    expect(lambda: "Groups (1 saved connections)" in text())
    send("Edit\r")
    expect(lambda: "Select group" in text())
    send("Empty\r")
    expect(lambda: "Group name" in text())
    send("\r")
    select_fixture_membership()
    assert saved_group("Empty")["connections"] == [connection_id]

    applied = subprocess.run(command + ["--group", "Selected"], env=env, capture_output=True, text=True, timeout=30)
    assert applied.returncode == 0, applied.stderr
    assert "Match originalhost fixture\n" in (ssh / "config").read_text()
    assert "Match originalhost fixture.invalid\n" in (ssh / "config").read_text()
    for name in ("fixture", "FIXTURE", "FiXtUrE", "fixture.invalid", "FIXTURE.INVALID", "FiXtUrE.InVaLiD"):
        effective = subprocess.run(["ssh", "-G", "-F", str(ssh / "config"), name],
                                   env=env, capture_output=True, text=True, timeout=30)
        assert effective.returncode == 0, effective.stderr
        settings = effective.stdout.splitlines()
        assert "user fixture" in settings and "hostname fixture.invalid" in settings, effective.stdout
        assert [line for line in settings if line.startswith("identityfile ")] == [f"identityfile {key}"], effective.stdout
    cancel_provisioning_and_remove_unused_key()
    send("/")
    height, width = 6, 35
    row, col = min(row, height - 1), 0
    screen = [[" "] * width for _ in range(height)]
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))
    os.kill(pid, signal.SIGWINCH)
    pump()
    send("\x1b[F")
    expect(lambda: "/exit" in text())
    send("\r")
    end = time.monotonic() + 15
    while True:
        exited, status = os.waitpid(pid, os.WNOHANG)
        if exited: break
        if time.monotonic() >= end: raise AssertionError("Application did not exit:\n" + text())
        pump(0.1)
    pid = None
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    print("PTY: version-first output, Enter/Escape import and deletion, Space-selected groups, case-insensitive SSH aliases/hostnames, retained-key cleanup, apply, resize and exit passed.")
finally:
    if pid is not None:
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
    os.close(fd)
    shutil.rmtree(home)
