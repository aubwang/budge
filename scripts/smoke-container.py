#!/usr/bin/env python3
"""Disposable clean-install check; only synthetic inputs, no provider traffic."""
import http.cookiejar
import json
import os
import pathlib
import pty
import re
import select
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = ROOT / "bin/budge-linux-amd64"
UNLOCK = "synthetic-container-unlock"
PASSWORD = "synthetic-container-owner"
LOCAL_PASS = "synthetic-container-device"

def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)

def main():
    tag = uuid.uuid4().hex[:10]
    name, volume = "budge-smoke-" + tag, "budge-smoke-data-" + tag
    owner_port, device_port, local_port = port(), port(), port()
    master, slave = pty.openpty()
    process = connector = None
    transcript = bytearray()
    try:
        args = ["docker", "run", "--rm", "-it", "--name", name, "--init", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "-p", f"127.0.0.1:{owner_port}:8080", "-p", f"127.0.0.1:{device_port}:8443", "-v", volume + ":/data", "budge-fresh:local", "server", "--container", "--db", "/data/budge.db", "--owner-listen", "0.0.0.0:8080", "--owner-host", f"127.0.0.1:{owner_port}", "--device-listen", "0.0.0.0:8443", "--url", f"https://127.0.0.1:{device_port}"]
        process = subprocess.Popen(args, stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        def prompt(expected):
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if expected.encode() in transcript:
                    return
                if process.poll() is not None:
                    raise RuntimeError("container exited before setup completed")
                if select.select([master], [], [], 0.1)[0]:
                    transcript.extend(os.read(master, 65536))
            raise RuntimeError("container setup prompt timed out")
        prompt("Server unlock secret:")
        os.write(master, (UNLOCK + "\n").encode())
        prompt("Initial owner password:")
        os.write(master, (PASSWORD + "\n").encode())
        prompt("Owner UI:")
        inspection = json.loads(run("docker", "inspect", name))[0]
        assert inspection["Config"]["User"].split(":")[0] == "65532"
        assert all(binding["HostIp"] == "127.0.0.1" for bindings in inspection["HostConfig"]["PortBindings"].values() for binding in bindings)
        assert inspection["HostConfig"]["ReadonlyRootfs"]
        # Probe this host's non-loopback IPv4 addresses without contacting another host.
        for address in run("hostname", "-I").split():
            if ":" in address or address.startswith("127."):
                continue
            with socket.socket() as probe:
                probe.settimeout(0.5)
                assert probe.connect_ex((address, owner_port)) != 0, "owner port exposed on a non-loopback host address"
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        base = f"http://127.0.0.1:{owner_port}"
        html = opener.open(base).read().decode()
        csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
        def post(path, data):
            return opener.open(base + path, urllib.parse.urlencode({**data, "csrf": csrf}).encode()).read().decode()
        html = post("/login", {"password": PASSWORD})
        csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
        html = post("/invite", {"label": "Synthetic container device"})
        invitation = re.search(r'<textarea[^>]*>([^<]+)</textarea>', html).group(1)
        with tempfile.TemporaryDirectory(prefix="budge-release-") as directory:
            identity = pathlib.Path(directory) / "device.identity"
            invitation_r, invitation_w = os.pipe()
            pass_r, pass_w = os.pipe()
            os.write(invitation_w, (invitation + "\n").encode()); os.close(invitation_w)
            os.write(pass_w, (LOCAL_PASS + "\n").encode()); os.close(pass_w)
            try:
                enrolled = subprocess.run([str(BINARY), "enroll", "--identity", str(identity), "--invitation-fd", str(invitation_r), "--passphrase-fd", str(pass_r)], pass_fds=(invitation_r, pass_r), capture_output=True, timeout=20)
                assert enrolled.returncode == 0, "packaged client enrollment failed"
            finally:
                os.close(invitation_r); os.close(pass_r)
            assert b"PRIVATE KEY" not in identity.read_bytes()
            pass_r, pass_w = os.pipe()
            os.write(pass_w, (LOCAL_PASS + "\n").encode()); os.close(pass_w)
            connector = subprocess.Popen([str(BINARY), "connect", "--identity", str(identity), "--listen", f"127.0.0.1:{local_port}", "--socket", str(pathlib.Path(directory) / "connect.sock"), "--passphrase-fd", str(pass_r)], pass_fds=(pass_r,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            os.close(pass_r)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not (pathlib.Path(directory) / "connect.sock").exists():
                if connector.poll() is not None:
                    raise RuntimeError("connector exited during setup")
                time.sleep(0.05)
            try:
                urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{local_port}/s/mock/write", data=b"synthetic"))
                raise AssertionError("identity unexpectedly granted a permission")
            except urllib.error.HTTPError as e:
                assert e.code == 403, "enrolled connector was not authenticated and default-denied"
            assert (pathlib.Path(directory) / "connect.sock").stat().st_mode & 0o777 == 0o600
            logs = run("docker", "logs", name)
            for secret in [UNLOCK, PASSWORD, LOCAL_PASS, invitation]:
                assert secret not in logs and secret.encode() not in transcript, "setup material leaked into logs"
            connector.terminate(); connector.communicate(timeout=10); connector = None
        print("PASS: nonroot read-only container; loopback publication; hidden setup inputs; owner login; packaged Linux enrollment; encrypted identity; private socket; authenticated default-deny; no setup secrets in logs.")
    finally:
        if connector is not None:
            connector.terminate(); connector.communicate(timeout=10)
        subprocess.run(["docker", "stop", "--time", "2", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if process is not None:
            process.wait(timeout=10)
        os.close(master)
        subprocess.run(["docker", "volume", "rm", volume], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if __name__ == "__main__":
    main()
