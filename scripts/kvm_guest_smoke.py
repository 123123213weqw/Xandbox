#!/usr/bin/env python3
"""Experimental jailed KVM guest-agent acceptance, NOT sandboxd integration.

Requires an isolated Linux/KVM test node with root and cgroup v2. Guest
commands travel only over vsock; they are never passed to a host shell.
"""

import argparse
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import secrets
import select
import signal
import shutil
import socket
import subprocess
import tempfile
import time


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=3)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main():
    def interrupted(signum, frame):
        raise SystemExit("KVM acceptance interrupted")

    for signum in (signal.SIGHUP, signal.SIGTERM):
        signal.signal(signum, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("firecracker", "jailer", "kernel", "initrd", "guestctl", "agent", "report", "log-dir"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or os.uname().sysname != "Linux":
        parser.error("root on an isolated Linux/KVM test node is required")
    files = {name: Path(getattr(args, name)).resolve() for name in ("firecracker", "jailer", "kernel", "initrd", "guestctl", "agent")}
    report_path, logs = Path(args.report).resolve(), Path(args.log_dir).resolve()
    if report_path.exists():
        parser.error("report path already exists")
    logs.mkdir(parents=True, exist_ok=True, mode=0o700)
    expected_kernel = "1e86630c63d61fd37b5a4d23cb66056286bdcc00ebca217c7ef95689575a4bb3"
    if digest(files["kernel"]) != expected_kernel:
        parser.error("test kernel checksum mismatch")
    refused = subprocess.run([str(files["agent"])], capture_output=True, timeout=5)
    assert refused.returncode != 0 and b"not an Xandbox guest image" in refused.stderr
    lock = json.loads((Path(__file__).parent / "kvm_assets.json").read_text())
    for name, expected in lock["release_binary_sha256"].items():
        assert digest(files[name]) == expected, "release binary checksum mismatch"
    version = subprocess.check_output([str(files["firecracker"]), "--version"], text=True, timeout=5).splitlines()[0]
    assert "v1.17.0" in version
    result = {
        "validated_on": datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
        "validated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "test": "experimental_jailed_guest_agent",
        "production_ready": False, "sandboxd_driver_integrated": False,
        "host_kernel": os.uname().release, "architecture": os.uname().machine,
        "firecracker": version, "guest_memory_mib": 512, "vcpus": 2,
        "workspace_bytes": 128 * 1024 * 1024, "guest_network_interfaces": 0,
        "artifacts_sha256": {name: digest(path) for name, path in files.items()},
        "agent_build": json.loads(subprocess.check_output([str(files["agent"]), "--build-info"], timeout=5)),
        "checks": ["guest agent refuses direct host initialization"], "samples": [],
    }
    boot_ids = []
    for iteration in range(2):
        identity, generation = secrets.token_hex(16), secrets.token_hex(16)
        uid = 300000 + secrets.randbelow(50000)
        try:
            pwd.getpwuid(uid)
            raise RuntimeError("test UID is already assigned")
        except KeyError:
            pass
        parent = Path("/sys/fs/cgroup") / ("xandbox-proof-" + identity)
        allocation_started = time.perf_counter()
        parent.mkdir()
        group = parent / identity
        process = None
        vm_pidfd = None
        with tempfile.TemporaryDirectory(prefix="xbvm-", dir="/tmp") as temp, (logs / f"vm-{iteration}.log").open("xb") as log:
            base = Path(temp)
            root = base / "j" / "firecracker" / identity / "root"
            root.mkdir(parents=True)
            for source, name in ((files["kernel"], "kernel"), (files["initrd"], "initrd")):
                shutil.copyfile(source, root / name)
                (root / name).chmod(0o444)
            disk = root / "workspace.ext4"
            with disk.open("xb") as out:
                out.truncate(result["workspace_bytes"])
            subprocess.run(["mkfs.ext4", "-q", "-F", str(disk)], check=True)
            os.chown(disk, uid, uid)

            def api(path, body):
                conn = UnixHTTP(root / "api.sock")
                try:
                    conn.request("PUT", path, json.dumps(body), {"Content-Type": "application/json"})
                    response = conn.getresponse()
                    data = response.read()
                    assert response.status == 204, (response.status, data.decode())
                finally:
                    conn.close()

            def guest(operation, *argv, timeout="5s", output_bytes=16384, expected_status="EXITED"):
                command = [str(files["guestctl"]), "-vsock-socket", str(root / "v.sock"), "-id", identity,
                           "-generation", generation, "-timeout", timeout, "-output-bytes", str(output_bytes), operation, *argv]
                call = subprocess.run(command, capture_output=True, text=True, timeout=12)
                if not call.stdout:
                    raise RuntimeError("guest control unavailable: " + call.stderr)
                response = json.loads(call.stdout)
                assert response["status"] == expected_status, response
                if expected_status in ("READY", "EXITED"):
                    assert call.returncode == 0, call.stderr
                return response

            try:
                started = time.perf_counter()
                process = subprocess.Popen([
                    "unshare", "--net", str(files["jailer"]), "--id", identity, "--exec-file", str(files["firecracker"]),
                    "--uid", str(uid), "--gid", str(uid), "--chroot-base-dir", str(base / "j"),
                    "--cgroup-version", "2", "--parent-cgroup", parent.name,
                    "--cgroup", "memory.max=805306368", "--cgroup", "memory.swap.max=0",
                    "--cgroup", "pids.max=64", "--cgroup", "cpu.max=200000 100000",
                    "--resource-limit", "no-file=256", "--resource-limit", "fsize=134217728",
                    "--", "--api-sock", "/api.sock",
                ], stdout=log, stderr=log, start_new_session=True,
                    env={"PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"), "XANDBOX_TEST_CANARY": secrets.token_hex(24)})
                vm_pidfd = os.pidfd_open(process.pid)
                deadline = time.monotonic() + 5
                while not (root / "api.sock").exists():
                    assert process.poll() is None, "jailer exited; inspect private VM log"
                    assert time.monotonic() < deadline, "API socket startup timed out"
                    time.sleep(0.01)
                api("/machine-config", {"vcpu_count": 2, "mem_size_mib": 512, "smt": False})
                api("/boot-source", {"kernel_image_path": "/kernel", "initrd_path": "/initrd",
                                     "boot_args": f"console=ttyS0 reboot=k panic=1 pci=off rdinit=/sbin/init xandbox.guest=1 xandbox.id={identity} xandbox.generation={generation}"})
                api("/drives/workspace", {"drive_id": "workspace", "path_on_host": "/workspace.ext4", "is_root_device": False, "is_read_only": False})
                api("/vsock", {"guest_cid": 3, "uds_path": "/v.sock"})
                api("/actions", {"action_type": "InstanceStart"})
                deadline = time.monotonic() + 15
                while True:
                    try:
                        health = guest("health", expected_status="READY")
                        break
                    except RuntimeError:
                        assert process.poll() is None, "VM exited; inspect private VM log"
                        assert time.monotonic() < deadline, "guest agent startup timed out"
                        time.sleep(0.1)
                create_ms = (time.perf_counter() - started) * 1000
                staging_ms = (started - allocation_started) * 1000
                boot_ids.append(health["boot_id"])
                status = Path(f"/proc/{process.pid}/status").read_text()
                assert f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}" in status
                assert "Seccomp:\t2\n" in status
                assert os.readlink(f"/proc/{process.pid}/ns/net") != os.readlink("/proc/self/ns/net")
                links = json.loads(subprocess.check_output(["nsenter", "--target", str(process.pid), "--net", "ip", "-j", "link"], timeout=3))
                assert [link["ifname"] for link in links] == ["lo"]
                assert (group / "memory.max").read_text().strip() == "805306368"
                assert (group / "pids.max").read_text().strip() == "64"
                assert (group / "cpu.max").read_text().strip() == "200000 100000"
                fds = Path(f"/proc/{process.pid}/fd")
                has_kvm = False
                for fd in fds.iterdir():
                    try:
                        has_kvm |= "kvm-vm" in os.readlink(fd)
                    except FileNotFoundError:
                        pass
                assert has_kvm, "no live KVM VM descriptor"
                assert guest("exec", "id", "-u")["output"]["stdout"].strip() == "65534"
                assert guest("exec", "id", "-g")["output"]["stdout"].strip() == "65534"
                assert guest("exec", "id", "-G")["output"]["stdout"].strip() == "65534"
                assert guest("exec", "sh", "-c", "grep '^NoNewPrivs:' /proc/self/status")["output"]["stdout"].strip() == "NoNewPrivs:\t1"
                assert guest("exec", "pwd")["output"]["stdout"].strip() == "/workspace"
                assert guest("exec", "sh", "-c", 'test -z "$XANDBOX_TEST_CANARY"')["output"]["exit_code"] == 0
                assert guest("exec", "ls", "/sys/class/net")["output"]["stdout"].strip() == "lo"
                rejected = subprocess.run([str(files["guestctl"]), "-vsock-socket", str(root / "v.sock"),
                                           "-id", identity, "-generation", "0" * 32 if generation != "0" * 32 else "1" * 32,
                                           "health"], capture_output=True, timeout=5)
                assert rejected.returncode != 0
                guest("health", expected_status="READY")
                assert guest("exec", "sh", "-c", "test ! -e note.txt")["output"]["exit_code"] == 0
                assert guest("exec", "sh", "-c", "printf guest-private > note.txt; cat note.txt")["output"]["stdout"] == "guest-private"
                assert guest("exec", "cat", "note.txt")["output"]["stdout"] == "guest-private"
                bounded = guest("exec", "sh", "-c", "yes x | head -c 65536", output_bytes=1024)
                assert bounded["output"]["truncated"] and len(bounded["output"]["stdout"].encode()) <= 1024
                escaped = "\x01" * (32768 - len("/bin/busybox") - len("printf") - len("%s"))
                boundary = guest("exec", "/bin/busybox", "printf", "%s", escaped, output_bytes=1024)
                assert boundary["output"]["stdout"] == "\x01" * 1024 and boundary["output"]["truncated"]
                guest("exec", "sh", "-c", "setsid sh -c 'sleep 1; echo escaped > /workspace/escaped' >/dev/null 2>&1 & sleep 10", timeout="100ms", expected_status="TIMED_OUT")
                time.sleep(1.3)
                assert guest("exec", "sh", "-c", "test ! -e escaped")["output"]["exit_code"] == 0
                disconnected = subprocess.Popen([
                    str(files["guestctl"]), "-vsock-socket", str(root / "v.sock"), "-id", identity,
                    "-generation", generation, "-timeout", "10s", "exec", "sh", "-c",
                    "touch disconnect-started; sleep 1; echo leaked > disconnect-leak; sleep 10",
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    deadline = time.monotonic() + 3
                    while guest("exec", "sh", "-c", "test -e disconnect-started")["output"]["exit_code"] != 0:
                        assert time.monotonic() < deadline, "disconnect test never started"
                        time.sleep(0.01)
                finally:
                    if disconnected.poll() is None:
                        disconnected.kill()
                    disconnected.wait(timeout=5)
                time.sleep(1.3)
                assert guest("exec", "sh", "-c", "test ! -e disconnect-leak")["output"]["exit_code"] == 0
                assert guest("health", expected_status="READY")["active_execution_groups"] == 0
                stopped = time.perf_counter()
                (group / "cgroup.kill").write_text("1")
                # Popen.wait(timeout) uses exponential polling and can add a
                # 32/64 ms measurement floor. Observe exit through pidfd.
                assert select.select([vm_pidfd], [], [], 5)[0], "VMM failed to exit"
                process.wait()
                os.close(vm_pidfd)
                vm_pidfd = None
                stop_ms = (time.perf_counter() - stopped) * 1000
                assert "populated 0\n" in (group / "cgroup.events").read_text()
                reclaimed = time.perf_counter()
                shutil.rmtree(base / "j")
                group.rmdir()
                parent.rmdir()
                result["samples"].append({"private_staging_ms": round(staging_ms, 3), "jailer_spawn_to_guest_ready_ms": round(create_ms, 3), "staging_and_spawn_to_guest_ready_ms": round(staging_ms + create_ms, 3), "cgroup_kill_to_process_exit_ms": round(stop_ms, 3), "private_files_and_cgroup_removal_ms": round((time.perf_counter() - reclaimed) * 1000, 3)})
            finally:
                if group.exists():
                    (group / "cgroup.kill").write_text("1")
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                if group.exists():
                    group.rmdir()
                if parent.exists():
                    parent.rmdir()
                if vm_pidfd is not None:
                    os.close(vm_pidfd)
    assert len(set(boot_ids)) == 2
    result["checks"] += ["two distinct KVM guest boots with fresh private disks", "live KVM VM descriptor verified", "guest commands run as UID/GID 65534 without supplementary groups and with no_new_privs", "stale generation rejected while current guest remains healthy", "persistent workspace within one guest", "total output bound", "timeout kills a setsid-escaped process tree", "host client death cancels execution; kernel execution cgroup count returns to zero", "guest exposes only loopback network interface", "VMM has a separate loopback-only host network namespace", "host environment canary absent in guest", "jailer drops VMM UID and default seccomp remains active", "host memory/CPU/pids cgroup settings verified", "VMM exit confirmed before private resource removal"]
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("x") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
