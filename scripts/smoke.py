#!/usr/bin/env python3
"""Exercise the real Unix-socket daemon using the simulation-only backend."""

import argparse
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, socket_path):
        super().__init__("localhost", timeout=3)
        self.socket_path = str(socket_path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", required=True)
    parser.add_argument("--cli", required=True)
    parser.add_argument("--work-dir")
    parser.add_argument("--cycles", type=int, default=50)
    args = parser.parse_args()
    daemon, cli = str(Path(args.daemon).resolve()), str(Path(args.cli).resolve())
    if args.cycles < 1:
        parser.error("--cycles must be positive")
    checks = []
    with tempfile.TemporaryDirectory(prefix="sbx-", dir=args.work_dir) as temp:
        root = Path(temp)
        state = root / "state"
        sock = state / "api.sock"
        process = None
        with (root / "daemon.log").open("ab", buffering=0) as log:
            def call(method, path, body=None, expected=200):
                conn = UnixHTTP(sock)
                try:
                    conn.request(method, path, None if body is None else json.dumps(body), {"Content-Type": "application/json"})
                    response = conn.getresponse()
                    raw = response.read()
                    assert response.status == expected, (response.status, raw.decode())
                    return json.loads(raw)
                finally:
                    conn.close()

            def wait(predicate, description):
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    value = predicate()
                    if value:
                        return value
                    time.sleep(0.01)
                raise AssertionError(f"timed out: {description}")

            def start():
                proc = subprocess.Popen([daemon, "-backend", "mock", "-insecure-mock", "-state-dir", str(state)], stdout=log, stderr=log)
                try:
                    def ready():
                        if proc.poll() is not None:
                            raise AssertionError((root / "daemon.log").read_text())
                        try:
                            return call("GET", "/healthz")
                        except (OSError, http.client.HTTPException):
                            return None
                    health = wait(ready, "daemon startup")
                    assert health["backend"] == "mock" and health["isolation"] is False
                    return proc
                except BaseException:
                    proc.kill()
                    proc.wait()
                    raise

            def create():
                return call("POST", "/v1/sandboxes", {}, expected=201)

            def run_command(instance, argv, timeout_ms=5000):
                base = f'/v1/sandboxes/{instance["id"]}'
                job = call("POST", base + "/exec", {"generation": instance["generation"], "argv": argv, "timeout_ms": timeout_ms}, expected=202)
                def finished():
                    current = call("GET", base + "/executions/" + job["id"])
                    return current if current["status"] != "RUNNING" else None
                return wait(finished, "execution")

            def destroy(instance):
                base = f'/v1/sandboxes/{instance["id"]}'
                call("DELETE", base, {"generation": instance["generation"]}, expected=202)
                wait(lambda: call("GET", base)["state"] == "DESTROYED", "reclamation")

            try:
                process = start()
                checks.append("Unix-socket health explicitly reports mock / no isolation")

                second = subprocess.run([daemon, "-backend", "mock", "-insecure-mock", "-state-dir", str(state)], capture_output=True, text=True, timeout=5)
                assert second.returncode != 0 and "already locked" in second.stderr
                checks.append("second controller cannot acquire the same state directory")

                a, b = create(), create()
                assert run_command(a, ["write", "note", "private-a"])["output"]["exit_code"] == 0
                assert run_command(a, ["read", "note"])["output"]["stdout"] == "private-a"
                assert run_command(b, ["read", "note"])["status"] == "FAILED"
                assert run_command(a, ["/bin/sh", "-c", "echo should-not-run"])["status"] == "FAILED"
                call("POST", f'/v1/sandboxes/{a["id"]}/exec', {"generation": "stale", "argv": ["echo"]}, expected=409)
                checks.append("workspace separation, stale-generation fence, and host-shell rejection")

                base_a = f'/v1/sandboxes/{a["id"]}'
                job = call("POST", base_a + "/exec", {"generation": a["generation"], "argv": ["sleep", "2s"]}, expected=202)
                stopped = call("POST", base_a + "/stop", {"generation": a["generation"]})
                assert stopped["state"] == "STOPPED"
                assert call("GET", base_a + "/executions/" + job["id"])["status"] == "CANCELLED"
                call("POST", base_a + "/exec", {"generation": a["generation"], "argv": ["echo"]}, expected=409)
                destroy(a)
                destroy(a)
                destroy(b)
                checks.append("stop drains execution; destroy is idempotent and separately observable")

                c = create()
                assert run_command(c, ["sleep", "1s"], timeout_ms=20)["status"] == "TIMED_OUT"
                cli_result = subprocess.run([cli, "-socket", str(sock), "exec", "-wait", c["id"], c["generation"], "echo", "from-cli"], capture_output=True, text=True, timeout=5)
                assert cli_result.returncode == 0, cli_result.stderr
                assert json.loads(cli_result.stdout)["output"]["stdout"] == "from-cli\n"
                destroy(c)
                checks.append("execution timeout and sandboxctl end-to-end command")

                orphan = create()
                assert run_command(orphan, ["write", "checkpoint", "must-be-reclaimed"])["status"] == "EXITED"
                process.kill()
                process.wait(timeout=5)
                process = start()
                wait(lambda: call("GET", f'/v1/sandboxes/{orphan["id"]}')["state"] == "DESTROYED", "restart recovery")
                call("POST", f'/v1/sandboxes/{orphan["id"]}/exec', {"generation": orphan["generation"], "argv": ["echo"]}, expected=409)
                checks.append("SIGKILL + restart fences and reclaims the previous generation")

                for n in range(args.cycles):
                    instance = create()
                    result = run_command(instance, ["echo", str(n)])
                    assert result["output"]["stdout"] == f"{n}\n"
                    destroy(instance)
                wait(lambda: call("GET", "/healthz")["stats"]["active"] == 0, "capacity returned")
                assert list((state / "instances").iterdir()) == []
                checks.append(f"{args.cycles} create/execute/destroy cycles leave no private workspaces")

                process.terminate()
                assert process.wait(timeout=10) == 0
                process = None
                assert not sock.exists()
                checks.append("graceful shutdown removes its socket")
            except BaseException:
                print((root / "daemon.log").read_text(), file=__import__("sys").stderr)
                raise
            finally:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)

    print(json.dumps({"backend": "mock", "microvm_benchmark": False, "cycles": args.cycles, "checks": checks}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
