#!/usr/bin/env python3
"""Authenticated process tests; all credentials and state are disposable."""

import argparse
import http.client
import json
from pathlib import Path
import subprocess
import tempfile
import time

from smoke import UnixHTTP


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", required=True)
    parser.add_argument("--cli", required=True)
    parser.add_argument("--keygen", required=True)
    args = parser.parse_args()
    daemon, cli, keygen = [str(Path(p).resolve()) for p in (args.daemon, args.cli, args.keygen)]
    checks = []
    with tempfile.TemporaryDirectory(prefix="xba-") as temp:
        root = Path(temp)
        state, config = root / "state", root / "auth.json"
        sock = state / "api.sock"
        tokens, keys = {}, []
        for tenant in ("alpha", "beta"):
            token_file, digest_file = root / f"{tenant}.token", root / f"{tenant}.json"
            command = [keygen, "-tenant", tenant, "-max-instances", "1", "-token-file", str(token_file), "-config-file", str(digest_file)]
            generated = subprocess.run(command, capture_output=True, text=True, timeout=5)
            assert generated.returncode == 0, generated.stderr
            tokens[tenant] = token_file.read_text().strip()
            assert tokens[tenant] not in generated.stdout + generated.stderr + digest_file.read_text()
            assert token_file.stat().st_mode & 0o077 == 0
            assert digest_file.stat().st_mode & 0o077 == 0
            keys.extend(json.loads(digest_file.read_text())["keys"])
            existing = token_file.read_bytes()
            duplicate = subprocess.run(command, capture_output=True, timeout=5)
            assert duplicate.returncode != 0 and token_file.read_bytes() == existing
        config.write_text(json.dumps({"version": 1, "keys": keys}))
        config.chmod(0o600)
        checks.append("keygen creates private files, stores only SHA-256 digests, and refuses overwrite")

        base = [daemon, "-backend", "mock", "-state-dir", str(state)]
        default = subprocess.run(base, capture_output=True, text=True, timeout=5)
        assert default.returncode != 0 and "exactly one" in default.stderr
        config.chmod(0o644)
        public = subprocess.run(base + ["-auth-file", str(config)], capture_output=True, text=True, timeout=5)
        assert public.returncode != 0
        config.chmod(0o600)
        checks.append("daemon fails closed without auth mode and refuses nonprivate configuration")

        process = None
        with (root / "daemon.log").open("ab", buffering=0) as log:
            def call(method, path, body=None, tenant="alpha", key=None, expected=200, headers=None):
                request_headers = {"Content-Type": "application/json"}
                if tenant is not None:
                    request_headers["Authorization"] = "Bearer " + tokens[tenant]
                if key is not None:
                    request_headers["Idempotency-Key"] = key
                request_headers.update(headers or {})
                conn = UnixHTTP(sock)
                try:
                    conn.request(method, path, None if body is None else json.dumps(body), request_headers)
                    response = conn.getresponse()
                    data = response.read()
                    assert response.status == expected, (response.status, data.decode())
                    assert not any(token.encode() in data for token in tokens.values())
                    return json.loads(data)
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
                proc = subprocess.Popen(base + ["-auth-file", str(config)], stdout=log, stderr=log)
                try:
                    def ready():
                        if proc.poll() is not None:
                            raise AssertionError("daemon exited during startup")
                        try:
                            return call("GET", "/healthz", tenant=None)
                        except (OSError, http.client.HTTPException):
                            return None
                    health = wait(ready, "daemon startup")
                    assert health["authentication"] and health["isolation"] is False and "stats" not in health
                    return proc
                except BaseException:
                    proc.kill()
                    proc.wait()
                    raise

            def create(tenant, key):
                return call("POST", "/v1/sandboxes", {}, tenant=tenant, key=key, expected=201)

            def destroy(instance, tenant):
                path = f'/v1/sandboxes/{instance["id"]}'
                call("DELETE", path, {"generation": instance["generation"]}, tenant=tenant, expected=202)
                wait(lambda: call("GET", path, tenant=tenant)["state"] == "DESTROYED", "reclamation")

            try:
                process = start()
                call("POST", "/v1/sandboxes", {}, tenant=None, key="missing-auth", expected=401)
                call("POST", "/v1/sandboxes", {}, key="wrong-auth", headers={"Authorization": "Bearer " + "x" * 40}, expected=401)
                call("POST", "/v1/sandboxes", {}, expected=400)
                a = create("alpha", "shared-key")
                assert create("alpha", "shared-key") == a
                assert "create_key_hash" not in a and "create_spec_hash" not in a
                call("POST", "/v1/sandboxes", {"ttl_ms": 10000}, key="shared-key", expected=409)
                call("POST", "/v1/sandboxes", {}, key="over-quota", expected=429)
                b = create("beta", "shared-key")
                assert a["id"] != b["id"]
                path = f'/v1/sandboxes/{a["id"]}'
                ref = {"generation": a["generation"]}
                command = {**ref, "argv": ["echo", "private-alpha"]}
                job = call("POST", path + "/exec", command, expected=202)
                for method, target, body in [
                    ("GET", path, None), ("POST", path + "/exec", command),
                    ("GET", path + "/executions/" + job["id"], None),
                    ("POST", path + "/stop", ref), ("DELETE", path, ref),
                ]:
                    call(method, target, body, tenant="beta", expected=404)
                call("POST", "/v1/sandboxes", {"tenant_id": "beta"}, key="forged", expected=400)
                checks.append("authentication, all tenant resource boundaries, quota, and creation replay/conflict")
                destroy(a, "alpha")
                destroy(b, "beta")

                ctl = [cli, "-socket", str(sock), "-token-file", str(root / "alpha.token")]
                created = subprocess.run(ctl + ["create", "-ttl", "1m", "-idempotency-key", "cli-key"], capture_output=True, text=True, timeout=5)
                assert created.returncode == 0, created.stderr
                c = json.loads(created.stdout)
                repeated = subprocess.run(ctl + ["create", "-ttl", "1m", "-idempotency-key", "cli-key"], capture_output=True, text=True, timeout=5)
                assert repeated.returncode == 0 and json.loads(repeated.stdout)["id"] == c["id"]
                executed = subprocess.run(ctl + ["exec", "-wait", c["id"], c["generation"], "echo", "authenticated-cli"], capture_output=True, text=True, timeout=5)
                assert executed.returncode == 0 and json.loads(executed.stdout)["output"]["stdout"] == "authenticated-cli\n"
                assert not any(token in created.stdout + created.stderr + repeated.stdout + executed.stdout for token in tokens.values())
                checks.append("token-file CLI performs authenticated creation replay and execution")

                process.kill()
                process.wait(timeout=5)
                process = start()
                wait(lambda: call("GET", f'/v1/sandboxes/{c["id"]}')["state"] == "DESTROYED", "restart fencing and reclamation")
                call("POST", "/v1/sandboxes", {"ttl_ms": 60000}, key="cli-key", expected=410)
                call("POST", "/v1/sandboxes", {}, key="shared-key", expected=410)
                assert list((state / "instances").iterdir()) == []
                checks.append("SIGKILL + restart retains tenant ownership and idempotency tombstones without resurrection")
                process.terminate()
                assert process.wait(timeout=10) == 0
                process = None
                logs = (root / "daemon.log").read_text()
                assert not any(token in logs for token in tokens.values())
                assert "private-alpha" not in logs and "authenticated-cli" not in logs
            finally:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)

    print(json.dumps({"backend": "mock", "provides_microvm_isolation": False, "checks": checks}, indent=2))


if __name__ == "__main__":
    main()
