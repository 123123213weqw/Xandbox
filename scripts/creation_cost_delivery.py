"""TEST ONLY: bounded private host receipt before an ungraceful outer power cut.

Not a persistence barrier, API/Stop latency, or performance qualification.
It does not repair a byte, stop a guest gracefully, or change fault profiles.
"""
import base64, hashlib, json, os, re, stat, sys, time
PREFIXES = {b"XANDBOX_CREATION_COST_ABI_PRIVATE ": "abi", b"XANDBOX_CREATION_COST_PRIVATE ": "normal"}
FAILURES = (b"XANDBOX_CREATION_COST_SETUP_FAILURE_PRIVATE ", b"XANDBOX_CREATION_COST_FAILED_CREATES_PRIVATE ")
MAX_CONSOLE = 2 << 20
MAX_PAYLOAD = 1 << 20
class InvalidDelivery(ValueError): pass
class DeliveryTimeout(TimeoutError): pass

def require(condition, message):
    if not condition: raise InvalidDelivery(message)

def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate original JSON field")
        result[key] = value
    return result

def inspect_console(data, scope):
    require(type(data) is bytes and len(data) <= MAX_CONSOLE and scope in ("checkpoint", "cold"), "bounded console/scope")
    groups = {"abi": [], "normal": []}
    lines = data.split(b"\n")
    for line in lines[:-1]:
        require(not any(line.startswith(p) for p in FAILURES), "producer rejected observation")
        for prefix, kind in PREFIXES.items():
            if not line.startswith(prefix): continue
            try: row = json.loads(line[len(prefix):], object_pairs_hook=unique_pairs)
            except (ValueError, UnicodeDecodeError) as error: raise InvalidDelivery("malformed newline-terminated frame") from error
            require(type(row) is dict and set(row) == {"scope", "index", "chunks", "bytes", "sha256", "data"}, "closed frame fields")
            require(row["scope"] == scope and all(type(row[k]) is int for k in ("index", "chunks", "bytes")), "scope and strict integer bounds")
            require(1 <= row["chunks"] <= 512 and 0 < row["bytes"] <= MAX_PAYLOAD and row["chunks"] == (row["bytes"]+2047)//2048, "fixed frame bounds")
            require(type(row["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", row["sha256"]) is not None and type(row["data"]) is str, "strict hash and base64 types")
            group = groups[kind]
            require(row["index"] == len(group) and row["index"] < row["chunks"], "duplicate/missing/reordered frame")
            if kind == "normal": require(groups["abi"] and len(groups["abi"]) == groups["abi"][0]["chunks"], "ABI receipt precedes normal frames")
            if group: require(all(row[k] == group[0][k] for k in ("scope", "chunks", "bytes", "sha256")), "mixed original frame sets")
            try: chunk = base64.b64decode(row["data"], validate=True)
            except (ValueError, TypeError) as error: raise InvalidDelivery("invalid original base64") from error
            require(len(chunk) == min(2048, row["bytes"]-row["index"]*2048) and base64.b64encode(chunk).decode() == row["data"], "canonical chunk range and encoding")
            group.append(row)
    payloads, hashes = {}, {}
    for kind, group in groups.items():
        if not group or len(group) != group[0]["chunks"]: continue
        value = b"".join(base64.b64decode(row["data"], validate=True) for row in group)
        require(len(value) == group[0]["bytes"] and hashlib.sha256(value).hexdigest() == group[0]["sha256"], "whole payload checksum mismatch; never repair")
        payloads[kind], hashes[kind] = value, group[0]["sha256"]
    tail = lines[-1]
    partial = bool(tail and any(tail.startswith(p) or p.startswith(tail) for p in tuple(PREFIXES)+FAILURES))
    counts = {k:len(v) for k,v in groups.items()}
    if len(payloads) != 2: return dict(complete=False, partial_tail=partial, received_frames=counts)
    require(not partial, "extra partial frame after complete original sets")
    return dict(complete=True, payloads=payloads, payload_sha256=hashes, received_frames=counts)

def await_delivery(read_snapshot, scope, *, timeout=2.0, now=time.monotonic, sleep=time.sleep):
    require(type(timeout) in (int, float) and 0 < timeout <= 2.0, "fixed maximum export wait, not workload timeout override")
    start, previous, reads = now(), b"", 0
    while True:
        current = read_snapshot(); reads += 1
        require(type(current) is bytes and current.startswith(previous), "append-only console; no rewrite or truncation")
        result = inspect_console(current, scope)
        elapsed = now()-start
        if result["complete"] and elapsed <= timeout:
            result.update(delivery_wait_seconds=elapsed, snapshot_reads=reads, after_measured_work_before_outer_power_cut=True, not_part_of_API_or_stop_latency=True)
            return result
        if elapsed >= timeout: raise DeliveryTimeout("original diagnostics incomplete or late at fixed export deadline; preserve bytes")
        previous = current
        sleep(min(.01, timeout-elapsed))

def bounded_file_reader(path, *, expected_uid):
    require(type(expected_uid) is int and 0 <= expected_uid < (1 << 32)-1, "explicit trusted launch UID required")
    uid = expected_uid
    identity = None
    def read():
        nonlocal identity
        fd = os.open(path, os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            read.fd_metadata = dict(file_type=stat.S_IFMT(info.st_mode), uid=info.st_uid, gid=info.st_gid, mode=stat.S_IMODE(info.st_mode), nlink=info.st_nlink, size=info.st_size, device=info.st_dev, inode=info.st_ino)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= MAX_CONSOLE, "owned bounded private regular console")
            current = (info.st_dev, info.st_ino)
            require(identity is None or identity == current, "original console inode cannot be replaced")
            identity = current
            value = stream.read(MAX_CONSOLE+1)
            require(len(value) <= MAX_CONSOLE, "bounded console during concurrent append")
            return value
    read.fd_metadata = None
    return read

def validate_creation_cost_profile(args):
    if args.creation_cost_diagnostics is None: return
    require(args.creation_cost_diagnostics in ("observe", "maximum"), "closed diagnostic mode")
    allowed = {"creation_cost_diagnostics", "node_budget", "fixture", "daemon", "warden", "firecracker", "jailer", "kernel", "initrd", "workspace", "alpine", "source_revision", "report", "log_dir"}
    require(args.node_budget is True and all(k in allowed or v is None or v is False for k,v in vars(args).items()), "delivery wait only in private healthy no-snapshot baseline; never fault/load modifiers")

def record_delivery(console, logs, scope, *, expected_uid):
    require(scope in ("checkpoint", "cold"), "closed diagnostic delivery scope")
    reader = bounded_file_reader(console, expected_uid=expected_uid)
    try:
        result = await_delivery(reader, scope)
    except (InvalidDelivery, DeliveryTimeout, OSError) as error:
        # Bounded scalar FD observations only. No path, payload or arbitrary error
        # message; preserve the original exception even if evidence export fails.
        value = dict(scope=scope, expected_uid=expected_uid, fd_metadata=reader.fd_metadata,
                     exception_class=type(error).__name__, errno=error.errno if isinstance(error, OSError) else None,
                     failed_not_qualified=True, no_missing_byte_repair=True)
        try:
            fd = os.open(logs/("diagnostic-delivery-"+scope+"-failure.json"), os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as target: json.dump(value, target, sort_keys=True); target.write("\n")
        except OSError:
            sys.stderr.write("PRIVATE_DELIVERY_FAILURE_RECEIPT_WRITE_FAILED\n")
        raise
    require(reader.fd_metadata is not None, "successful original FD observation required")
    return dict(scope=scope, expected_uid=expected_uid, fd_metadata=dict(reader.fd_metadata), complete_original_payloads_received=True,
                payload_sha256=result["payload_sha256"], payload_bytes={k:len(v) for k,v in result["payloads"].items()}, received_frames=result["received_frames"],
                delivery_wait_seconds=result["delivery_wait_seconds"], snapshot_reads=result["snapshot_reads"], not_part_of_API_or_stop_latency=True,
                after_measured_work_before_outer_power_cut=True, observation_method_changed_may_allow_background_IO_progress=True,
                no_guest_shutdown_extra_fsync_or_missing_byte_reconstruction=True)
