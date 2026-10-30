"""Test-only closed response observations, not critical-path or queue attribution."""

import math


PHASES = (
    "xa_core_admission", "xa_core_owner_commit", "xa_core_driver", "xa_core_ready_commit",
    "xa_driver_slot", "xa_driver_owner", "xa_driver_quota_reserve", "xa_driver_copy",
    "xa_driver_quota_verify", "xa_driver_activation",
)


def validate_create_server(value, elapsed_ns):
    if (type(value) is not dict or set(value) != {"status", "entries"}
            or value["status"] != "observed" or type(value["entries"]) is not list
            or len(value["entries"]) != len(PHASES)):
        raise ValueError("complete fixed raw-create server observation required")
    for phase, entry in zip(PHASES, value["entries"]):
        if (type(entry) is not dict or set(entry) != {"phase", "ms", "calls"}
                or entry["phase"] != phase or type(entry["calls"]) is not int
                or entry["calls"] != 1 or type(entry["ms"]) not in (int, float)
                or not math.isfinite(entry["ms"]) or not 0 <= entry["ms"] <= 35001):
            raise ValueError("closed ordered finite raw-create server entry required")
    entries = value["entries"]
    # Independent 0.001 ms header rounding, not a shared kernel timestamp.
    if (type(elapsed_ns) is not int or elapsed_ns <= 0
            or sum(e["ms"] for e in entries[4:]) > entries[2]["ms"] + 0.01
            or sum(e["ms"] for e in entries[:4]) > elapsed_ns / 1e6 + 0.01):
        raise ValueError("inconsistent nested server/client duration envelopes")
