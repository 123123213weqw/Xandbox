#!/usr/bin/env python3
"""Opt-in TEST process observation; never a substitute for ordinary-daemon CI."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

import diagnostics_smoke

HELPER = 'TestDiagnosticsProbeProcessHelper'
FD_ENV = 'XANDBOX_DIAGNOSTICS_PROBE_FD'
CODES = ('clean', 'pending', 'write_error', 'other_error')


def decode_receipt(raw):
    if len(raw) != 2 or raw[0] != ord('X') or raw[1] >= len(CODES):
        raise ValueError('invalid closed probe receipt')
    return CODES[raw[1]]


class ObservedProcess:
    def __init__(self, process, reader, receipts):
        self.process, self.reader, self.receipts = process, reader, receipts

    def __getattr__(self, name):
        return getattr(self.process, name)

    def wait(self, timeout=None):
        status = self.process.wait(timeout=timeout)
        if self.reader is not None:
            reader, self.reader = self.reader, None
            try:
                # Nonblocking and bounded even if a faulty helper retains an FD.
                try:
                    raw = os.read(reader, 3)
                    outcome = decode_receipt(raw)
                except (BlockingIOError, ValueError):
                    outcome = 'unavailable'
                self.receipts.append({'exit_status': status, 'close_result': outcome})
            finally:
                os.close(reader)
        return status  # A receipt NEVER turns a nonzero ordinary result into success.


def observed_popen(base, *, receipts, **kwargs):
    reader, writer = os.pipe()
    os.set_blocking(reader, False)
    os.set_blocking(writer, False)
    env = os.environ.copy()
    env[FD_ENV] = str(writer)
    command = [base[0], '-test.run=^' + HELPER + '$', '--', *base[1:]]
    try:
        process = subprocess.Popen(command, env=env, pass_fds=(writer,), **kwargs)
    except BaseException:
        os.close(reader)
        raise
    finally:
        os.close(writer)
    return ObservedProcess(process, reader, receipts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--daemon', required=True)
    parser.add_argument('--helper', required=True)
    parser.add_argument('--node', required=True)
    args = parser.parse_args()
    receipts = []
    processes = []
    def start(base, **kwargs):
        process = observed_popen([str(Path(args.helper).resolve()), *base[1:]], receipts=receipts, **kwargs)
        processes.append(process)
        return process
    original_argv = sys.argv
    sys.argv = [str(Path(diagnostics_smoke.__file__).resolve()),
                '--daemon', str(Path(args.daemon).resolve()), '--node', str(Path(args.node).resolve())]
    passed = False
    try:
        # Only the 45 valid restart incarnations use the TEST observer. The
        # original post-loop refusal/flag checks still use the ordinary daemon.
        diagnostics_smoke.main(daemon_popen=start)
        passed = True
    except (AssertionError, OSError, ValueError, subprocess.TimeoutExpired):
        pass  # Export ONLY the fixed receipt enums below, never exception/console text.
    finally:
        sys.argv = original_argv
        # Startup failures may leave no terminate_cleanly call. Collect only
        # already-terminal owned handles; never extend the original wait budget.
        for process in processes:
            if process.poll() is not None:
                process.wait(timeout=0)
    result = {'test_only': True, 'ordinary_binary_acceptance': False,
              'original_ci_cause_proven': False, 'production_ready': False,
              'full_original_45_cycle_harness_passed': passed, 'receipts': receipts}
    print(json.dumps(result, sort_keys=True))
    return 0 if passed and len(receipts) == 45 and all(
        r == {'exit_status': 0, 'close_result': 'clean'} for r in receipts) else 1


if __name__ == '__main__':
    raise SystemExit(main())
