"""Opt-in disposable Linux CI diagnostic, NEVER a native acceptance gate.

Raw test output, profiles, paths and arbitrary symbol names stay runner-private.
No runtime/installer/Go-test behavior is changed. See docs/RUNTIME_CPU_DIAGNOSTIC.md.
"""
import collections
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import resource
import signal
import subprocess
import sys
import tempfile
import time


TARGET = 'TestRuntimeWorkStopWriteAheadCutsRecoverExactPlanWithoutEarlyStop'
CUTS = tuple('runtime-work-stop-' + section + '-' + point
             for section in ('intent', 'complete', 'anchor', 'publish')
             for point in ('written', 'synced', 'renamed', 'durable'))
PACKAGE = 'github.com/123123213weqw/Xandbox/internal/installtxn'
CAP_SECONDS = 300
MAX_CAPTURE = 16 * 1024 * 1024
CATEGORIES = ('race_instrumentation', 'go_runtime', 'json', 'regexp',
              'project', 'other_or_unattributed')


class DiagnosticError(Exception):
    """Never export exception messages, even from subprocess/JSON/OS errors."""


def require(condition):
    if not condition:
        raise DiagnosticError()


def number(value, maximum=600000):
    require(type(value) in (int, float) and math.isfinite(value)
            and 0 <= value <= maximum)
    return value


def test_summary(raw):
    """Require this entire existing parent and all16 cuts ONCE, no skip/fill."""
    require(0 < len(raw) <= MAX_CAPTURE)
    expected = (TARGET,) + tuple(TARGET + '/' + cut for cut in CUTS)
    runs, passes, elapsed = collections.Counter(), collections.Counter(), {}
    run_order, pass_order = [], []
    package_starts, package_passes = 0, 0
    for line in raw.splitlines():
        require(0 < len(line) <= 1024 * 1024)
        event = json.loads(line)
        require(type(event) is dict and event.get('Package') == PACKAGE)
        action = event.get('Action')
        require(action in ('start', 'run', 'pass', 'output'))
        name = event.get('Test')
        if name is not None:
            require(name in expected and action in ('run', 'pass', 'output'))
            if action == 'run':
                runs[name] += 1
                run_order.append(name)
            if action == 'pass':
                require(runs[name] == 1 and passes[name] == 0)
                passes[name] += 1
                pass_order.append(name)
                elapsed[name] = number(event.get('Elapsed'), CAP_SECONDS)
        elif action == 'start':
            package_starts += 1
        elif action == 'pass':
            package_passes += 1
        else:
            require(action == 'output')
        if action == 'output':
            require(type(event.get('Output')) is str
                    and 'WARNING: DATA RACE' not in event['Output'])
    require(package_starts == package_passes == 1
            and runs == passes == collections.Counter(expected)
            and run_order == list(expected)
            and pass_order == list(expected[1:]) + [TARGET])
    # Export ONLY fixed names and validated numbers, never event Output/Time.
    return {'parent': TARGET, 'parent_passes': 1, 'all16_cuts_passed_once': True,
            'parent_elapsed_seconds': elapsed[TARGET],
            'cut_elapsed_seconds': {cut: elapsed[TARGET + '/' + cut] for cut in CUTS}}


def category(symbol):
    # Symbols influence a CLOSED category only. No symbol text is exported.
    if symbol.startswith(('__tsan', 'racecall', 'racefunc', 'runtime.race')):
        return 'race_instrumentation'
    if symbol.startswith('runtime.'):
        return 'go_runtime'
    if symbol.startswith('encoding/json'):
        return 'json'
    if symbol.startswith('regexp.') or symbol.startswith('regexp/'):
        return 'regexp'
    if symbol.startswith('github.com/123123213weqw/Xandbox/internal/'):
        return 'project'
    return 'other_or_unattributed'


def cpu_summary(raw):
    """Parse the COMPLETE flat pprof-ms table; NEVER sum overlapping cum CPU."""
    require(0 < len(raw) <= MAX_CAPTURE)
    text = raw.decode('utf-8', errors='strict')
    lines = text.splitlines()
    require(lines.count('Type: cpu') == 1 and len(lines) <= 10000)
    totals = re.findall(r'^Duration: [^\n]+, Total samples = ([0-9.]+)ms \([^\n]+\)$',
                        text, re.M)
    require(len(totals) == 1 and not any('Dropped ' in s for s in lines))
    total = number(float(totals[0]))
    require(total > 0)
    columns = [i for i, line in enumerate(lines)
               if line.split() == ['flat', 'flat%', 'sum%', 'cum', 'cum%']]
    require(len(columns) == 1)
    values = dict.fromkeys(CATEGORIES, 0.0)
    rows = 0
    for line in lines[columns[0] + 1:]:
        match = re.fullmatch(
            r'\s*(0|[0-9.]+ms)\s+[0-9.]+%\s+[0-9.]+%\s+'
            r'(0|[0-9.]+ms)\s+[0-9.]+%\s+(.{1,4096})', line)
        require(match is not None)
        flat = number(0 if match[1] == '0' else float(match[1][:-2]))
        # pprof prints exact zero without a unit; nonzero always requires ms.
        number(0 if match[2] == '0' else float(match[2][:-2]))
        values[category(match[3])] += flat
        rows += 1
    require(rows > 0 and abs(sum(values.values()) - total) < 0.01)
    return {'scope': 'profiled_parent_test_process_only_not_helper_CPU_or_IO_wait',
            'total_sampled_CPU_ms': total, 'flat_CPU_ms_by_closed_category': values,
            'all_flat_rows_accounted': True,
            'original_node_cause_or_cap_fit_established': False}


def environment():
    # No ambient token/credential/Go-experiment/hook configuration is forwarded.
    env = {k: os.environ[k] for k in ('HOME', 'PATH', 'TMPDIR', 'GOCACHE', 'GOMODCACHE')
           if k in os.environ}
    env.update({'GOENV': 'off', 'GOWORK': 'off', 'GOTOOLCHAIN': 'go1.27.3',
                'GOMAXPROCS': '2', 'GOFLAGS': '-p=1', 'GOMEMLIMIT': '512MiB',
                'CGO_ENABLED': '1', 'LC_ALL': 'C', 'LANG': 'C'})
    return env


def hosted_linux_only(env, system, uid):
    require(system == 'Linux' and uid != 0 and env.get('GITHUB_ACTIONS') == 'true'
            and env.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and env.get('RUNNER_OS') == 'Linux')


def bounded(command, cwd, env, private, label, deadline):
    """One launched session only; no host-wide PID lookup or signaling."""
    require(label in ('revision', 'compiler', 'test', 'pprof'))
    require(time.monotonic() < deadline)
    out, err = private / (label + '.out'), private / (label + '.err')
    with out.open('xb') as stdout, err.open('xb') as stderr:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stdout,
                                   stderr=stderr, start_new_session=True)
        try:
            while True:
                # Check bounds even when the producer has just terminated.
                require(out.stat().st_size <= MAX_CAPTURE and err.stat().st_size <= MAX_CAPTURE)
                require(time.monotonic() < deadline)
                status = process.poll()
                if status is not None:
                    break
                time.sleep(0.1)
            require(status == 0)
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass  # The owned session may have exited at this boundary.
                process.wait()
    require(err.stat().st_size == 0)
    with out.open('rb') as stream:
        data = stream.read(MAX_CAPTURE + 1)
    require(len(data) <= MAX_CAPTURE)
    return data


def usage_summary(before, after):
    # Linux ru_maxrss is one waited-child high-water mark, NOT concurrent RSS.
    return {
        'scope': 'go_build_and_test_waited_descendants_not_profile_scope',
        'user_CPU_seconds': number(after.ru_utime - before.ru_utime),
        'system_CPU_seconds': number(after.ru_stime - before.ru_stime),
        'max_waited_child_RSS_KiB_not_sum': number(after.ru_maxrss, 2**40),
        'input_block_operations': number(after.ru_inblock - before.ru_inblock, 2**40),
        'output_block_operations': number(after.ru_oublock - before.ru_oublock, 2**40),
        'voluntary_context_switches': number(after.ru_nvcsw - before.ru_nvcsw, 2**40),
        'involuntary_context_switches': number(after.ru_nivcsw - before.ru_nivcsw, 2**40),
        'IO_wait_latency_or_original_host_diagnosis': False,
    }


def main():
    require(len(sys.argv) == 1 and sys.flags.optimize == 0)
    hosted_linux_only(os.environ, platform.system(), os.geteuid())
    os.umask(0o077)
    os.setpriority(os.PRIO_PROCESS, 0, 10)  # Absolute self-only priority.
    require(os.getpriority(os.PRIO_PROCESS, 0) == 10)
    root = Path(__file__).resolve().parent.parent
    start = time.monotonic()
    deadline = start + CAP_SECONDS
    env = environment()
    with tempfile.TemporaryDirectory(prefix='xandbox-cpu-') as name:
        private = Path(name)
        revision = bounded(['git', 'rev-parse', 'HEAD'], root, env, private,
                           'revision', deadline).decode().strip()
        require(re.fullmatch('[0-9a-f]{40}', revision) is not None
                and revision == os.environ.get('GITHUB_SHA'))
        compiler = bounded(['go', 'version'], root, env, private, 'compiler', deadline)
        require(compiler == b'go version go1.27.3 linux/amd64\n')
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        tests = bounded(
            ['go', 'test', '-json', '-race', '-count=1', '-timeout=280s',
             '-run=^' + TARGET + '$', '-cpuprofile=' + str(private / 'cpu.out'),
             '-o', str(private / 'diagnostic.test'), './internal/installtxn'],
            root, env, private, 'test', deadline)
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        test_wall = time.monotonic() - start
        require((private / 'cpu.out').stat().st_size <= MAX_CAPTURE)
        parsed_tests = test_summary(tests)
        pprof = bounded(
            ['go', 'tool', 'pprof', '-top', '-nodecount=0', '-nodefraction=0',
             '-unit=milliseconds', str(private / 'diagnostic.test'), str(private / 'cpu.out')],
            root, env, private, 'pprof', deadline)
        parsed_cpu = cpu_summary(pprof)
        result = {
            'schema': 'xandbox.disposable-runtime-cpu.v1', 'head': revision,
            'diagnostic_complete': True, 'native_qualification': False,
            'original_longload_or_KVM_qualification': False,
            'compiler': 'go1.27.3 linux/amd64', 'race': True, 'count': 1,
            'Go_processes': 2, 'package_parallelism': 1, 'self_nice': 10,
            'soft_GOMEMLIMIT_MiB_not_kernel_quota': 512,
            'whole_diagnostic_cap_seconds': CAP_SECONDS,
            'build_and_test_wall_seconds': number(test_wall, CAP_SECONDS),
            'test_source_sha256': hashlib.sha256(
                (root / 'internal/installtxn/runtime_work_stop_linux_test.go').read_bytes()).hexdigest(),
            'test': parsed_tests, 'CPU': parsed_cpu, 'waited_usage': usage_summary(before, after),
            'raw_output_profiles_paths_symbols_exported': False,
        }
        require(time.monotonic() < deadline)
    # Only after complete validation AND private-directory cleanup.
    require(time.monotonic() < deadline)
    print(json.dumps(result, sort_keys=True))


def entrypoint():
    try:
        main()
        return 0
    except (Exception, KeyboardInterrupt):
        print(json.dumps({'schema': 'xandbox.disposable-runtime-cpu.v1',
                          'diagnostic_complete': False, 'native_qualification': False,
                          'failure': 'closed_diagnostic_failure_no_raw_details',
                          'raw_output_profiles_paths_symbols_exported': False}))
        return 1


if __name__ == '__main__':
    raise SystemExit(entrypoint())
