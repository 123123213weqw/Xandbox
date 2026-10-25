#!/usr/bin/env python3
"""Read-only doctor process smoke; never KVM or deployment acceptance."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

IDS = ('linux', 'architecture', 'systemd_pid1', 'systemd_version', 'cgroup_v2', 'controllers', 'kvm_device', 'kvm_permissions')
CHECKS = {
    'linux': {'pass': 'linux_observed', 'fail': 'linux_required'},
    'architecture': {'pass': 'qualified_fixture_architecture', 'unknown': 'architecture_requires_separate_qualification'},
    'systemd_pid1': {'pass': 'systemd_pid1_observed', 'fail': 'systemd_pid1_required', 'unknown': 'pid1_observation_unavailable'},
    'systemd_version': {'pass': 'running_manager_version_floor_met', 'fail': 'dedicated_newer_systemd_node_required', 'unknown': 'running_manager_version_unconfirmed'},
    'cgroup_v2': {'pass': 'cgroup2_filesystem_observed', 'fail': 'unified_cgroup2_required', 'unknown': 'cgroup_filesystem_unconfirmed'},
    'controllers': {'pass': 'root_controllers_observed_not_unit_delegation', 'fail': 'required_root_controller_missing', 'unknown': 'controller_inventory_unconfirmed'},
    'kvm_device': {'pass': 'kvm_character_device_observed_not_opened', 'fail': 'kvm_character_device_required', 'unknown': 'kvm_device_unconfirmed'},
    'kvm_permissions': {'pass': 'caller_access_observed_not_device_open', 'fail': 'authorized_operator_access_required', 'unknown': 'caller_device_access_unconfirmed'},
}
CODES = {code for values in CHECKS.values() for code in values.values()}
DEFERRED = ('actual_kvm_creation', 'clone3_and_namespace_capabilities', 'unit_delegation_and_budget_readback',
            'asset_hashes_and_guest_health', 'storage_quota_and_backing_device', 'reserved_uids_and_trusted_paths',
            'node_capacity_and_pressure', 'network_and_tls_policy', 'production_fault_matrix_and_slos')


def validate(v, terminal):
    assert type(v) is dict and set(v) == {'version', 'profile', 'os', 'architecture', 'required_systemd_major',
        'observed_systemd_major', 'basic_prerequisites_met', 'checks', 'missing_controllers', 'deferred_checks',
        'read_only', 'vm_created', 'isolation_validated', 'production_ready'}
    assert type(v['version']) is int and v['version'] == 1 and v['profile'] == 'systemd-install-v1'
    assert type(v['required_systemd_major']) is int and v['required_systemd_major'] == 254
    assert type(v['observed_systemd_major']) is int and 0 <= v['observed_systemd_major'] <= 9999
    assert v['os'] in ('linux', 'darwin', 'windows', 'other') and v['architecture'] in ('amd64', 'arm64', 'other')
    assert v['read_only'] is True and v['vm_created'] is False and v['isolation_validated'] is False and v['production_ready'] is False
    assert v['deferred_checks'] == list(DEFERRED)
    assert type(v['checks']) is list and len(v['checks']) == 8 and [c['id'] for c in v['checks']] == list(IDS)
    for c in v['checks']:
        assert set(c) == {'id', 'status', 'code'} and c['status'] in CHECKS[c['id']] and c['code'] == CHECKS[c['id']][c['status']]
    assert type(v['missing_controllers']) is list
    assert v['missing_controllers'] == [c for c in ('cpu', 'io', 'memory', 'pids') if c in v['missing_controllers']]
    passed = all(c['status'] == 'pass' for c in v['checks'])
    assert type(v['basic_prerequisites_met']) is bool and v['basic_prerequisites_met'] is passed
    assert terminal == (0 if passed else 1)
    if passed:
        assert v['os'] == 'linux' and v['architecture'] == 'amd64' and v['observed_systemd_major'] >= 254 and not v['missing_controllers']


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--doctor', type=Path, required=True)
    args = p.parse_args()
    doctor = str(args.doctor.resolve())
    with tempfile.TemporaryDirectory(prefix='xd-doctor-') as temp:
        root = Path(temp)
        # A hostile PATH executable and ambient remote-manager selection must
        # not be used. Marker/sentinel checks are not a universal write trace.
        fake = root / 'systemctl'
        fake.write_text('#!/bin/sh\necho invoked > wrong-command-invoked\nexit 99\n')
        fake.chmod(0o700)
        sentinel = root / 'operator-input'
        sentinel.write_bytes(b'unchanged local smoke sentinel\n')
        env = os.environ.copy()
        env.update(PATH=str(root), HOME=str(root), SYSTEMD_HOST='PRIVATE_POISON_HOST',
                   SYSTEMD_BUS_ADDRESS='PRIVATE_POISON_ADDRESS', DBUS_SYSTEM_BUS_ADDRESS='PRIVATE_POISON_ADDRESS',
                   SYSTEMD_PAGER='PRIVATE_POISON_PAGER', SYSTEMD_OFFLINE='1')
        r = subprocess.run([doctor], cwd=root, env=env, capture_output=True, timeout=10)
        assert len(r.stdout) <= 16384 and not r.stderr and b'PRIVATE_' not in r.stdout
        validate(json.loads(r.stdout), r.returncode)
        for argv in (['--install'], ['-root', 'PRIVATE_POISON_PATH'], ['sh', '-c', 'PRIVATE_POISON_COMMAND']):
            bad = subprocess.run([doctor, *argv], cwd=root, env=env, capture_output=True, timeout=5)
            assert bad.returncode == 2 and not bad.stdout and bad.stderr == b'xandbox-doctor: no paths, commands or installation arguments accepted\n'
        help_result = subprocess.run([doctor, '--help'], cwd=root, env=env, capture_output=True, timeout=5)
        assert help_result.returncode == 0 and not help_result.stderr and b'not deployment' in help_result.stdout
        assert not (root / 'wrong-command-invoked').exists() and sentinel.read_bytes() == b'unchanged local smoke sentinel\n'
        assert sorted(x.name for x in root.iterdir()) == ['operator-input', 'systemctl']
    print(json.dumps({'doctor_process_smoke': True, 'host_modification_or_vm_creation_acceptance': False}))


if __name__ == '__main__':
    main()
