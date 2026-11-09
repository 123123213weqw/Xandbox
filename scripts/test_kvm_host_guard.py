import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

import host_test_guard as guard


def healthy():
    return {'total': 128 * guard.GIB, 'available': 100 * guard.GIB,
            'cgroup_available': None, 'cpus': 32,
            'disks': [(1024 * guard.GIB, 800 * guard.GIB, 10000000, 9000000)],
            'memory_full': 0.0, 'io_full': 0.0}


class HostBudgetTests(unittest.TestCase):
    def setUp(self):
        self.budget = guard.Budget(10 * guard.GIB, 24 * guard.GIB, 8)

    def test_positive_preflight_and_runtime(self):
        for starting in (True, False):
            self.assertEqual(guard.reasons(self.budget, healthy(), starting=starting), ())

    def test_memory_preserves_twenty_percent_and_accounts_full_budget(self):
        view = healthy()
        reserve = view['total'] // 5
        view['available'] = reserve + self.budget.memory - 1
        self.assertIn('host_memory_headroom', guard.reasons(self.budget, view, starting=True))
        self.assertNotIn('host_memory_headroom', guard.reasons(self.budget, view, starting=False))
        view['available'] = reserve - 1
        self.assertIn('host_memory_headroom', guard.reasons(self.budget, view, starting=False))

    def test_fixed_minimum_and_fraction_and_cpu_reserve(self):
        view = healthy()
        view.update(total=32 * guard.GIB, available=8 * guard.GIB - 1, cpus=8)
        result = guard.reasons(self.budget, view, starting=False)
        for reason in ('host_memory_headroom', 'test_memory_fraction', 'host_cpu_reserve'):
            self.assertIn(reason, result)

    def test_ancestor_headroom_is_independent_of_host_free_ram(self):
        view = healthy()
        view['cgroup_available'] = 2 * guard.GIB + self.budget.memory - 1
        self.assertIn('ancestor_memory_headroom', guard.reasons(self.budget, view, starting=True))
        view['cgroup_available'] = 2 * guard.GIB - 1
        self.assertIn('ancestor_memory_headroom', guard.reasons(self.budget, view, starting=False))

    def test_disk_growth_and_inode_reserves(self):
        view = healthy()
        total, _, inodes, _ = view['disks'][0]
        view['disks'] = [(total, total // 10 + self.budget.disk - 1, inodes, inodes // 10 + 150000 - 1)]
        self.assertEqual(guard.reasons(self.budget, view, starting=True),
                         ('host_disk_headroom', 'host_inode_headroom'))
        self.assertEqual(guard.reasons(self.budget, view, starting=False), ())
        view['disks'] = [(total, total // 10 - 1, inodes, inodes // 10 - 1)]
        self.assertEqual(guard.reasons(self.budget, view, starting=False),
                         ('host_disk_headroom', 'host_inode_headroom'))

    def test_every_filesystem_is_checked_not_only_srv(self):
        view = healthy()
        view['disks'].append((32 * guard.GIB, 1, 1000000, 900000))
        self.assertIn('host_disk_headroom', guard.reasons(self.budget, view, starting=False))

    def test_pressure_thresholds_and_invalid_data_fail_closed(self):
        for key, value, code in [('memory_full', 0.5, 'memory_full_pressure'),
                                 ('io_full', 10, 'io_full_pressure')]:
            view = healthy(); view[key] = value
            self.assertIn(code, guard.reasons(self.budget, view, starting=False))
        for key, value in [('total', True), ('cpus', 0), ('available', -1),
                           ('memory_full', float('nan')), ('io_full', float('inf')),
                           ('cgroup_available', False), ('disks', [])]:
            view = healthy(); view[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(guard.UnsafeHost):
                guard.reasons(self.budget, view, starting=True)

    def test_budget_never_accepts_relaxed_unbounded_or_nonintegral_caps(self):
        for values in [(19 * guard.GIB, guard.GIB, 4, 900),
                       (guard.GIB, 49 * guard.GIB, 4, 900),
                       (guard.GIB, guard.GIB, 13, 900),
                       (guard.GIB, guard.GIB, 4, 3601),
                       (True, guard.GIB, 4, 900), (guard.GIB, guard.GIB, 0, 900)]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                guard.Budget(*values)

    def test_pressure_parser_rejects_missing_duplicate_and_nonfinite(self):
        self.assertEqual(guard.pressure('some avg10=1.25 avg60=0 total=1\nfull avg10=0 total=0', 'full'), 0)
        for text in ('', 'some avg10=0', 'full avg10=nan', 'full avg10=-1',
                     'full avg10=101', 'full avg10=0\nfull avg10=0',
                     'full avg10=50 avg10=0'):
            with self.subTest(text=text), self.assertRaises((guard.UnsafeHost, KeyError)):
                guard.pressure(text, 'full')

    def test_all_finite_ancestor_limits_are_observed(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root); group = directory / 'cgroups'; group.mkdir()
            parent = group / 'slice'; parent.mkdir(); child = parent / 'task'; child.mkdir()
            membership = directory / 'membership'; membership.write_text('0::/slice/task\n')
            for path, maximum, current in ((group, 'max', 100), (parent, '1000', 900), (child, '800', 200)):
                (path / 'memory.max').write_text(maximum)
                (path / 'memory.current').write_text(str(current))
            def path(name):
                return {'/proc/self/cgroup': membership, '/sys/fs/cgroup': group}.get(str(name), Path(name))
            with mock.patch.object(guard, 'Path', side_effect=path):
                self.assertEqual(guard.cgroup_headroom(), 100)
                (parent / 'memory.max').write_text('max')
                self.assertEqual(guard.cgroup_headroom(), 600)
                (child / 'memory.current').unlink()
                with self.assertRaises(OSError): guard.cgroup_headroom()

    def test_v1_or_unresolved_cgroup_namespace_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            membership = Path(root) / 'membership'
            def path(name):
                return membership if str(name) == '/proc/self/cgroup' else Path(name)
            with mock.patch.object(guard, 'Path', side_effect=path):
                for text in ('2:memory:/slice\n', '0::/../../hidden\n', '0::/one\n0::/two\n'):
                    membership.write_text(text)
                    with self.subTest(text=text), self.assertRaises(guard.UnsafeHost): guard.cgroup_headroom()


class MonitorTests(unittest.TestCase):
    def make(self, read=None, clock=None, *, admitted=True):
        monitor = guard.HostGuard(guard.Budget(3 * guard.GIB, 4 * guard.GIB, 4), (),
                                  _sample=read or healthy, _clock=clock)
        # Most state-machine tests begin at an already admitted state. Startup
        # controls below independently exercise the real start/lease path.
        monitor._active = admitted
        return monitor

    def test_failure_latches_no_relaunch_and_callback_exactly_once(self):
        monitor = self.make(); handle = mock.Mock(); spawn = mock.Mock(return_value='child')
        self.assertEqual(monitor.launch(handle, spawn), 'child')
        monitor.trip(); monitor.trip()
        handle.abort.assert_called_once_with()
        with self.assertRaises(guard.UnsafeHost): monitor.check()
        with self.assertRaises(guard.UnsafeHost): monitor.launch(handle, spawn)
        spawn.assert_called_once_with()

    def test_current_generation_only_not_previous(self):
        monitor = self.make(); first, second = mock.Mock(), mock.Mock()
        monitor.launch(first, lambda: None); monitor.launch(second, lambda: None)
        monitor.trip()
        first.abort.assert_not_called(); second.abort.assert_called_once_with()

    def test_failed_abort_is_not_reported_as_confirmed_cleanup(self):
        monitor = self.make(); handle = mock.Mock()
        handle.abort.side_effect = OSError('private detail')
        monitor.launch(handle, lambda: None); monitor.trip()
        self.assertIn('unconfirmed', monitor.failure)
        self.assertNotIn('private detail', monitor.failure)

    def test_missing_observation_and_wall_limit_abort(self):
        for failure in ('read', 'deadline'):
            monitor = self.make(clock=lambda: 10)
            monitor.deadline = 5 if failure == 'deadline' else 20
            if failure == 'read': monitor.read = mock.Mock(side_effect=OSError())
            handle = mock.Mock(); monitor.launch(handle, lambda: None)
            monitor.done = mock.Mock(); monitor.done.wait.return_value = False
            monitor._watch()
            handle.abort.assert_called_once_with()
            with self.assertRaises(guard.UnsafeHost): monitor.check()

    def test_trip_during_spawn_waits_then_aborts_spawned_generation(self):
        monitor = self.make(); handle = mock.Mock(); entered = threading.Event(); release = threading.Event()
        def spawn():
            entered.set()
            self.assertTrue(release.wait(2))
        launch = threading.Thread(target=lambda: monitor.launch(handle, spawn))
        launch.start(); self.assertTrue(entered.wait(2))
        trip = threading.Thread(target=monitor.trip); trip.start()
        release.set(); launch.join(2); trip.join(2)
        self.assertFalse(launch.is_alive()); self.assertFalse(trip.is_alive())
        handle.abort.assert_called_once_with()

    def test_start_failure_releases_serial_lease(self):
        with tempfile.TemporaryFile() as file:
            fd = os.dup(file.fileno())
            monitor = self.make(read=mock.Mock(side_effect=OSError()), admitted=False)
            with mock.patch.object(guard, 'serial_lock', return_value=fd):
                with self.assertRaises(OSError): monitor.start()
            with self.assertRaises(OSError): os.fstat(fd)

    def test_start_close_is_single_use_and_releases_lease(self):
        with tempfile.TemporaryFile() as file:
            fd = os.dup(file.fileno()); monitor = self.make(admitted=False)
            with mock.patch.object(guard, 'serial_lock', return_value=fd): monitor.start()
            monitor.close(); monitor.close()
            with self.assertRaises(OSError): os.fstat(fd)
            with self.assertRaises(guard.UnsafeHost): monitor.start()

    def test_never_started_monitor_cannot_authorize_spawn(self):
        monitor = self.make(admitted=False); spawn = mock.Mock(); handle = mock.Mock()
        with self.assertRaises(guard.UnsafeHost): monitor.launch(handle, spawn)
        spawn.assert_not_called(); handle.abort.assert_not_called()

    def test_stop_or_close_cannot_be_followed_by_unmonitored_spawn(self):
        for method in ('stop', 'close'):
            monitor = self.make(); spawn = mock.Mock(); handle = mock.Mock()
            getattr(monitor, method)()
            with self.subTest(method=method), self.assertRaises(guard.UnsafeHost):
                monitor.launch(handle, spawn)
            spawn.assert_not_called(); handle.abort.assert_not_called()


class OwnedHandleTests(unittest.TestCase):
    def test_abort_closes_only_owned_pipe_and_pins_original_kill_inode(self):
        with tempfile.TemporaryDirectory() as root:
            group = Path(root); (group / 'cgroup.kill').write_text('0')
            read, write = os.pipe(); other_read, other_write = os.pipe()
            try:
                handle = guard.OwnedAbort(group, write)
                (group / 'cgroup.kill').rename(group / 'original')
                (group / 'cgroup.kill').write_text('untouched')
                handle.abort(); handle.close(); handle.close()
                self.assertEqual(os.read(read, 1), b'')
                self.assertEqual((group / 'original').read_text(), '1')
                self.assertEqual((group / 'cgroup.kill').read_text(), 'untouched')
                os.write(other_write, b'x'); self.assertEqual(os.read(other_read, 1), b'x')
            finally:
                os.close(read); os.close(other_read); os.close(other_write)

    def test_symlink_kill_target_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as root:
            group = Path(root); (group / 'target').write_text('untouched')
            (group / 'cgroup.kill').symlink_to(group / 'target')
            read, write = os.pipe()
            try:
                with self.assertRaises(OSError): guard.OwnedAbort(group, write)
                self.assertEqual((group / 'target').read_text(), 'untouched')
            finally:
                os.close(read); os.close(write)

    def test_serial_lease_rejects_second_and_keeps_same_inode(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'guard'; fd = guard._serial_lock_at(path, os.getuid())
            inode = os.fstat(fd).st_ino
            try:
                with self.assertRaises(BlockingIOError): guard._serial_lock_at(path, os.getuid())
            finally: os.close(fd)
            fd = guard._serial_lock_at(path, os.getuid())
            try: self.assertEqual(os.fstat(fd).st_ino, inode)
            finally: os.close(fd)

    def test_serial_lease_rejects_unsafe_directory_symlink_and_lock_content(self):
        with tempfile.TemporaryDirectory() as root:
            # mkdir's mode is filtered by umask: under 077, requesting 0755
            # creates a SAFE 0700 directory. Establish the actual unsafe input
            # explicitly; never weaken the production permission check.
            path = Path(root) / 'guard'; path.mkdir(mode=0o700); path.chmod(0o755)
            self.assertEqual(path.stat().st_mode & 0o7777, 0o755)
            with self.assertRaises(guard.UnsafeHost): guard._serial_lock_at(path, os.getuid())
            path.chmod(0o700); (path / 'lock').write_text('foreign'); (path / 'lock').chmod(0o600)
            with self.assertRaises(guard.UnsafeHost): guard._serial_lock_at(path, os.getuid())
            (path / 'lock').unlink(); (path / 'lock').symlink_to(Path(root) / 'other')
            with self.assertRaises(OSError): guard._serial_lock_at(path, os.getuid())

    def test_nested_harness_is_wired_before_allocation_and_spawn(self):
        # Source wiring only: no privileged fixture is launched by these tests.
        text = Path(__file__).with_name('kvm_nested_host.py').read_text()
        self.assertLess(text.index('host_guard.start()'), text.index("root.mkdir(mode=0o700)"))
        self.assertIn('process=host_guard.launch(lifetime,lambda: subprocess.Popen(', text)
        self.assertIn('host_guard.check()\n    assert result', text)
        self.assertIn('result[\'host_safety_guard_aborted\']', text)

    def test_installer_harness_uses_the_same_guard_and_retains_source_pin(self):
        text = Path(__file__).with_name('kvm_systemd_host.py').read_text()
        self.assertLess(text.index('host_guard.start()'), text.index('create(root);create(control)'))
        self.assertIn('process=host_guard.launch(lifetime,lambda: subprocess.Popen(', text)
        self.assertIn("result['host_safety_guard_sha256']", text)
        self.assertIn('host_guard.check()\n    assert result', text)


if __name__ == '__main__':
    unittest.main()
