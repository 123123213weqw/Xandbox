import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import reader_rollback_smoke as reader


class FixedReaderInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.binary = self.root / 'image'
        self.raw = b'fixed-test-data-only-never-executed'
        self.binary.write_bytes(self.raw)
        self.binary.chmod(0o700)
        self.pin = reader.Pin(len(self.raw), hashlib.sha256(self.raw).hexdigest())

    def test_same_verified_descriptor_survives_path_rebinding_without_adoption(self):
        fd, before = reader.open_pinned(str(self.binary), self.pin)
        try:
            self.binary.rename(self.root / 'original')
            self.binary.write_bytes(b'not-the-verified-image')
            self.assertEqual(os.pread(fd, len(self.raw), 0), self.raw)
            # Linux may give creation and rename the same coarse timestamp.
            # The invariant is that the retained FD still selects the original
            # inode/bytes, never the different image now occupying the path.
            self.assertEqual(os.fstat(fd).st_ino, before[1])
            self.assertNotEqual(self.binary.stat().st_ino, before[1])
        finally:
            os.close(fd)

    def test_modified_same_size_image_is_refused(self):
        self.binary.write_bytes(b'X' + self.raw[1:])
        with self.assertRaisesRegex(reader.Refused, ''):
            reader.open_pinned(str(self.binary), self.pin)

    def test_symlink_relative_directory_and_size_mismatch_refuse(self):
        link = self.root / 'link'
        link.symlink_to(self.binary)
        for path in (str(link), 'relative-image', str(self.root)):
            with self.assertRaises((reader.Refused, OSError)):
                reader.open_pinned(path, self.pin)
        self.binary.write_bytes(self.raw + b'x')
        with self.assertRaises(reader.Refused):
            reader.open_pinned(str(self.binary), self.pin)

    def test_unsafe_modes_and_hard_links_refuse(self):
        for mode in (0o600, 0o722, 0o777):
            self.binary.chmod(mode)
            with self.assertRaises(reader.Refused):
                reader.open_pinned(str(self.binary), self.pin)
        self.binary.chmod(0o700)
        os.link(self.binary, self.root / 'other')
        with self.assertRaises(reader.Refused):
            reader.open_pinned(str(self.binary), self.pin)

    def test_short_read_or_identity_drift_closes_descriptor(self):
        for kind in ('short', 'drift'):
            actual = os.fstat
            observed = []
            def fstat(fd):
                value = actual(fd)
                observed.append(fd)
                if kind == 'drift' and len(observed) == 2:
                    self.binary.chmod(0o500)
                    value = actual(fd)
                return value
            with patch('reader_rollback_smoke.os.fstat', side_effect=fstat):
                with patch('reader_rollback_smoke.os.pread', return_value=b'') if kind == 'short' else patch('reader_rollback_smoke.time.monotonic'):
                    with self.assertRaises(reader.Refused):
                        reader.open_pinned(str(self.binary), self.pin)
            self.assertTrue(observed)
            with self.assertRaises(OSError):
                os.fstat(observed[0])
            self.binary.chmod(0o700)

    def test_fixed_pair_is_not_an_environment_or_caller_digest_selector(self):
        self.assertEqual(set(reader.PINS), {'baseline', 'candidate', 'node'})
        self.assertNotEqual(reader.PINS['baseline'], reader.PINS['candidate'])
        source = inspect.getsource(reader.main)
        self.assertIn("for role in PINS:", source)
        for flag in ('--state-dir', '--backend', '--sha256', '--force', '--allow'):
            self.assertNotIn(flag, source)
        with patch('reader_rollback_smoke.platform.system', return_value='Darwin'):
            with patch('reader_rollback_smoke.subprocess.Popen') as start:
                with self.assertRaises(reader.Refused):
                    reader.exercise({})
                start.assert_not_called()


class ReaderAuthorityTests(unittest.TestCase):
    def previous(self):
        return {'ledger': {'old.json': 'old-complete-byte-hash'},
                'sessions': {'session.json': {'id': 'session', 'revision': 2,
                    'create_key_hash': 'permanent', 'attempts': [{'key_hash': 'initial'}, {'key_hash': 'switch'}]}},
                'identity': b'original-epoch-identity',
                'control': {'epoch': 'epoch', 'revision': 4, 'mode': 'drained'}}

    def test_append_preserves_all_old_terminal_authority(self):
        previous = self.previous()
        current = copy.deepcopy(previous)
        current['ledger']['new.json'] = 'new-identity'
        current['sessions']['new.json'] = {'id': 'new-session'}
        reader.preserved(previous, current)

    def test_missing_or_modified_tombstone_fails(self):
        for action in ('remove', 'mutate'):
            previous = self.previous()
            current = copy.deepcopy(previous)
            if action == 'remove':
                current['ledger'].pop('old.json')
            else:
                current['ledger']['old.json'] = 'rewritten-generation-or-key'
            with self.assertRaises(reader.Refused):
                reader.preserved(previous, current)

    def test_session_revision_keys_attempts_and_identity_must_survive(self):
        for action in ('remove', 'revision', 'key', 'attempt'):
            previous = self.previous()
            current = copy.deepcopy(previous)
            if action == 'remove':
                current['sessions'].clear()
            elif action == 'revision':
                current['sessions']['session.json']['revision'] = 1
            elif action == 'key':
                current['sessions']['session.json']['create_key_hash'] = 'restored-old-key'
            else:
                current['sessions']['session.json']['attempts'].pop()
            with self.assertRaises(reader.Refused):
                reader.preserved(previous, current)

    def test_node_epoch_revision_mode_and_identity_cannot_rewind(self):
        for field, value in (('epoch', 'new-epoch'), ('revision', 3), ('mode', 'open')):
            previous = self.previous()
            current = copy.deepcopy(previous)
            current['control'][field] = value
            with self.assertRaises(reader.Refused):
                reader.preserved(previous, current)
        current = self.previous()
        current['identity'] = b'old-identity-copy'
        with self.assertRaises(reader.Refused):
            reader.preserved(self.previous(), current)

    def test_only_four_sequential_mock_boots_no_restore_or_arbitrary_commands(self):
        source = inspect.getsource(reader.exercise)
        for gate in ("('baseline', 'candidate', 'baseline', 'candidate')",
                     "'-backend', 'mock'", 'with disposable_root(',
                     'process.wait(timeout=15)', 'revision == 8',
                     "change('drain')", "'IDEMPOTENCY_GONE'", "'SESSION_GONE'",
                     "auth.read_bytes() == auth_before", 'preserved(previous, terminal_snapshot(state))'):
            self.assertIn(gate, source)
        for forbidden in ('shutil.copy', 'copytree', 'rmtree(state', 'shell=True', 'sudo', 'firecracker', 'rsync'):
            self.assertNotIn(forbidden, source)

    def test_unreaped_writer_keeps_private_state_instead_of_finalizer_deletion(self):
        root = None
        try:
            with reader.disposable_root(lambda: False) as root:
                (root / 'still-owned-state').write_bytes(b'preserve')
            self.assertEqual((root / 'still-owned-state').read_bytes(), b'preserve')
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
        finally:
            if root is not None:
                (root / 'still-owned-state').unlink()
                root.rmdir()

    def test_reaped_fixture_is_removed_but_rebound_root_is_not_adopted(self):
        with reader.disposable_root(lambda: True) as root:
            (root / 'owned').write_bytes(b'owned')
        self.assertFalse(root.exists())
        moved = None
        try:
            with self.assertRaises(reader.Refused):
                with reader.disposable_root(lambda: True) as root:
                    moved = root.with_name(root.name + '-test-rebound')
                    root.rename(moved)
                    root.mkdir(mode=0o700)
            self.assertTrue(root.exists())
            self.assertTrue(moved.exists())
        finally:
            if moved is not None:
                root.rmdir()
                moved.rmdir()


class TerminalFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name).resolve()
        for name in ('ledger', 'sessions', 'instances', 'admission'):
            (self.state / name).mkdir(mode=0o700)
        self.core = self.state / 'ledger/old.json'
        self.session = self.state / 'sessions/session.json'
        self.core_value = {'version': 1, 'record': {'id': 'old', 'state': 'DESTROYED'}}
        self.session_value = {'version': 1, 'record': {'id': 'session', 'state': 'CLOSED',
            'revision': 2, 'attempts': [{'key_hash': 'old'}, {'key_hash': 'new'}], 'updated_at': 'forward'}}
        self.write(self.core, self.core_value)
        self.write(self.session, self.session_value)
        self.write(self.state / 'admission/state.json', {'revision': 4, 'mode': 'drained'})
        (self.state / 'admission.identity').write_bytes(b'original-identity')

    def write(self, path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def test_only_session_updated_at_may_advance_on_reader_restart(self):
        previous = reader.terminal_snapshot(self.state)
        self.session_value['record']['updated_at'] = 'later'
        self.write(self.session, self.session_value)
        reader.preserved(previous, reader.terminal_snapshot(self.state))
        self.session_value['record']['attempts'][1]['key_hash'] = 'rewound'
        self.write(self.session, self.session_value)
        with self.assertRaises(reader.Refused):
            reader.preserved(previous, reader.terminal_snapshot(self.state))

    def test_nonterminal_core_session_or_workspace_refuses(self):
        self.core_value['record']['state'] = 'READY'
        self.write(self.core, self.core_value)
        with self.assertRaises(reader.Refused):
            reader.terminal_snapshot(self.state)
        self.core_value['record']['state'] = 'DESTROYED'
        self.write(self.core, self.core_value)
        self.session_value['record']['state'] = 'ACTIVE'
        self.write(self.session, self.session_value)
        with self.assertRaises(reader.Refused):
            reader.terminal_snapshot(self.state)
        self.session_value['record']['state'] = 'CLOSED'
        self.write(self.session, self.session_value)
        (self.state / 'instances/unknown').mkdir()
        with self.assertRaises(reader.Refused):
            reader.terminal_snapshot(self.state)

    def test_unknown_or_symlink_inventory_is_not_silently_ignored(self):
        extra = self.state / 'ledger/.record-pending'
        extra.write_bytes(b'incomplete')
        with self.assertRaises(reader.Refused):
            reader.terminal_snapshot(self.state)
        extra.unlink()
        alias = self.state / 'ledger/alias.json'
        alias.symlink_to(self.core)
        with self.assertRaises(reader.Refused):
            reader.terminal_snapshot(self.state)

    def test_size_count_and_permission_bounds_are_real_inputs(self):
        self.core.chmod(0o644)
        with self.assertRaises(reader.Refused):
            reader.terminal_snapshot(self.state)
        self.core.chmod(0o600)
        self.core.write_bytes(b'x' * ((128 << 10) + 1))
        with self.assertRaises(reader.Refused):
            reader.terminal_snapshot(self.state)
        self.write(self.core, self.core_value)
        with self.assertRaises(reader.Refused):
            list(reader.private_rows(self.state / 'ledger', 0))


if __name__ == '__main__':
    unittest.main()
