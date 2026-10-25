"""Pure report-validation models, not node/KVM acceptance."""
import copy
import unittest
from doctor_smoke import CHECKS, CODES, DEFERRED, IDS, validate


def model():
    return {'version': 1, 'profile': 'systemd-install-v1', 'os': 'linux', 'architecture': 'amd64',
            'required_systemd_major': 254, 'observed_systemd_major': 255, 'basic_prerequisites_met': True,
            'checks': [{'id': name, 'status': 'pass', 'code': CHECKS[name]['pass']} for name in IDS],
            'missing_controllers': [], 'deferred_checks': list(DEFERRED), 'read_only': True,
            'vm_created': False, 'isolation_validated': False, 'production_ready': False}


class DoctorValidationTests(unittest.TestCase):
    def test_complete_model_never_claims_vm_or_production(self):
        validate(model(), 0)
        for field in ('vm_created', 'isolation_validated', 'production_ready'):
            bad = model()
            bad[field] = True
            with self.assertRaises(AssertionError):
                validate(bad, 0)

    def test_failure_or_unknown_cannot_return_success(self):
        for status in ('fail', 'unknown'):
            v = model()
            v['checks'][3]['status'] = status
            v['checks'][3]['code'] = CHECKS['systemd_version'][status]
            v['basic_prerequisites_met'] = False
            validate(v, 1)
            with self.assertRaises(AssertionError):
                validate(v, 0)
            v['basic_prerequisites_met'] = True
            with self.assertRaises(AssertionError):
                validate(v, 0)

    def test_closed_shape_primitives_codes_and_controller_names(self):
        for field, value in [('version', True), ('required_systemd_major', True), ('observed_systemd_major', True),
                             ('read_only', False), ('missing_controllers', ['PRIVATE_NAME']),
                             ('missing_controllers', ['io', 'io']), ('profile', 'arbitrary'), ('os', 'PRIVATE_HOST'),
                             ('deferred_checks', []), ('extra', 'PRIVATE_PATH')]:
            v = model()
            v[field] = value
            with self.assertRaises(AssertionError):
                validate(v, 0)
        for field, value in [('status', 'ready'), ('code', 'PRIVATE_ERROR')]:
            v = model()
            v['checks'][0][field] = value
            with self.assertRaises(AssertionError):
                validate(v, 0)
        self.assertTrue(CODES)

    def test_architecture_and_old_version_do_not_pass_basic_success(self):
        for field, value in [('architecture', 'arm64'), ('os', 'darwin'), ('observed_systemd_major', 249)]:
            v = copy.deepcopy(model())
            v[field] = value
            with self.assertRaises(AssertionError):
                validate(v, 0)
