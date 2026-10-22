import unittest
from kvm_io_probe import parse_io_stat, parse_wchar


class IOStatTests(unittest.TestCase):
    def test_private_vmm_write_counter_must_be_explicit_unique_and_numeric(self):
        self.assertEqual(parse_wchar('rchar: 99\nwchar: 4194304\n'), 4194304)
        for raw in ('', 'rchar: 99', 'wchar: -1', 'wchar: 1\nwchar: 2'):
            with self.assertRaises(AssertionError): parse_wchar(raw)
    def test_no_activity_is_zero_not_borrowed_from_other_device(self):
        self.assertEqual(parse_io_stat('8:1 wbytes=32\n', '8:0'), dict.fromkeys(('rbytes', 'wbytes', 'rios', 'wios'), 0))

    def test_exact_device_and_known_fields_only(self):
        self.assertEqual(parse_io_stat('8:0 rbytes=10 wbytes=20 rios=1 wios=2 dbytes=9\n8:1 wbytes=999\n', '8:0'),
                         {'rbytes': 10, 'wbytes': 20, 'rios': 1, 'wios': 2})

    def test_malformed_or_duplicate_kernel_fields_fail(self):
        for raw in ('8:0 wbytes=1 wbytes=2', '8:0 wbytes=-1', '8:0 wbytes=1\n8:0 wbytes=2'):
            with self.assertRaises(AssertionError): parse_io_stat(raw, '8:0')


if __name__ == '__main__': unittest.main()
