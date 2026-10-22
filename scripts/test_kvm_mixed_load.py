import unittest

from kvm_mixed_load import gauges, overlaps, summarize, workload


class MixedProbeTests(unittest.TestCase):
    def test_gauges_do_not_accept_absence_negative_or_duplicate(self):
        text = '\n'.join('xandbox_' + k + ' 0' for k in
                         ('allocated', 'stop_queued', 'cleanup_queued', 'stop_running', 'cleanup_running'))
        self.assertEqual(gauges(text)['allocated'], 0)
        for invalid in ('', text.replace('allocated 0', 'allocated -1'), text + '\nxandbox_allocated 1'):
            with self.assertRaises(ValueError):
                gauges(invalid)

    def test_quantiles_are_nearest_rank_not_interpolation(self):
        self.assertEqual(summarize([{'x': 1}, {'x': 10}, {'x': 20}], ('x',))['x'],
                         {'count': 3, 'p50': 10, 'p95': 20, 'p99': 20, 'p100': 20})

    def test_overlap_excludes_adjacent_intervals(self):
        a = [{'switch_start_ms': 1, 'switch_end_ms': 3}]
        b = [{'switch_start_ms': 3, 'switch_end_ms': 4}, {'switch_start_ms': 2, 'switch_end_ms': 4}]
        self.assertEqual(overlaps(a, b, 'switch'), 1)

    def test_fixed_workloads_are_argv_only(self):
        for tenant in ('alpha', 'beta'):
            value = workload(tenant)
            self.assertEqual(value[:2], ['sh', '-c'])
            self.assertIn('set -e;', value[2])
            self.assertIn('wc -c < /tmp/mixed-memory', value[2])
            self.assertNotIn('/srv/', value[2])
        self.assertNotEqual(workload('alpha'), workload('beta'))


if __name__ == '__main__':
    unittest.main()
