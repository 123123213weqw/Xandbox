"""Generated fixtures only; no recorded console or runtime identity dependencies."""

import copy
import json
import unittest

from creation_cost_server import PHASES, validate_create_server
import creation_cost_trace_analyzer as analyzer
from test_creation_cost_profile import generated_normal_bytes
from test_creation_cost_trace_analyzer import packet, frames, abi


def generated_server():
    return {"status": "observed", "entries": [
        {"phase": phase, "ms": 0, "calls": 1} for phase in PHASES
    ]}


def generated_packet(scope="checkpoint"):
    value = packet()
    value["schema"] = 4
    value["scope"] = scope
    if scope == "cold":
        value["http_create_elapsed"] = [dict(
            ordinal=0, phase="cold-fresh", elapsed_ns=1_000_000, success=True
        )]
    for row in value["http_create_elapsed"]:
        row["server_timing"] = generated_server()
    return value


class ServerTests(unittest.TestCase):
    def test_legacy_three_retains_original_shape_and_reports_stage_unknown(self):
        value = packet()
        original = copy.deepcopy(value)
        result = analyzer.analyze(value)
        self.assertEqual(value, original)
        self.assertEqual(result["schema"], 3)
        self.assertFalse(result["server_creation_stage_observations_available"])
        self.assertTrue(all("server_timing" not in row for row in result["http_create_elapsed"]))

    def test_four_preserves_every_original_elapsed_and_fixed_stage_vector(self):
        for scope in ("checkpoint", "cold"):
            with self.subTest(scope=scope):
                value = generated_packet(scope)
                original = copy.deepcopy(value)
                result = analyzer.analyze_console(
                    frames(abi(value), analyzer.ABI_PREFIX) + frames(value, analyzer.PREFIX), scope
                )
                self.assertEqual(value, original)
                self.assertEqual(result["schema"], 4)
                self.assertTrue(result["server_creation_stage_observations_available"])
                self.assertEqual(result["http_create_elapsed"], value["http_create_elapsed"])
                self.assertTrue(result["server_spans_are_nested_and_not_pure_queue_or_physical_io"])
                self.assertTrue(result["no_per_create_kernel_clock_anchors_or_syscall_critical_path_attribution"])

    def test_four_unknown_or_uncalled_capture_not_promoted_to_successful_diagnostics(self):
        for status in ("not_observed", "no_response", "missing", "invalid", "other"):
            value = generated_packet()
            row = value["http_create_elapsed"][0]
            row["server_timing"] = {"status": status, "entries": []}
            with self.subTest(status=status), self.assertRaises(analyzer.InvalidObservation):
                analyzer.analyze(value)
            self.assertTrue(row["success"])  # Original API success is not rewritten.
            self.assertEqual(row["server_timing"]["status"], status)

    def test_schema_versions_never_silently_reinterpret_old_rows(self):
        cases = []
        value = generated_packet()
        value["schema"] = 3
        cases.append(value)
        value = generated_packet()
        del value["http_create_elapsed"][0]["server_timing"]
        cases.append(value)
        for version in (True, 3.0, 4.0, 2, 5, "4"):
            value = generated_packet()
            value["schema"] = version
            cases.append(value)
        for value in cases:
            with self.subTest(schema=value["schema"]), self.assertRaises(analyzer.InvalidObservation):
                analyzer.analyze(value)

    def test_closed_complete_ordered_entries_no_extra_names_or_identity(self):
        mutations = (
            lambda v: v["entries"].pop(),
            lambda v: v["entries"].reverse(),
            lambda v: v["entries"].append(v["entries"][0]),
            lambda v: v["entries"][1].update(phase=PHASES[0]),
            lambda v: v["entries"][0].update(phase="private-unrecognized"),
            lambda v: v["entries"][0].update(calls=2),
            lambda v: v["entries"][0].update(calls=True),
            lambda v: v["entries"][0].update(identity="generated-not-allowed"),
            lambda v: v.update(raw_header="generated-not-allowed"),
            lambda v: v.update(entries=None),
        )
        for i, mutate in enumerate(mutations):
            value = generated_packet()
            mutate(value["http_create_elapsed"][0]["server_timing"])
            with self.subTest(case=i), self.assertRaises(analyzer.InvalidObservation):
                analyzer.analyze(value)

    def test_nonfinite_bool_negative_and_out_of_bounds_duration_rejected(self):
        for ms in (True, "0.000", None, -0.001, float("nan"), float("inf"), 35001.001):
            value = generated_packet()
            value["http_create_elapsed"][0]["server_timing"]["entries"][0]["ms"] = ms
            with self.subTest(ms=ms), self.assertRaises(analyzer.InvalidObservation):
                analyzer.analyze(value)

    def test_known_nesting_rounding_consistency_is_not_clock_alignment(self):
        value = generated_server()
        value["entries"][2]["ms"] = 3
        value["entries"][4]["ms"] = 3.006
        validate_create_server(value, 3_000_000)
        value["entries"][4]["ms"] = 3.011
        with self.assertRaises(ValueError):
            validate_create_server(value, 10_000_000)
        value["entries"][4]["ms"] = 0
        with self.assertRaises(ValueError):
            validate_create_server(value, 1_000_000)
        for elapsed in (0, -1, True, 1.0):
            with self.subTest(elapsed=elapsed), self.assertRaises(ValueError):
                validate_create_server(value, elapsed)

    def test_new_vectors_keep_original_maximum_payload_and_frame_bounds(self):
        value = generated_packet()
        prefix = json.dumps(value).encode()
        data = prefix + b" " * ((1 << 20) - len(prefix))
        result = analyzer.analyze_console(generated_normal_bytes(value, data), "checkpoint", "maximum")
        self.assertEqual(result["normal_JSON_prefix_bytes"], len(prefix))
        self.assertEqual(result["explicit_synthetic_ASCII_whitespace_bytes"], (1 << 20) - len(prefix))
        with self.assertRaises(analyzer.InvalidObservation):
            analyzer.analyze_console(generated_normal_bytes(value, data), "checkpoint", "observe")

    def test_both_old_and_new_inline_failures_refuse_even_complete_normal(self):
        value = generated_packet()
        console = frames(abi(value), analyzer.ABI_PREFIX) + frames(value, analyzer.PREFIX)
        failed = {"schema": 2, "scope": "checkpoint", "valid_comparison": False,
                  "http_create_elapsed": value["http_create_elapsed"]}
        prefix = "XANDBOX_CREATION_COST_FAILED_CREATES_PRIVATE "
        for suffix in ((prefix + '{"schema":1}\n').encode(), (prefix + json.dumps(failed) + "\n").encode()):
            with self.subTest(size=len(suffix)), self.assertRaises(analyzer.InvalidObservation):
                analyzer.analyze_console(console + suffix, "checkpoint")


if __name__ == "__main__":
    unittest.main()
