import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from bench import analyze, analyze_extended


def fixture(count):
    records = [dict(event="start", warmup_ms=1000, sample_ms=10000),
               dict(event="window", start_ticks=0, end_ticks=400, frequency=40, user_ticks=400)]
    for pid in range(1, count + 1):
        records.append(dict(event="worker", pid=pid, user_ticks=400 // count,
                            dispatches=40 // count, max_peer_gap=count - 1,
                            first_ordinal=pid, last_ordinal=40 - count + pid))
    for i in range(40):
        records.append(dict(event="dispatch", ordinal=i + 1, pid=i % count + 1, ticks=i * 10))
    records.append(dict(event="result", result="PASS"))
    for sequence, record in enumerate(records, 1):
        record.update(schema=1, run_id="a" * 32, boot_id="b" * 32, case_id=f"fairness-{count}", sequence=sequence)
    return records


def wire(records):
    return b"\n".join(b"KTEST " + json.dumps(r).encode() for r in records) + b"\n"


class FairnessOracle(unittest.TestCase):
    def test_round_robin_fixed_profiles(self):
        for count in [4, 8]:
            result, _ = analyze(wire(fixture(count)), count, "a" * 32, "b" * 32)
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["dispatch_count"], 40)

    def test_reported_pass_cannot_hide_unfair_cpu_share(self):
        records = fixture(4)
        records[2]["user_ticks"] = 10
        records[3]["user_ticks"] = 190
        with self.assertRaisesRegex(ValueError, "share"):
            analyze(wire(records), 4, "a" * 32, "b" * 32)


class ExtendedMeasurementOracle(unittest.TestCase):
    def frame(self, kind, body):
        records = [dict(event="start", kind=kind), *body, dict(event="result", result="PASS")]
        for i, record in enumerate(records, 1):
            record.update(schema=1, run_id="a" * 32, boot_id="b" * 32, case_id=kind, sequence=i)
        return wire(records)

    def test_wake_samples_are_recomputed_and_thresholded(self):
        config = dict(event="configuration", frequency=1000, required_samples=10000, peers=7, sleep_ms=10)
        samples = [dict(event="wake-sample", sample=i + 1, deadline_ticks=i * 100,
                        wake_ticks=i * 100 + 1, user_ticks=i * 100 + 21,
                        wake_latency_ticks=20, deadline_latency_ticks=21) for i in range(10000)]
        result, _ = analyze_extended(self.frame("wakeup", [config, *samples]), "wakeup", "a" * 32, "b" * 32)
        self.assertEqual(result["wake_p99_ms"], 20)
        samples[0]["wake_latency_ticks"] = 19
        with self.assertRaisesRegex(ValueError, "raw timestamps"):
            analyze_extended(self.frame("wakeup", [config, *samples]), "wakeup", "a" * 32, "b" * 32)

    def test_mask_histogram_and_maximum(self):
        measured = dict(event="masking", frequency=1000000, intervals=9, maximum_ticks=900,
                        location="scheduler.rs", line=10, start_ticks=1, end_ticks=10000)
        buckets = [dict(event="mask-bucket", bucket=i, count=9 if i == 3 else 0) for i in range(7)]
        result, _ = analyze_extended(self.frame("masking", [measured, *buckets]), "masking", "a" * 32, "b" * 32)
        self.assertEqual(result["maximum_ms"], .9)
        measured["maximum_ticks"] = 1001
        with self.assertRaisesRegex(ValueError, "one millisecond"):
            analyze_extended(self.frame("masking", [measured, *buckets]), "masking", "a" * 32, "b" * 32)

    def test_census_rejects_one_leaked_owner(self):
        body = ([dict(event="baseline", owner=i, count=i + 1) for i in range(12)] +
                [dict(event="progress", completed_cycles=i) for i in range(1000, 10001, 1000)] +
                [dict(event="final", owner=i, count=i + 1) for i in range(12)])
        result, _ = analyze_extended(self.frame("reclaim", body), "reclaim", "a" * 32, "b" * 32)
        self.assertEqual(result["completed_cycles"], 10000)
        body[-1]["count"] += 1
        with self.assertRaisesRegex(ValueError, "census"):
            analyze_extended(self.frame("reclaim", body), "reclaim", "a" * 32, "b" * 32)

    def test_reported_gap_cannot_hide_dispatch_reordering(self):
        records = fixture(4)
        records[6]["pid"] = 2
        with self.assertRaises(ValueError):
            analyze(wire(records), 4, "a" * 32, "b" * 32)

    def test_wrong_window_is_not_a_measurement(self):
        records = fixture(4)
        records[1]["end_ticks"] = 399
        with self.assertRaisesRegex(ValueError, "ten guest seconds"):
            analyze(wire(records), 4, "a" * 32, "b" * 32)
