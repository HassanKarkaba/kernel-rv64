"""Host oracle checks for the actual-kernel negative-control harness."""
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from kernel_mutations import analyze, NAMES


class MutationOracle(unittest.TestCase):
    def records(self, failed=None):
        common = dict(schema=1, run_id='a'*32, boot_id='b'*32, case_id='kernel-mutations')
        records = [dict(common, sequence=1, event='start')]
        for sequence, name in enumerate(NAMES, 2):
            records.append(dict(common, sequence=sequence, event='assertion', assertion=name,
                                result='FAIL' if name == failed else 'PASS', error=0))
        records.append(dict(common, sequence=6, event='result', result='FAIL' if failed else 'PASS'))
        return records

    def parse(self, records, failed=None):
        serial = b'\n'.join(b'KTEST ' + json.dumps(record).encode() for record in records) + b'\n'
        return analyze(serial, 'a'*32, 'b'*32, failed)

    def test_baseline_and_every_expected_mutation(self):
        for failed in [None, *NAMES]:
            self.parse(self.records(failed), failed)

    def test_undetected_mutation_never_passes(self):
        with self.assertRaises(ValueError):
            self.parse(self.records(), NAMES[0])

    def test_unrelated_failure_never_passes(self):
        with self.assertRaises(ValueError):
            self.parse(self.records(NAMES[1]), NAMES[0])

    def test_infrastructure_error_never_passes(self):
        records = self.records(NAMES[0])
        records[1]['error'] = -12
        with self.assertRaises(ValueError):
            self.parse(records, NAMES[0])

    def test_identity_or_missing_terminal_never_passes(self):
        records = self.records()
        records[1]['run_id'] = 'c'*32
        with self.assertRaises(ValueError):
            self.parse(records)
        with self.assertRaises(ValueError):
            self.parse(self.records()[:-1])


if __name__ == '__main__':
    unittest.main()
