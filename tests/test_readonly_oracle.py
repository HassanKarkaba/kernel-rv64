"""Synthetic records test rejection logic only; they never qualify a guest."""
import copy,json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import readonly_test as oracle

class ReadonlyOracle(unittest.TestCase):
    def fixture(self,mode=b'M',instrumented=True):
        rows=[dict(event='start')]
        rows += [dict(event='check',name=name,actual=value,expected=value) for name,value in oracle.expected_checks(mode).items()]
        if instrumented:
            rows += [dict(event='owners',name=name,counts=[0]*12) for name in ['baseline','before_denied','after_denied','final']]
        rows += [dict(event='result',result='PASS',error=0)]
        for sequence,row in enumerate(rows,1):row.update(schema=1,run_id='1'*32,boot_id='2'*32,case_id='readonly-open',sequence=sequence)
        return rows
    def parse(self,rows,mode=b'M',instrumented=True):
        prefix=b'KTEST ' if instrumented else b'ROTEST '
        return oracle.records(b''.join(prefix+json.dumps(row).encode()+b'\n' for row in rows),'1'*32,'2'*32,instrumented,mode)
    def test_all_named_mode_matrices(self):
        for mode in (b'M',b'T',b'F'):
            for instrumented in (False,True):self.parse(self.fixture(mode,instrumented),mode,instrumented)
    def test_missing_required_case_is_rejected(self):
        rows=self.fixture();rows=[row for row in rows if row.get('name')!='create_missing']
        for i,row in enumerate(rows,1):row['sequence']=i
        with self.assertRaisesRegex(ValueError,'required case matrix'):self.parse(rows)
    def test_guest_cannot_change_expected_errno(self):
        rows=self.fixture();row=next(r for r in rows if r.get('name')=='write_existing');row.update(actual=0,expected=0)
        with self.assertRaisesRegex(ValueError,'independent expectation'):self.parse(rows)
    def test_stale_identity_truncated_and_duplicate_records_rejected(self):
        for mutate in ['identity','truncated','duplicate']:
            rows=copy.deepcopy(self.fixture())
            if mutate=='identity':rows[1]['run_id']='0'*32
            if mutate=='truncated':rows.pop()
            if mutate=='duplicate':rows.insert(2,copy.deepcopy(rows[1]))
            with self.assertRaises(ValueError):self.parse(rows)
    def test_release_cannot_claim_instrumented_census(self):
        with self.assertRaisesRegex(ValueError,'release execution unexpectedly'):self.parse(self.fixture(),instrumented=False)
    def test_duplicate_owner_name_is_rejected(self):
        rows=self.fixture();rows.insert(-1,copy.deepcopy(next(r for r in rows if r.get('event')=='owners')))
        for i,row in enumerate(rows,1):row['sequence']=i
        with self.assertRaisesRegex(ValueError,'duplicate owner'):self.parse(rows)
    def test_actual_mismatch_preserved_for_negative_control(self):
        rows=self.fixture();row=next(r for r in rows if r.get('name')=='write_existing');row['actual']=4;rows[-1]['result']='FAIL'
        _,checks,_=self.parse(rows);self.assertEqual(checks['write_existing']['actual'],4);self.assertEqual(checks['write_existing']['expected'],-30)

if __name__=='__main__':unittest.main()
