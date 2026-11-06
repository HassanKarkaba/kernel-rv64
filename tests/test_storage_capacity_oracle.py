"""Reject incomplete or altered host records; synthetic rows are not execution proof."""
import copy,json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import storage_capacity_test as oracle

class StorageCapacityOracle(unittest.TestCase):
    def rows(self):
        result=[{'event':'start'}]
        for name,(value,count) in oracle.EXPECTED.items():result.extend({'event':'check','name':name,'actual':value,'expected':value} for _ in range(count))
        for name in ['baseline','before_full','after_full','final']:
            counts=[0]*12;counts[4]=6 if name in ['before_full','after_full'] else 3;counts[7]=counts[8]=3 if name in ['before_full','after_full'] else 0
            result.append({'event':'owners','name':name,'counts':counts})
        result.append({'event':'result','result':'PASS','error':0})
        self.number(result);return result
    def number(self,rows):
        for sequence,row in enumerate(rows,1):row.update(schema=1,case_id='storage-capacity',run_id='1'*32,boot_id='2'*32,sequence=sequence)
    def parse(self,rows):return oracle.analyze(b''.join(b'KTEST '+json.dumps(row).encode()+b'\n' for row in rows),'1'*32,'2'*32,True)
    def test_complete_fixed_matrix(self):self.parse(self.rows())
    def test_cannot_omit_indirect_boundary_write(self):
        rows=self.rows();rows.remove(next(r for r in rows if r.get('name')=='direct_indirect_write'));self.number(rows)
        with self.assertRaisesRegex(ValueError,'matrix incomplete'):self.parse(rows)
    def test_cannot_change_enospc_expectation(self):
        rows=self.rows();row=next(r for r in rows if r.get('name')=='growth_needs_data');row.update(actual=0,expected=0)
        with self.assertRaisesRegex(ValueError,'independent syscall'):self.parse(rows)
    def test_cannot_hide_open_description_leak(self):
        rows=self.rows();row=next(r for r in rows if r.get('event')=='owners' and r['name']=='final');row['counts'][7]=1
        with self.assertRaisesRegex(ValueError,'owner census changed'):self.parse(rows)
    def test_duplicate_owner_name_is_rejected(self):
        rows=self.rows();rows.insert(-1,copy.deepcopy(next(r for r in rows if r.get('event')=='owners')));self.number(rows)
        with self.assertRaisesRegex(ValueError,'duplicate owner'):self.parse(rows)
    def test_cannot_remove_final_line_terminator(self):
        serial=b''.join(b'KTEST '+json.dumps(row).encode()+b'\n' for row in self.rows()).rstrip(b'\n')
        with self.assertRaisesRegex(ValueError,'unterminated'):oracle.analyze(serial,'1'*32,'2'*32,True)
if __name__=='__main__':unittest.main()
