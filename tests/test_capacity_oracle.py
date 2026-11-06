import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from capacity_test import analyze


class CapacityOracle(unittest.TestCase):
    def records(self):
        records=[]
        def emit(event,**fields):records.append(dict(schema=1,run_id='a'*32,boot_id='b'*32,case_id='global-capacity',sequence=len(records)+1,event=event,**fields))
        emit('start')
        baseline=[21,10,10000,1,3,0,21,0,0,0,0,0]
        for index,kind in enumerate(('memory','files','pipes')):
            for owner,count in enumerate(baseline):emit('baseline',kind=kind,owner=owner,count=count)
            counts={'memory':[4077]*7+[4035,0],'files':[30]*8+[16],'pipes':[15]*3+[1]+[0]*5}[kind]
            for worker,count in enumerate(counts):
                local=30 if kind=='files' else 15
                error=-12 if kind=='memory' else -24 if count==local else -23
                emit('worker',kind=kind,worker=worker,pid=258+index*256+worker,allocated=count,error=error,initial_pages=19,page_allowance=4077)
            peak=baseline.copy();peak[0]=32766 if kind=='memory' else 192;peak[3]=10
            peak[4]=39+(sum(counts) if kind=='files' else sum(counts)*2 if kind=='pipes' else 0)
            peak[7]=peak[8]=256 if kind=='files' else 0
            peak[9]=peak[10]=peak[11]=64 if kind=='pipes' else 18
            for owner,count in enumerate(peak):emit('peak',kind=kind,owner=owner,count=count)
            if kind=='memory':emit('pool',total=32768,reserved=2,live=32766,free=0)
            for owner,count in enumerate(baseline):emit('final',kind=kind,owner=owner,count=count)
            emit('family-result',kind=kind,result='PASS',retry=True)
        emit('result',result='PASS',error=0)
        return records
    def parse(self,records):
        return analyze(b'\n'.join(b'KTEST '+json.dumps(r).encode() for r in records)+b'\n','a'*32,'b'*32)
    def test_valid_all_families(self):self.assertEqual(len(self.parse(self.records())[0]),3)
    def test_missing_resource_or_owner_leak_rejected(self):
        for event,kind,owner in [('peak','files',7),('peak','pipes',9),('final','memory',1)]:
            records=self.records();target=next(r for r in records if r['event']==event and r.get('kind')==kind and r.get('owner')==owner);target['count']+=1
            with self.assertRaises(ValueError):self.parse(records)
    def test_unused_global_pages_rejected(self):
        records=self.records();next(r for r in records if r['event']=='pool')['free']=1
        with self.assertRaises(ValueError):self.parse(records)
    def test_wrong_errno_or_identity_rejected(self):
        records=self.records();next(r for r in records if r['event']=='worker')['error']=-24
        with self.assertRaises(ValueError):self.parse(records)
        records=self.records();records[1]['boot_id']='c'*32
        with self.assertRaises(ValueError):self.parse(records)


if __name__=='__main__':unittest.main()
