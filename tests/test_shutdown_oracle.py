"""Synthetic frames exercise oracle rejections, never qualify a runtime kernel."""
import copy,json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import shutdown_test as oracle
class ShutdownOracle(unittest.TestCase):
    def fixture(self,mode='clean_drain'):
        instrumented=mode=='waiter_recheck';frequency=1000;start=100;deadline=5100
        rows=[dict(event='start'),dict(event='acknowledged',bytes=1,clock_ns=1),dict(event='participants',writer=258,waiter=259,peer=260,unauthorized_shutdown_denials=3),dict(event='phase',name='arm_active'),dict(event='phase',name='active_submitted'),dict(event='peer_progress',pipe_bytes=1,compute_iterations=100000)]
        if instrumented:rows += [dict(event='trace-header',count=2,lost=0,frequency=frequency),dict(event='trace',record=[1,50,3,258,4]),dict(event='trace',record=[2,60,3,259,1])]
        else:rows += [dict(event='trace-unavailable')]
        rows += [dict(event='phase',name='shutdown_ready'),dict(event='request',clock_ns=100,observer=instrumented)]
        for seq,row in enumerate(rows,1):row.update(schema=1,case_id='shutdown-drain',run_id='1'*32,boot_id='2'*32,sequence=seq)
        logs=[dict(event='SHUTDOWN_BEGIN',timestamp=start+1,pid=257,transaction=deadline)]
        if instrumented:logs += [dict(event='SHUTDOWN_OBSERVER_WAIT',timestamp=start+2,pid=257,transaction=0),dict(event='SHUTDOWN_WAITER_RECHECK',timestamp=start+3,pid=259,transaction=0)]
        logs += [dict(event='SHUTDOWN_UNCERTAIN' if mode=='deadline_final_flush' else 'SHUTDOWN_CLEAN',timestamp=deadline+1 if mode=='deadline_final_flush' else start+20,pid=257,transaction=deadline if mode=='deadline_final_flush' else 0)]
        return rows,logs
    def parse(self,rows,logs,mode='clean_drain'):
        prefix=b'KTEST ' if mode=='waiter_recheck' else b'SDTEST '
        serial=b''.join(prefix+json.dumps(r).encode()+b'\n' for r in rows)+b''.join(b'KLOG '+json.dumps(r).encode()+b'\n' for r in logs)
        return oracle.analyze(serial,'1'*32,'2'*32,mode=='waiter_recheck',mode,1000)
    def test_named_cases(self):
        for mode in ['clean_drain','waiter_recheck','deadline_final_flush']:self.parse(*self.fixture(mode),mode)
    def test_device_error_is_not_global_deadline_counterexample(self):
        rows,logs=self.fixture('deadline_final_flush');logs[-1]['transaction']=0
        with self.assertRaisesRegex(ValueError,'global watchdog'):self.parse(rows,logs,'deadline_final_flush')
    def test_excessively_late_uncertain_observation_is_rejected(self):
        rows,logs=self.fixture('deadline_final_flush');logs[-1]['timestamp']=5103
        with self.assertRaisesRegex(ValueError,'2ms cadence/masking bound'):self.parse(rows,logs,'deadline_final_flush')
    def test_wrong_waiter_cannot_qualify_recheck(self):
        rows,logs=self.fixture('waiter_recheck');logs[-2]['pid']=258
        with self.assertRaisesRegex(ValueError,'expected admitted waiter'):self.parse(rows,logs,'waiter_recheck')
    def test_waiter_must_have_blocked_on_fs_before_shutdown(self):
        rows,logs=self.fixture('waiter_recheck');next(r for r in rows if r.get('record',[0,0,0,0,0])[3]==259)['record'][4]=4
        with self.assertRaisesRegex(ValueError,'blocked on filesystem'):self.parse(rows,logs,'waiter_recheck')
    def test_missing_pipe_peer_observation_is_rejected(self):
        rows,logs=self.fixture();next(r for r in rows if r['event']=='peer_progress')['pipe_bytes']=0
        with self.assertRaisesRegex(ValueError,'pipe/compute'):self.parse(rows,logs)
    def test_late_clean_shutdown_is_rejected(self):
        rows,logs=self.fixture();logs[-1]['timestamp']=5101
        with self.assertRaisesRegex(ValueError,'inside the deadline'):self.parse(rows,logs)
if __name__=='__main__':unittest.main()
