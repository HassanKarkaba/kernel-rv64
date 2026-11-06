#!/usr/bin/env python3
"""Actual shutdown admission/drain, waiter recheck and five-second final-flush deadline.

The waiter case names a declared init-only observation hook; other cases use
ordinary release behavior. NBD gates hold real requests and never edit guest RAM.
"""
import argparse,hashlib,io,json,os,shutil,socket,struct,tempfile,threading,uuid
from pathlib import Path
import fsck,mkfs,nbd_fault as nbd
from accept import source_identity
from crash_test import NbdGuest,sparse_output,logical
from doctor import probe,sha256
from guest_test import build
from protocol import trusted_records
from readonly_test import ObservedStore,copy_source
from recovery_test import nbd_boot

class GatedStore(ObservedStore):
    def __init__(self,initial,trace,deadline):
        super().__init__(initial,trace);self.gated=False;self.base_flushes=0;self.deadline=deadline
        self.home_held=threading.Event();self.home_release=threading.Event();self.final_held=threading.Event();self.final_release=threading.Event()
    def enable(self):self.base_flushes=self.counts['flushes'];self.gated=True
    def write(self,offset,data):
        if self.gated and offset>=19*4096 and not self.home_held.is_set():
            if offset!=19*4096:raise AssertionError('first home write is not allocation block')
            self.trace.emit('shutdown_home_request_held',offset=offset);self.home_held.set()
            if not self.home_release.wait(30):raise RuntimeError('host home-request gate watchdog')
        return super().write(offset,data)
    def flush(self):
        relative=self.counts['flushes']+1-self.base_flushes
        if self.gated and self.deadline and relative==6 and not self.final_held.is_set():
            self.trace.emit('shutdown_final_flush_held',relative_flush=relative);self.final_held.set()
            if not self.final_release.wait(30):raise RuntimeError('host final-flush gate watchdog')
        return super().flush()

def timebase(path):
    data=path.read_bytes();magic,total,off_struct,off_strings,_,_,_,_,size_strings,size_struct=struct.unpack_from('>10I',data)
    if magic!=0xd00dfeed or total!=len(data):raise ValueError('invalid recorded DTB')
    strings=data[off_strings:off_strings+size_strings];cursor=off_struct;limit=off_struct+size_struct;values=[]
    while cursor<limit:
        token=struct.unpack_from('>I',data,cursor)[0];cursor+=4
        if token==1:
            cursor=data.index(0,cursor)+1;cursor=(cursor+3)&~3
        elif token==3:
            length,nameoff=struct.unpack_from('>II',data,cursor);cursor+=8;name=strings[nameoff:strings.index(0,nameoff)]
            if name==b'timebase-frequency':
                if length not in (4,8):raise ValueError('unsupported timebase width')
                values.append(int.from_bytes(data[cursor:cursor+length],'big'))
            cursor=(cursor+length+3)&~3
        elif token==9:break
        elif token not in (2,4):raise ValueError('invalid DTB token')
    if len(values)!=1 or values[0]<=0:raise ValueError('missing/ambiguous timebase')
    return values[0]

def analyze(serial,run_id,boot_id,instrumented,mode,frequency):
    normalized=serial if instrumented else b'\n'.join(b'KTEST '+line[7:] if line.startswith(b'SDTEST ') else b'' for line in serial.split(b'\n'))
    rows=trusted_records(normalized)
    for sequence,row in enumerate(rows,1):
        expected={'schema':1,'case_id':'shutdown-drain','run_id':run_id,'boot_id':boot_id,'sequence':sequence}
        if any(row.get(k)!=v for k,v in expected.items()):raise ValueError('invalid immutable-init record identity/order')
    events=[r.get('event') for r in rows]
    if not rows or events[0]!='start' or events[-1]!='request' or 'check' in events:raise ValueError('init failed or shutdown returned unexpectedly')
    def single(event):
        found=[r for r in rows if r.get('event')==event]
        if len(found)!=1:raise ValueError('missing/duplicate '+event)
        return found[0]
    participants=single('participants');peer=single('peer_progress');ack=single('acknowledged');request=single('request')
    if participants.get('unauthorized_shutdown_denials')!=3 or peer.get('pipe_bytes')!=1 or peer.get('compute_iterations')!=100000 or ack.get('bytes')!=1:raise ValueError('pre-shutdown capability/pipe/compute/ack cases incomplete')
    ids=[participants.get(k) for k in ['writer','waiter','peer']]
    if len(set(ids))!=3 or any(type(x)is not int or x<=257 for x in ids):raise ValueError('invalid participant PIDs')
    if request.get('observer')!=(mode=='waiter_recheck'):raise ValueError('incorrect observation domain')
    phases=[r.get('name') for r in rows if r.get('event')=='phase']
    if phases!=['arm_active','active_submitted','shutdown_ready']:raise ValueError('missing shutdown synchronization phases')
    if instrumented:
        header=single('trace-header');trace=[r['record'] for r in rows if r.get('event')=='trace']
        if header.get('frequency')!=frequency or header.get('lost')!=0 or header.get('count')!=len(trace):raise ValueError('trace coverage/clock mismatch')
        for sequence,row in enumerate(trace,1):
            if len(row)!=5 or row[0]!=sequence:raise ValueError('malformed trace')
        if not any(row[2:]==[3,participants['writer'],4] for row in trace):raise ValueError('writer was not observed blocked on real I/O')
        if not any(row[2:]==[3,participants['waiter'],1] for row in trace):raise ValueError('waiter was not admitted and blocked on filesystem ownership')
    elif 'trace-header' in events:raise ValueError('release falsely claims private trace')
    logs=trusted_records(b'\n'.join(b'KTEST '+line[5:] if line.startswith(b'KLOG ') else b'' for line in serial.split(b'\n')))
    if any(type(row.get(key)) is not int or row[key]<0 for row in logs for key in ['timestamp','pid','transaction']):raise ValueError('invalid kernel diagnostic scalars')
    begins=[r for r in logs if r.get('event')=='SHUTDOWN_BEGIN'];ends=[r for r in logs if r.get('event') in ['SHUTDOWN_CLEAN','SHUTDOWN_UNCERTAIN']]
    if len(begins)!=1 or len(ends)!=1:raise ValueError('missing/duplicate shutdown disposition')
    begin,end=begins[0],ends[0];deadline=begin['transaction'];start=deadline-5*frequency
    if begin['pid']!=257 or begin['timestamp']<start or end['timestamp']<begin['timestamp']:raise ValueError('invalid shutdown timestamps')
    if mode=='deadline_final_flush':
        if end['event']!='SHUTDOWN_UNCERTAIN' or end['transaction']!=deadline or end['timestamp']<deadline:raise ValueError('five-second global watchdog did not fire for its declared deadline')
        # The published deadline remains exactly five seconds. Observation is
        # bounded by the declared1ms timer poll plus the contract's <=1ms
        # masked interval; timestamp is sampled before KLOG serialization.
        if (end['timestamp']-deadline)*1000>2*frequency:raise ValueError('global watchdog observation exceeds the2ms cadence/masking bound')
    elif end['event']!='SHUTDOWN_CLEAN' or end['timestamp']>=deadline:raise ValueError('active transaction did not drain cleanly inside the deadline')
    rechecks=[r for r in logs if r.get('event')=='SHUTDOWN_WAITER_RECHECK']
    if mode=='waiter_recheck':
        waits=[r for r in logs if r.get('event')=='SHUTDOWN_OBSERVER_WAIT']
        if len(waits)!=1 or waits[0]['pid']!=257 or not begin['timestamp']<=waits[0]['timestamp']<end['timestamp']:raise ValueError('declared observer substitution was not observed')
        if len(rechecks)!=1 or rechecks[0]['pid']!=participants['waiter'] or not begin['timestamp']<=rechecks[0]['timestamp']<end['timestamp']:raise ValueError('expected admitted waiter did not acquire and recheck the shutdown flag')
    return rows,logs,{'participants':participants,'frequency':frequency,'start_ticks':start,'deadline_ticks':deadline,'disposition_ticks':end['timestamp'],'drain_guest_nanoseconds':(end['timestamp']-start)*1_000_000_000//frequency,'deadline_observation_lateness_ticks':max(0,end['timestamp']-deadline),'deadline_observation_bound_nanoseconds':2_000_000,'deadline_observation_bound_basis':'1ms timer poll plus required<=1ms interrupt mask; deadline itself stays5s; diagnostic timestamp is captured before serialization, without host-time correction','disposition':end['event'],'waiter_recheck_observed':bool(rechecks)}

def check_state(initial,actual):
    originals={r['name']:r for r in initial['files']};files={r['name']:r for r in actual['files']}
    if files.keys()!=originals.keys() or actual['sequence']!=2:raise AssertionError('shutdown admitted extra/missing mutation')
    for name,value in files.items():
        expected=originals[name].copy()
        if name in ['/ack','/active']:
            data=b'K' if name=='/ack' else b'A';expected.update(size=1,sha256=hashlib.sha256(data).hexdigest())
        if any(value[key]!=expected[key] for key in ['inode','generation','size','sha256']):raise AssertionError('shutdown independent model mismatch '+name)

def one(args,initial,kernel,normal,firmware,directory,mode,run_id,boot_id):
    directory.mkdir();instrumented=mode=='waiter_recheck';record={'schema':1,'status':'INCOMPLETE','mode':mode,'instrumented':instrumented,'kernel_sha256':sha256(kernel)};guest=None;store=None;errors=[]
    try:
        with tempfile.TemporaryDirectory(prefix='krv-shutdown-') as tmp,(directory/'nbd.jsonl').open('x') as log:
            store=GatedStore(initial,nbd.Trace(log),mode=='deadline_final_flush');path=Path(tmp)/'disk.sock'
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
                listener.bind(str(path));listener.listen(1);listener.settimeout(60)
                def serve():
                    try:
                        connection,_=listener.accept()
                        with connection:connection.settimeout(35);nbd.session(connection,store)
                    except (EOFError,BrokenPipeError,ConnectionResetError):pass
                    except Exception as error:errors.append(str(error))
                thread=threading.Thread(target=serve,daemon=True);thread.start();guest=NbdGuest(args.qemu,kernel,firmware,path,directory/'guest')
                def phase(name):guest.expect(b'"event":"phase","name":"'+name.encode()+b'"}\\r?\\n')
                def send(value=b'g'):guest.child.stdin.write(value);guest.child.stdin.flush()
                guest.expect(rb'(?:^|\n)READY\r?\n');guest.expect(rb'"event":"start"}\r?\n');send({'clean_drain':b'C','waiter_recheck':b'W','deadline_final_flush':b'D'}[mode])
                phase('arm_active');store.enable();send();phase('active_submitted')
                if not store.home_held.wait(10):raise AssertionError('active committed transaction did not reach gated home write')
                committed,_=store.outcome('none');sparse_output(directory/'held-commit.img',committed);held=fsck.inspect(directory/'held-commit.img')
                if not held['needs_replay']:raise AssertionError('held request was not a committed partial checkpoint')
                send();phase('shutdown_ready');send();guest.expect(rb'KLOG [^\n]*"event":"SHUTDOWN_BEGIN"[^\n]*\n');store.home_release.set()
                if mode=='deadline_final_flush':
                    if not store.final_held.wait(10):raise AssertionError('final exclusive flush was not reached')
                    guest.expect(rb'KLOG [^\n]*"event":"SHUTDOWN_UNCERTAIN"[^\n]*\n',timeout=15);store.final_release.set()
                guest.wait_for_shutdown(30);serial=bytes(guest.data);guest=None;thread.join(5)
                if thread.is_alive() or errors:raise RuntimeError('backend shutdown failed '+repr(errors))
            final,_=store.outcome('none');sparse_output(directory/'shutdown.img',final);state=fsck.inspect(directory/'shutdown.img');check_state(fsck.Image(io.BytesIO(initial)).inspect(),state)
            frequency=timebase(directory/'guest/machine.dtb');rows,logs,timing=analyze(serial,run_id,boot_id,instrumented,mode,frequency)
            (directory/'raw-records.json').write_text(json.dumps(rows,indent=2)+'\n');(directory/'kernel-diagnostics.json').write_text(json.dumps(logs,indent=2)+'\n');(directory/'fsck.json').write_text(json.dumps(state,indent=2)+'\n')
        recovered,_=nbd_boot(args,final,normal,firmware,directory/'reboot');recovered_state=fsck.Image(io.BytesIO(recovered)).inspect();
        if recovered_state['needs_replay'] or logical(recovered_state)!=logical(state):raise AssertionError('normal guest reboot failed independent shutdown state oracle')
        record.update(status='PASS',timing=timing,initial_sha256=hashlib.sha256(initial).hexdigest(),shutdown_sha256=sha256(directory/'shutdown.img'),recovered_sha256=hashlib.sha256(recovered).hexdigest(),held_committed_checkpoint=True,active_transaction_drained=True,waiter_file_unchanged=True,acknowledged_write_preserved=True,actual_reboot=True,normal_reboot_kernel_sha256=sha256(normal))
    except Exception as error:record.update(status='INCOMPLETE' if isinstance(error,TimeoutError) else 'FAIL',reason=str(error))
    finally:
        if store:store.home_release.set();store.final_release.set()
        if guest:guest.close()
        (directory/'case-report.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record),flush=True)
    if record['status']!='PASS':raise RuntimeError(record.get('reason'))
    return record

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path);p.add_argument('--qemu',default='qemu-system-riscv64');p.add_argument('--firmware',type=Path,default=Path('build/fw_dynamic.bin'));p.add_argument('--cargo',default='cargo');args=p.parse_args();root=Path(__file__).resolve().parents[1];output=args.output.resolve()
    if output.is_relative_to(root):p.error('evidence must be outside source')
    output.mkdir(parents=True,exist_ok=False);report={'schema':1,'status':'INCOMPLETE','scope':__doc__,'cases':[]};run_id=uuid.uuid4().hex;boot_id=uuid.uuid4().hex
    try:
        snapshot=output/'candidate-source';report.update(source_identity=copy_source(root,snapshot),run_id=run_id,boot_id=boot_id)
        qemu=probe('qemu-system-riscv64',args.qemu);report['qemu']=qemu
        if qemu['status']!='MATCH':raise RuntimeError('pinned QEMU11.1.3 required')
        args.qemu=qemu['path'];firmware=output/'fw_dynamic.bin';shutil.copyfile(args.firmware.resolve(strict=True),firmware);report['firmware_sha256']=sha256(firmware)
        env=os.environ.copy();env.update(KERNEL_TEST_RUN_ID=run_id,KERNEL_TEST_BOOT_ID=boot_id,CARGO_TARGET_DIR=str(output/'user-target'),SOURCE_DATE_EPOCH='1793923200')
        command=[args.cargo,'build','--locked','--offline','--release','-p','user-programs','--target','riscv64imac-unknown-none-elf','--bin','shutdown-init','--bin','shutdown-worker','--bin','init'];build('build-user',command,snapshot,output,env);report['build_commands']=[command];programs=output/'user-target/riscv64imac-unknown-none-elf/release';report['program_sha256']={name:sha256(programs/name) for name in ['shutdown-init','shutdown-worker','init']}
        kernels={}
        for label in ['release','instrumented','normal']:
            env.update(CARGO_TARGET_DIR=str(output/(label+'-target')),KERNEL_INIT_ELF=str(programs/('init' if label=='normal' else 'shutdown-init')));command=[args.cargo,'build','--locked','--offline','--release','-p','kernel','--target','riscv64imac-unknown-none-elf']+(['--features','instrumented'] if label=='instrumented' else []);build('build-'+label,command,snapshot,output,env);report['build_commands'].append(command);kernels[label]=output/(label+'-target/riscv64imac-unknown-none-elf/release/kernel')
        empty=output/'empty';empty.write_bytes(b'');path=output/'initial.img';mkfs.create(path,uuid.UUID(run_id).bytes,[('/shutdown-worker',programs/'shutdown-worker'),('/ack',empty),('/active',empty),('/waiter',empty)]);initial=path.read_bytes()
        for mode in ['clean_drain','waiter_recheck','deadline_final_flush']:report['cases'].append(one(args,initial,kernels['instrumented' if mode=='waiter_recheck' else 'release'],kernels['normal'],firmware,output/mode,mode,run_id,boot_id))
        if source_identity(snapshot)!=report['source_identity']:raise RuntimeError('frozen source snapshot changed')
        report.update(status='PASS',source_snapshot_unchanged=True,original_tree_still_matches=source_identity(root)==report['source_identity'])
    except Exception as error:report.update(status='INCOMPLETE' if isinstance(error,TimeoutError) else 'FAIL',reason=str(error))
    (output/'shutdown-report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='cases'},indent=2));return 0 if report['status']=='PASS' else 2

if __name__=='__main__':raise SystemExit(main())
