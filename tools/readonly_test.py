#!/usr/bin/env python3
"""Actual syscall READ_ONLY/FAILED cases with release and instrumented kernels.

Mount valid sequence-exhaustion images; retain a writable descriptor across the
last successful transaction; compare block activity and owner counts. An isolated
negative control removes only the open admission check, must finish normally and
expose the WRITE-open/EROFS mismatch, then the fixed binary is rerun.
"""
import argparse, hashlib, json, os, shutil, socket, struct, tempfile, threading, uuid
from pathlib import Path
import fsck, mkfs, nbd_fault as nbd
from accept import source_identity
from crash_test import NbdGuest, sparse_output
from corruption_test import seal_region
from doctor import probe, sha256
from guest_test import build
from protocol import trusted_records

IGNORE={'.git','target','build','var','.venv','__pycache__','.pytest_cache','.DS_Store'}
MODES={'mount_max':b'M','exhaustion_transition':b'T','failed':b'F'}
PAYLOAD=b'abcdefghijklmnopqrstuvwxyz012345'
OPEN_CASES={'write_existing','readwrite_existing','create_read_existing','create_write_existing','create_missing','create_exclusive_existing','truncate_existing','truncate_empty'}

class ObservedStore(nbd.SectorStore):
    def __init__(self,initial,trace):
        super().__init__(initial,trace);self.counts={'reads':0,'writes':0,'flushes':0};self.arm=False;self.triggered=False
    def read(self,offset,length):
        self.counts['reads']+=1
        if self.arm:
            self.arm=False;self.triggered=True;self.trace.emit('readonly_backend_read_error',offset=offset,length=length);raise nbd.CommandError(5)
        return super().read(offset,length)
    def write(self,offset,data):self.counts['writes']+=1;return super().write(offset,data)
    def flush(self):self.counts['flushes']+=1;return super().flush()

def expected_checks(mode):
    expected={name:(-5 if mode==b'F' else -30) for name in OPEN_CASES}
    expected.update(initial_seek=0,invalid_flags_before_state=-22,invalid_path_before_state=-22,bad_pointer_before_state=-14,repeated_denials=300,denial_owner_counts=0,zero_read_invalid_pointer=0,zero_write_invalid_pointer=-9 if mode==b'M' else 0,close=0,pipe_containment=0,final_owner_counts=0)
    if mode==b'F':
        expected['trigger_read_error']=-5
        expected.update({name:-5 for name in ['failed_read_open','failed_read','failed_write','failed_seek','failed_stat','failed_list','failed_fsync','failed_spawn']})
    else:
        expected.update(offset_survives_denied_open=0,offset_byte=104,permitted_seek=0,permitted_stat=0,permitted_list=0,permitted_fsync=0,read_open=0,missing_read_open=-2,readonly_nonzero_write=-9 if mode==b'M' else -30,readonly_unlink=-30,readonly_same_rename=-30,descriptor_capacity=29,full_table_read=-24,full_table_write_precedence=-24)
        if mode==b'T':expected['last_transaction']=0
    return expected

def records(serial,run_id,boot_id,instrumented,mode):
    # Release uses a dedicated prefix emitted only by the immutable sole init;
    # normalize complete framing into the same strict bounded JSON parser.
    normalized=serial if instrumented else b'\n'.join(b'KTEST '+line[7:] if line.startswith(b'ROTEST ') else b'' for line in serial.split(b'\n'))
    rows=trusted_records(normalized)
    if not rows:raise ValueError('no immutable-init result records')
    for sequence,row in enumerate(rows,1):
        expected={'schema':1,'case_id':'readonly-open','run_id':run_id,'boot_id':boot_id,'sequence':sequence}
        if any(row.get(k)!=v for k,v in expected.items()):raise ValueError('invalid record identity/order')
    if rows[0].get('event')!='start' or rows[-1].get('event')!='result' or rows[-1].get('error')!=0:raise ValueError('guest did not finish the case normally')
    checks={}
    for row in rows:
        if row.get('event')=='check':
            if row['name'] in checks or type(row.get('actual')) is not int or type(row.get('expected')) is not int:raise ValueError('malformed or duplicate check')
            checks[row['name']]=row
    oracle=expected_checks(mode)
    if set(checks)!=set(oracle) or any(checks[name]['expected']!=value for name,value in oracle.items()):raise ValueError('required case matrix or independent expectation mismatch')
    owner_rows=[row for row in rows if row.get('event')=='owners']
    if len({row.get('name') for row in owner_rows})!=len(owner_rows):raise ValueError('duplicate owner census name')
    owners={row['name']:row['counts'] for row in rows if row.get('event')=='owners'}
    if instrumented:
        if set(owners)!={'baseline','before_denied','after_denied','final'} or any(len(x)!=12 or any(type(n)is not int or n<0 for n in x) for x in owners.values()):raise ValueError('owner census incomplete')
    elif owners:raise ValueError('release execution unexpectedly used private observations')
    return rows,checks,owners

def inspect_fixture(path,mode):
    report=fsck.inspect(path);expected=(1<<64)-1 if mode!=b'F' else 0
    if report['sequence']!=expected or report['needs_replay']:raise AssertionError('unexpected logical sequence/replay state')
    files={entry['name']:entry for entry in report['files']}
    payload=(b'Z'+PAYLOAD[1:]) if mode==b'T' else PAYLOAD
    if set(files)!={'/payload','/empty'} or files['/payload']['sha256']!=hashlib.sha256(payload).hexdigest() or files['/payload']['size']!=len(payload) or files['/empty']['size']!=0:raise AssertionError('logical state changed unexpectedly')
    return report

def one(args,kernel,firmware,initial,directory,mode,run_id,boot_id,instrumented,negative=False):
    directory.mkdir();errors=[];result={'schema':1,'status':'INCOMPLETE','mode':mode.decode(),'instrumented':instrumented,'negative_control':negative,'kernel_sha256':sha256(kernel),'initial_sha256':hashlib.sha256(initial).hexdigest()}
    guest=None
    try:
        with tempfile.TemporaryDirectory(prefix='krv-readonly-') as temporary,(directory/'nbd.jsonl').open('x') as log:
            store=ObservedStore(initial,nbd.Trace(log));path=Path(temporary)/'nbd.sock'
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
                listener.bind(str(path));listener.listen(1);listener.settimeout(60)
                def serve():
                    try:
                        connection,_=listener.accept()
                        with connection:connection.settimeout(30);nbd.session(connection,store)
                    except (EOFError,BrokenPipeError,ConnectionResetError):pass
                    except Exception as error:errors.append(str(error))
                thread=threading.Thread(target=serve,daemon=True);thread.start()
                guest=NbdGuest(args.qemu,kernel,firmware,path,directory/'guest')
                def send(value):guest.child.stdin.write(value);guest.child.stdin.flush()
                def phase(name):guest.expect(b'"event":"phase","name":"'+name.encode()+b'"}\\r?\\n')
                guest.expect(rb'(?:^|\n)READY\r?\n');guest.expect(rb'"event":"start"}\r?\n');send(mode)
                if mode==b'F':phase('fault_armed');store.arm=True;send(b'g')
                phase('denied_begin');before=dict(store.counts);image_before=bytes(store.stable)
                sparse_output(directory/'before-denied.img',image_before);inspect_fixture(directory/'before-denied.img',mode)
                store.trace.emit('readonly_denied_begin',counts=before);send(b'g')
                phase('denied_end');after=dict(store.counts);image_after=bytes(store.stable)
                store.trace.emit('readonly_denied_end',counts=after);send(b'g')
                phase('operations_end');operations_end=dict(store.counts)
                if operations_end['writes']!=after['writes'] or operations_end['flushes']!=after['flushes'] or (mode==b'F' and operations_end!=after):raise AssertionError('no-effect/FAILED operations issued forbidden block activity')
                store.trace.emit('readonly_operations_end',counts=operations_end);send(b'g')
                guest.wait_for_shutdown(60);serial=bytes(guest.data);guest=None
                thread.join(5)
                if thread.is_alive() or errors:raise RuntimeError('backend did not terminate cleanly: '+repr(errors))
            final,_=store.outcome('none');sparse_output(directory/'final.img',final)
            checked=inspect_fixture(directory/'final.img',mode)
            if image_before!=image_after or image_before!=final:raise AssertionError('rejected or permitted volatile operations altered persistent bytes')
            if before!=after and not negative:raise AssertionError('open rejections issued block activity')
            if mode==b'F' and (not store.triggered or b'SHUTDOWN_UNCERTAIN' not in serial):raise AssertionError('FAILED fixture or shutdown missing')
            if mode!=b'F' and b'SHUTDOWN_CLEAN' not in serial:raise AssertionError('healthy readonly shutdown missing')
            rows,checks,owners=records(serial,run_id,boot_id,instrumented,mode)
            (directory/'raw-records.json').write_text(json.dumps(rows,indent=2)+'\n');(directory/'fsck.json').write_text(json.dumps(checked,indent=2)+'\n')
            mismatches=[x for x in checks.values() if x['actual']!=x['expected']]
            if negative:
                exposed=checks['write_existing']
                if rows[-1].get('result')!='FAIL' or exposed['expected']!=-30 or exposed['actual']<3:raise AssertionError('baseline did not expose actual WRITE-open success versus EROFS')
                allowed={'write_existing','readwrite_existing','create_read_existing','create_write_existing','create_exclusive_existing','repeated_denials'}
                if any(row['name'] not in allowed for row in mismatches):raise AssertionError('baseline failed for a reason outside the removed admission check')
                disposition='EXPECTED_COUNTEREXAMPLE'
            else:
                if rows[-1].get('result')!='PASS' or mismatches:raise AssertionError('syscall expectation mismatch: '+repr(mismatches))
                if instrumented:
                    if owners['before_denied']!=owners['after_denied'] or owners['baseline']!=owners['final']:raise AssertionError('owner counts changed across rejection or cleanup')
                    if [owners['baseline'][i] for i in [4,7,8]]!=[3,0,0] or [owners['before_denied'][i] for i in [4,7,8]]!=[4,1,1]:raise AssertionError('descriptor/open-description/reference counts disagree with fixture')
                disposition='PASS'
            result.update(status='PASS',disposition=disposition,checks=list(checks.values()),owner_counts=owners,block_activity_before_denied=before,block_activity_after_denied=after,block_activity_after_operations=operations_end,total_block_activity=store.counts,shutdown_scope="Additional NBD flushes after operations_end can originate from QEMU backend shutdown; no flush/write was observed during the checked syscalls",final_sha256=sha256(directory/'final.img'),sequence=checked['sequence'],persistent_bytes_unchanged_after_transition=True,mismatches=mismatches)
    except Exception as error:result.update(status='INCOMPLETE' if isinstance(error,TimeoutError) else 'FAIL',reason=str(error))
    finally:
        if guest:guest.close()
        (directory/'case-report.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('checks','owner_counts','mismatches')}),flush=True)
    if result['status']!='PASS':raise RuntimeError('readonly case failed: '+str(directory)+' '+result.get('reason',''))
    return result

def copy_source(root,destination):
    shutil.copytree(root,destination,ignore=lambda _p,names:[n for n in names if n in IGNORE])
    return source_identity(destination)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path);p.add_argument('--qemu',default='qemu-system-riscv64');p.add_argument('--firmware',type=Path,default=Path('build/fw_dynamic.bin'));p.add_argument('--cargo',default='cargo');args=p.parse_args()
    root=Path(__file__).resolve().parents[1];output=args.output.resolve()
    if output.is_relative_to(root):p.error('evidence must be outside candidate tree')
    output.mkdir(parents=True,exist_ok=False);run_id=uuid.uuid4().hex;boot_id=uuid.uuid4().hex
    report={'schema':1,'status':'INCOMPLETE','scope':'Actual release and instrumented syscall boundary READ_ONLY/FAILED with independent byte/metadata/block-activity checks and original-defect negative control','run_id':run_id,'boot_id':boot_id,'cases':[],'limitations':['Release owner counts are inferred by resource reuse; exact12-field counts are observed only in instrumented executions.','FAILED offsets cannot be queried through the ordinary ABI; offset preservation is observed on READ_ONLY descriptors.']}
    try:
        snapshot=output/'candidate-source';report['source_identity']=copy_source(root,snapshot)
        qemu=probe('qemu-system-riscv64',args.qemu);report['qemu']=qemu
        if qemu['status']!='MATCH':raise RuntimeError('QEMU11.1.3 required')
        args.qemu=qemu['path'];firmware=output/'fw_dynamic.bin';shutil.copyfile(args.firmware.resolve(strict=True),firmware);report['firmware_sha256']=sha256(firmware)
        environment=os.environ.copy();environment.update(KERNEL_TEST_RUN_ID=run_id,KERNEL_TEST_BOOT_ID=boot_id,CARGO_TARGET_DIR=str(output/'user-target'),SOURCE_DATE_EPOCH='1793923200')
        user_command=[args.cargo,'build','--locked','--offline','--release','-p','user-programs','--target','riscv64imac-unknown-none-elf','--bin','fsreadonly'];build('build-user',user_command,snapshot,output,environment)
        init=output/'user-target/riscv64imac-unknown-none-elf/release/fsreadonly';report['init_sha256']=sha256(init);environment['KERNEL_INIT_ELF']=str(init)
        kernels={};commands=[user_command]
        for instrumented in [False,True]:
            label='instrumented' if instrumented else 'release';environment['CARGO_TARGET_DIR']=str(output/(label+'-target'))
            command=[args.cargo,'build','--locked','--offline','--release','-p','kernel','--target','riscv64imac-unknown-none-elf']+(['--features','instrumented'] if instrumented else [])
            build('build-'+label,command,snapshot,output,environment);commands.append(command);kernels[label]=output/(label+'-target/riscv64imac-unknown-none-elf/release/kernel')
        report['kernel_sha256']={k:sha256(v) for k,v in kernels.items()};report['build_commands']=commands
        payload=output/'payload';payload.write_bytes(PAYLOAD);empty=output/'empty';empty.write_bytes(b'');initial=output/'initial.img';mkfs.create(initial,uuid.UUID(run_id).bytes,[('/payload',payload),('/empty',empty)])
        images={}
        for name,mode in MODES.items():
            data=bytearray(initial.read_bytes());sequence={'mount_max':(1<<64)-1,'exhaustion_transition':(1<<64)-2,'failed':0}[name];struct.pack_into('<Q',data,19*4096+2048,sequence);seal_region(data,19*4096,4096);images[name]=bytes(data);sparse_output(output/(name+'-initial.img'),data)
        for label,kernel in kernels.items():
            for name,mode in MODES.items():report['cases'].append(one(args,kernel,firmware,images[name],output/(label+'-'+name),mode,run_id,boot_id,label=='instrumented'))
        baseline=output/'baseline-source';copy_source(snapshot,baseline);path=baseline/'kernel/src/syscall.rs';source=path.read_text();start=source.index('        // Admission belongs to the same filesystem owner as lookup and mutation.',source.index('fn open_file('));end=source.index('        let slot = (0..256)',start);removed=source[start:end]
        if 'match fs.state()' not in removed or 'return Err(Error::ReadOnly)' not in removed:raise RuntimeError('open admission check is not the expected isolated control')
        path.write_text(source[:start]+source[end:]);report['negative_control']={'mutation':'Remove only open_file storage-state admission block','removed_source':removed,'source_identity':source_identity(baseline)}
        environment['CARGO_TARGET_DIR']=str(output/'baseline-target');command=[args.cargo,'build','--locked','--offline','--release','-p','kernel','--features','instrumented','--target','riscv64imac-unknown-none-elf'];build('build-baseline',command,baseline,output,environment);baseline_kernel=output/'baseline-target/riscv64imac-unknown-none-elf/release/kernel'
        report['negative_control']['kernel_sha256']=sha256(baseline_kernel);report['negative_control']['case']=one(args,baseline_kernel,firmware,images['mount_max'],output/'baseline-mount-max',b'M',run_id,boot_id,True,negative=True)
        report['restored_case']=one(args,kernels['instrumented'],firmware,images['mount_max'],output/'restored-mount-max',b'M',run_id,boot_id,True)
        if source_identity(snapshot)!=report['source_identity']:raise RuntimeError('frozen fixed test source changed')
        report.update(status='PASS',source_snapshot_unchanged=True,original_tree_still_matches=source_identity(root)==report['source_identity'])
    except Exception as error:report.update(status='INCOMPLETE' if isinstance(error,TimeoutError) else 'FAIL',reason=str(error))
    (output/'readonly-report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ('cases','negative_control','restored_case')},indent=2));return 0 if report['status']=='PASS' else 2

if __name__=='__main__':raise SystemExit(main())
