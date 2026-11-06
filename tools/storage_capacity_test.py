#!/usr/bin/env python3
"""Full16384-block/256-inode guest ENOSPC, no-effects, release, retry and reboot."""
import argparse,hashlib,io,json,os,shutil,socket,tempfile,threading,uuid
from collections import Counter
from pathlib import Path
import fsck,nbd_fault as nbd
from accept import source_identity
from crash_test import NbdGuest,sparse_output,logical
from doctor import probe,sha256
from guest_test import build
from largest_recovery_test import fixture
from readonly_test import ObservedStore,copy_source
from recovery_test import nbd_boot
from protocol import trusted_records

EXPECTED={'empty_needs_data':(-28,1),'growth_needs_data':(-28,1),'create_needs_inode':(-28,1),'maximum_file_write':(-27,1),'maximum_file_seek':(-22,1),'full_owner_counts':(0,1),'release_file':(0,1),'retry_create':(0,1),'retry_empty_offset':(1,1),'retry_growth_offset':(4096,1),'direct_indirect_write':(4096,13),'inode_full_again':(-28,1),'empty_readback':(78,1),'growth_readback':(0,1),'indirect_readback':(0,1),'new_fsync':(0,1),'final_owner_counts':(0,1)}

def analyze(serial,run_id,boot_id,instrumented):
    normalized=serial if instrumented else b'\n'.join(b'KTEST '+line[7:] if line.startswith(b'ROTEST ') else b'' for line in serial.split(b'\n'))
    rows=trusted_records(normalized)
    if not rows or rows[0].get('event')!='start' or rows[-1].get('event')!='result' or rows[-1].get('result')!='PASS' or rows[-1].get('error')!=0:raise ValueError('missing complete successful immutable-init result')
    for sequence,row in enumerate(rows,1):
        identity={'schema':1,'case_id':'storage-capacity','run_id':run_id,'boot_id':boot_id,'sequence':sequence}
        if any(row.get(k)!=v for k,v in identity.items()):raise ValueError('result identity or sequence mismatch')
    checks=[row for row in rows if row.get('event')=='check'];counts=Counter(row['name'] for row in checks)
    if counts!=Counter({k:v[1] for k,v in EXPECTED.items()}):raise ValueError('required full-capacity case/count matrix incomplete')
    for row in checks:
        if type(row.get('actual')) is not int or type(row.get('expected')) is not int or row['actual']!=row['expected'] or row['expected']!=EXPECTED[row['name']][0]:raise ValueError('independent syscall expectation mismatch')
    owner_rows=[row for row in rows if row.get('event')=='owners']
    if len({row.get('name') for row in owner_rows})!=len(owner_rows):raise ValueError('duplicate owner census name')
    owners={row['name']:row['counts'] for row in rows if row.get('event')=='owners'}
    if instrumented:
        if set(owners)!={'baseline','before_full','after_full','final'} or any(len(v)!=12 or any(type(n)is not int or n<0 for n in v) for v in owners.values()):raise ValueError('missing ownership census')
        if owners['baseline']!=owners['final'] or owners['before_full']!=owners['after_full']:raise ValueError('owner census changed across rejection/cleanup')
        if [owners['baseline'][i] for i in [4,7,8]]!=[3,0,0] or [owners['before_full'][i] for i in [4,7,8]]!=[6,3,3]:raise ValueError('descriptor/open/ref census disagrees with fixture')
    elif owners:raise ValueError('release cannot claim instrumented observations')
    return rows,owners

def check_logical(initial,after,phase):
    if after['needs_replay']:raise AssertionError('successful transaction left replay pending')
    originals={f['name']:f for f in initial['files']};actual={f['name']:f for f in after['files']}
    if phase=='reclaimed':
        if set(actual)!=set(originals)-{'/f000'} or after['sequence']!=1 or after['used_blocks']!=15359:raise AssertionError('unlink did not release exactly1025blocks and one inode')
        expected={k:v for k,v in originals.items() if k!='/f000'}
    else:
        if set(actual)!=(set(originals)-{'/f000'})|{'/new'} or after['sequence']!=17 or after['used_blocks']!=15375:raise AssertionError('retry namespace,17transactions or block allocation mismatch')
        expected={k:v.copy() for k,v in originals.items() if k!='/f000'}
        expected['/f016'].update(size=1,sha256=hashlib.sha256(b'N').hexdigest())
        growth=bytes(range(256))*15616+b'G'*4096;expected['/f015'].update(size=len(growth),sha256=hashlib.sha256(growth).hexdigest())
        data=b''.join(bytes([48+i])*4096 for i in range(13));expected['/new']={'name':'/new','inode':originals['/f000']['inode'],'generation':originals['/f000']['generation']+1,'size':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    for name,wanted in expected.items():
        if any(actual[name][key]!=wanted[key] for key in ['inode','generation','size','sha256']):raise AssertionError('independent file model mismatch '+name)

def one(args,initial,kernel,normal,firmware,directory,run_id,boot_id,instrumented):
    directory.mkdir();record={'schema':1,'status':'INCOMPLETE','instrumented':instrumented,'kernel_sha256':sha256(kernel)};guest=None;errors=[];initial_state=fsck.Image(io.BytesIO(initial)).inspect()
    try:
        with tempfile.TemporaryDirectory(prefix='krv-full-') as tmp,(directory/'nbd.jsonl').open('x') as log:
            store=ObservedStore(initial,nbd.Trace(log));path=Path(tmp)/'disk.sock'
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
                listener.bind(str(path));listener.listen(1);listener.settimeout(60)
                def serve():
                    try:
                        connection,_=listener.accept()
                        with connection:connection.settimeout(30);nbd.session(connection,store)
                    except (EOFError,BrokenPipeError,ConnectionResetError):pass
                    except Exception as error:errors.append(str(error))
                thread=threading.Thread(target=serve,daemon=True);thread.start();guest=NbdGuest(args.qemu,kernel,firmware,path,directory/'guest')
                def phase(name):guest.expect(b'"event":"phase","name":"'+name.encode()+b'"}\\r?\\n')
                def proceed():guest.child.stdin.write(b'g');guest.child.stdin.flush()
                guest.expect(rb'(?:^|\n)READY\r?\n');phase('full_begin');before=dict(store.counts);image_before=bytes(store.stable);proceed()
                phase('full_end');after=dict(store.counts)
                if image_before!=bytes(store.stable) or image_before!=initial or before['writes']!=after['writes'] or before['flushes']!=after['flushes']:raise AssertionError('full-resource failure changed persistent bytes or started journal writes/barriers')
                store.trace.emit('full_rejection_verified',before=before,after=after);proceed()
                phase('reclaimed');reclaimed=bytes(store.stable);sparse_output(directory/'reclaimed.img',reclaimed);state=fsck.inspect(directory/'reclaimed.img');check_logical(initial_state,state,'reclaimed');proceed()
                phase('operations_end');final=bytes(store.stable);sparse_output(directory/'final.img',final);state=fsck.inspect(directory/'final.img');check_logical(initial_state,state,'final');proceed()
                guest.wait_for_shutdown(60);serial=bytes(guest.data);guest=None;thread.join(5)
                if thread.is_alive() or errors:raise RuntimeError('backend termination failure '+repr(errors))
            if bytes(store.stable)!=final or b'SHUTDOWN_CLEAN' not in serial:raise AssertionError('shutdown changed image or missed clean marker')
            rows,owners=analyze(serial,run_id,boot_id,instrumented);(directory/'raw-records.json').write_text(json.dumps(rows,indent=2)+'\n');(directory/'fsck.json').write_text(json.dumps(state,indent=2)+'\n')
        rebooted,_=nbd_boot(args,final,normal,firmware,directory/'reboot');reboot_state=fsck.Image(io.BytesIO(rebooted)).inspect()
        if rebooted!=final or logical(reboot_state)!=logical(state):raise AssertionError('actual normal-init guest reboot changed the expected state')
        record.update(status='PASS',full_blocks=initial_state['used_blocks'],full_files=len(initial_state['files']),reclaimed_blocks=1025,reclaimed_inodes=1,final_blocks=state['used_blocks'],final_files=len(state['files']),sequence=state['sequence'],rejected_block_activity_before=before,rejected_block_activity_after=after,owner_counts=owners,initial_sha256=hashlib.sha256(initial).hexdigest(),reclaimed_sha256=sha256(directory/'reclaimed.img'),final_sha256=sha256(directory/'final.img'),normal_reboot_kernel_sha256=sha256(normal),actual_reboot=True,checks=EXPECTED)
    except Exception as error:record.update(status='INCOMPLETE' if isinstance(error,TimeoutError) else 'FAIL',reason=str(error))
    finally:
        if guest:guest.close()
        (directory/'case-report.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({k:v for k,v in record.items() if k not in ['owner_counts','checks']}),flush=True)
    if record['status']!='PASS':raise RuntimeError(record.get('reason'))
    return record

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--qemu',default='qemu-system-riscv64');p.add_argument('--firmware',type=Path,default=Path('build/fw_dynamic.bin'));p.add_argument('--cargo',default='cargo');args=p.parse_args();root=Path(__file__).resolve().parents[1];output=args.output.resolve()
    if output.is_relative_to(root):p.error('evidence must be outside candidate source')
    output.mkdir(parents=True,exist_ok=False);report={'schema':1,'status':'INCOMPLETE','scope':'Actual release/instrumented full16384-block and256-file ENOSPC no-effects, one-file reclamation, retry, direct-to-indirect allocation and normal-init reboot','cases':[]};run_id=uuid.uuid4().hex;boot_id=uuid.uuid4().hex
    try:
        snapshot=output/'candidate-source';report.update(source_identity=copy_source(root,snapshot),run_id=run_id,boot_id=boot_id)
        qemu=probe('qemu-system-riscv64',args.qemu);report['qemu']=qemu
        if qemu['status']!='MATCH':raise RuntimeError('pinned QEMU11.1.3 required')
        args.qemu=qemu['path'];firmware=output/'fw_dynamic.bin';shutil.copyfile(args.firmware.resolve(strict=True),firmware);report['firmware_sha256']=sha256(firmware)
        env=os.environ.copy();env.update(KERNEL_TEST_RUN_ID=run_id,KERNEL_TEST_BOOT_ID=boot_id,CARGO_TARGET_DIR=str(output/'user-target'),SOURCE_DATE_EPOCH='1793923200')
        command=[args.cargo,'build','--locked','--offline','--release','-p','user-programs','--target','riscv64imac-unknown-none-elf','--bin','fsfull','--bin','init'];build('build-user',command,snapshot,output,env);programs=output/'user-target/riscv64imac-unknown-none-elf/release';report['init_sha256']={name:sha256(programs/name) for name in ['init','fsfull']}
        kernels={};report['build_commands']=[command]
        for label in ['release','instrumented','normal']:
            env.update(CARGO_TARGET_DIR=str(output/(label+'-target')),KERNEL_INIT_ELF=str(programs/('init' if label=='normal' else 'fsfull')))
            command=[args.cargo,'build','--locked','--offline','--release','-p','kernel','--target','riscv64imac-unknown-none-elf']+(['--features','instrumented'] if label=='instrumented' else []);build('build-'+label,command,snapshot,output,env);report['build_commands'].append(command);kernels[label]=output/(label+'-target/riscv64imac-unknown-none-elf/release/kernel')
        inputs=output/'fixture';inputs.mkdir();fixture(inputs);initial=(inputs/'before.img').read_bytes();checked=fsck.inspect(inputs/'before.img')
        if checked['used_blocks']!=16384 or len(checked['files'])!=256 or checked['sequence']!=0 or checked['needs_replay']:raise AssertionError('full initial fixture invalid')
        for label in ['release','instrumented']:report['cases'].append(one(args,initial,kernels[label],kernels['normal'],firmware,output/label,run_id,boot_id,label=='instrumented'))
        if source_identity(snapshot)!=report['source_identity']:raise RuntimeError('frozen source snapshot changed')
        report.update(status='PASS',source_snapshot_unchanged=True,original_tree_still_matches=source_identity(root)==report['source_identity'])
    except Exception as error:report.update(status='INCOMPLETE' if isinstance(error,TimeoutError) else 'FAIL',reason=str(error))
    (output/'storage-capacity-report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='cases'},indent=2));return 0 if report['status']=='PASS' else 2

if __name__=='__main__':raise SystemExit(main())
