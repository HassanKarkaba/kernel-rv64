#!/usr/bin/env python3
"""Exhaust/release/retry real global page, open-description and pipe resources."""
import argparse
import json
import os
from pathlib import Path
import sys
import time
import uuid
import fsck
import mkfs
from accept import source_identity
from doctor import probe, sha256
from guest_test import build
from protocol import trusted_records
from smoke import Guest


def analyze(serial, run_id, boot_id):
    records=trusted_records(serial)
    if len(records)!=141:raise ValueError(f'expected141 trusted records, got{len(records)}')
    for sequence,record in enumerate(records,1):
        expected=dict(schema=1,run_id=run_id,boot_id=boot_id,case_id='global-capacity',sequence=sequence)
        if any(record.get(k)!=v for k,v in expected.items()):raise ValueError('identity or sequence mismatch')
    if records[0].get('event')!='start' or records[-1].get('event')!='result' or records[-1].get('result')!='PASS' or records[-1].get('error')!=0:
        raise ValueError('missing successful trusted terminal record')
    summaries=[]
    cursor=1
    for index,kind in enumerate(('memory','files','pipes')):
        length=47 if kind=='memory' else 46
        body=records[cursor:cursor+length];cursor+=length
        extra=1 if kind=='memory' else 0
        baseline,workers,peak,final,terminal=body[:12],body[12:21],body[21:33],body[33+extra:45+extra],body[45+extra]
        def census(rows,event):
            values=[]
            for owner,row in enumerate(rows):
                if row.get('event')!=event or row.get('kind')!=kind or row.get('owner')!=owner or type(row.get('count'))is not int or row['count']<0:raise ValueError('malformed ownership census')
                values.append(row['count'])
            return values
        initial=census(baseline,'baseline');maximum=census(peak,'peak');after=census(final,'final')
        if initial!=after:raise ValueError('owner counts failed to return to baseline')
        if terminal.get('event')!='family-result' or terminal.get('kind')!=kind or terminal.get('result')!='PASS' or terminal.get('retry')is not True:raise ValueError('retry did not pass')
        pids=set();total=0;preload_pages=0;constrained=False
        for ordinal,worker in enumerate(workers):
            if worker.get('event')!='worker' or worker.get('kind')!=kind or worker.get('worker')!=ordinal:raise ValueError('worker order mismatch')
            pid,count,error,pages,allowance=(worker[k] for k in ('pid','allocated','error','initial_pages','page_allowance'))
            if any(type(v)is not int for v in (pid,count,error,pages,allowance)) or pid in pids or pid<=257 or count<0 or not 0<pages<4096 or allowance!=4096-pages:raise ValueError('invalid worker accounting')
            pids.add(pid);total+=count;preload_pages+=pages
            if kind=='memory':
                if error!=-12 or count>allowance or (ordinal==0 and count!=allowance):raise ValueError('memory exhaustion did not isolate local/global quotas')
                constrained |= count<allowance
            else:
                local=30 if kind=='files' else 15
                if count>local or error!=(-24 if count==local else -23):raise ValueError('descriptor/global resource error precedence mismatch')
        if maximum[3]!=initial[3]+9:raise ValueError('all nine preloaded workers were not alive at peak')
        if kind=='memory':
            physical=body[33]
            if physical.get('event')!='pool' or any(type(physical.get(k))is not int or physical[k]<0 for k in ('total','reserved','live','free')):raise ValueError('invalid physical-pool census')
            if physical['total']!=32768 or physical['reserved']+physical['live']!=physical['total'] or physical['free']!=0 or maximum[0]!=physical['live'] or total+preload_pages+initial[0]!=physical['live'] or not constrained:raise ValueError('global128MiB physical pool was not actually exhausted')
        elif kind=='files':
            if maximum[7]!=256 or maximum[8]!=256 or total!=256:raise ValueError('global256 open descriptions not reached')
        elif maximum[9]!=64 or total!=46:
            raise ValueError('global64 pipes including18 controls not reached')
        if maximum[9]!=(64 if kind=='pipes' else 18):raise ValueError('unexpected control-pipe accounting')
        expected_fds=initial[4]+36+(total if kind=='files' else total*2 if kind=='pipes' else 0)
        if maximum[4]!=expected_fds:raise ValueError('descriptor census disagrees with retained resources')
        summaries.append(dict(kind=kind,allocated=total,preloaded_worker_pages=preload_pages,baseline=initial,peak=maximum,final=after,retry=True,physical_pool=body[33] if kind=='memory' else None))
    return summaries,records


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--qemu',default='qemu-system-riscv64')
    parser.add_argument('--firmware',type=Path,default=Path('build/fw_dynamic.bin'))
    parser.add_argument('--cargo',default='cargo')
    parser.add_argument('--timeout',type=int,default=600)
    args=parser.parse_args();root=Path(__file__).resolve().parents[1];output=args.output.resolve()
    if output.is_relative_to(root):parser.error('capacity evidence must be outside source')
    output.mkdir(parents=True,exist_ok=False)
    run_id,boot_id=uuid.uuid4().hex,uuid.uuid4().hex
    report=dict(schema=1,status='INCOMPLETE',run_id=run_id,boot_id=boot_id,source_identity=source_identity(root),
                scope='Actual global128MiB user-page/256open-description/64pipe exhaustion, reclamation and retry',
                limitations=['Local limits and other resource types have separate boundary cases.','Instrumentation exposes owner counts only to immutable init.'])
    guest=None
    try:
        qemu=probe('qemu-system-riscv64',args.qemu);report['qemu']=qemu
        if qemu['status']!='MATCH':raise ValueError('QEMU11.1.3 required')
        firmware=args.firmware.resolve(strict=True)
        env=os.environ.copy();env.update(KERNEL_TEST_RUN_ID=run_id,KERNEL_TEST_BOOT_ID=boot_id,CARGO_HOME=str(output/'cargo-home'),CARGO_TARGET_DIR=str(output/'user-target'),SOURCE_DATE_EPOCH='1793923200')
        user_command=[args.cargo,'build','--locked','--release','-p','user-programs','--target','riscv64imac-unknown-none-elf']
        build('build-user',user_command,root,output,env);programs=output/'user-target/riscv64imac-unknown-none-elf/release'
        env.update(CARGO_TARGET_DIR=str(output/'kernel-target'),KERNEL_INIT_ELF=str(programs/'capacity-init'))
        kernel_command=[args.cargo,'build','--locked','--release','-p','kernel','--features','instrumented','--target','riscv64imac-unknown-none-elf']
        build('build-kernel',kernel_command,root,output,env);kernel=output/'kernel-target/riscv64imac-unknown-none-elf/release/kernel'
        report['build']=dict(commands=[user_command,kernel_command],kernel_sha256=sha256(kernel),init_sha256=sha256(programs/'capacity-init'),worker_sha256=sha256(programs/'capacity-worker'),firmware_sha256=sha256(firmware))
        image=output/'capacity.img';mkfs.create(image,uuid.UUID(run_id).bytes,[('/capacity-worker',programs/'capacity-worker')])
        guest=Guest(qemu['path'],kernel,firmware,image,output/'boot',start_paused=True,icount=True)
        guest.expect(rb'(?:^|\n)READY\r?\n');start=time.monotonic();progress=start
        while guest.child.poll()is None:
            guest.pump(.1);now=time.monotonic()
            if now-start>args.timeout:raise TimeoutError('capacity guest watchdog expired')
            if now-progress>30:print(f'capacity: {now-start:.0f} host seconds',flush=True);progress=now
        guest.wait_for_shutdown(1)
        report['families'],records=analyze(bytes(guest.data),run_id,boot_id);guest=None
        (output/'raw-records.json').write_text(json.dumps(records,indent=2)+'\n')
        checked=fsck.inspect(image)
        if checked['needs_replay'] or {entry['name'] for entry in checked['files']}!={'/capacity-worker'}:raise ValueError('capacity test failed to restore temporary namespace')
        (output/'fsck.json').write_text(json.dumps(checked,indent=2)+'\n')
        report.update(status='PASS',source_unchanged=source_identity(root)==report['source_identity'],elapsed_host_seconds=time.monotonic()-start)
        if not report['source_unchanged']:report['applicability']='Recorded binary identities only; source changed during run'
    except Exception as error:report.update(status='INCOMPLETE' if isinstance(error,TimeoutError)else'FAIL',reason=str(error))
    finally:
        if guest:guest.close()
        (output/'capacity-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2));return 0 if report['status']=='PASS'else 2


if __name__=='__main__':sys.exit(main())
