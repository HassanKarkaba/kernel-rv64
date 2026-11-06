#!/usr/bin/env python3
"""Compile isolated journal mutants and reproduce actual guest counterexamples.

Captures ordinary guest write/unlink syscalls through actual VirtIO/NBD. An independent
serial model checks sector survival subsets; each mutant must then exhibit its
counterexample on an actual recovery boot. Baseline and restored captures must
pass the same independent subset oracle and complete an actual reboot.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid
import fsck
import mkfs
from corruption_test import RefusalGuest
from crash_test import capture,logical,sparse_output
from doctor import probe,sha256
from history_test import inspect_bytes
from journal_mutations import mutate

NAMES=['early_ack','missing_prepare_flush','missing_commit_flush','early_retirement','stale_payload_reuse']


def expected_states(initial):
    report=inspect_bytes(initial);states=[logical(report)]
    report['sequence']=1
    for file in report['files']:
        if file['name']=='/producer':file['sha256']=hashlib.sha256(b'ABCDEFal contents\n').hexdigest()
    states.append(logical(report))
    report['sequence']=2
    report['files']=[file for file in report['files'] if file['name']!='/victim']
    states.append(logical(report))
    return states


def outcomes(initial,records):
    stable=bytearray(initial);pending=[];ack=0;operation=0;current=None
    for record in records:
        event=record['event']
        if event=='request_submission':current=record['command']
        if event=='sector_issue':pending.append((record['version'],record['sector'],base64.b64decode(record['data'],validate=True)))
        elif event=='flush_completion':
            for _,sector,data in pending:stable[sector*512:(sector+1)*512]=data
            pending=[]
        elif event=='guest_ack':ack+=1
        # At most one syscall is in progress beyond the observed acknowledgments.
        operation=min(ack+1,2)
        relevant=event in ('sector_issue','flush_completion','guest_ack') or event in ('request_submission','request_completion','reply_sent') and current in (1,3)
        if not relevant:continue
        selections=[[],pending,pending[::2],pending[1::2],
                    [item for item in pending if item[1]==8],
                    [item for item in pending if item[1]!=8]]
        selections += [[item] for item in pending]
        seen=set()
        for selection in selections:
            versions=tuple(item[0] for item in selection)
            if versions in seen:continue
            seen.add(versions);saved={sector:bytes(stable[sector*512:(sector+1)*512]) for _,sector,_ in selection}
            for _,sector,data in selection:stable[sector*512:(sector+1)*512]=data
            yield record,stable,versions,ack,operation
            for sector,data in saved.items():stable[sector*512:(sector+1)*512]=data


def illegal(image,states,ack,operation):
    try:
        actual=inspect_bytes(image)
    except fsck.Corruption as error:return 'independent decoder: '+str(error)
    if logical(actual) not in states[ack:operation+1]:return 'not an allowed acknowledged serial prefix'
    return None


def boot_counterexample(args,kernel,firmware,image,directory,states,ack,operation):
    path=directory/'crash.img';sparse_output(path,image)
    guest=RefusalGuest(args.qemu,kernel,firmware,path,directory/'recovery')
    try:
        reply=guest.expect(rb'(?:READY\r?\n|Recovery console: status help shutdown\r?\n)')
        refused=b'Recovery console' in reply
        if not refused:guest.expect(rb'> ')
        guest.shutdown()
    finally:guest.close()
    after=illegal(path.read_bytes(),states,ack,operation)
    return {'mount_refused':refused,'after_oracle_error':after,'detected':refused or after is not None,'after_sha256':sha256(path)}


def candidate(args,snapshot,output,name,original,firmware,init,initial,states):
    directory=output/name;directory.mkdir();source=directory/'source';shutil.copytree(snapshot,source)
    code=original if name in ('baseline','restored') else mutate(original,name)
    (source/'crates/disk-format/src/lib.rs').write_text(code)
    env=os.environ.copy();env['CARGO_TARGET_DIR']=str(directory/'target');env['KERNEL_INIT_ELF']=str(init)
    command=['cargo','build','--locked','--offline','--release','-p','kernel','--target','riscv64imac-unknown-none-elf']
    result=subprocess.run(command,cwd=source,env=env,capture_output=True,text=True,timeout=180)
    (directory/'build.log').write_text(result.stdout+result.stderr)
    if result.returncode:raise RuntimeError(name+' did not compile; not a valid negative control')
    kernel=directory/'target/riscv64imac-unknown-none-elf/release/kernel'
    args.commands=['run /fswork write /producer 0 6 65']
    if name!='early_ack':args.commands.append('rm /victim')
    records=capture(args,initial,kernel,firmware,directory)
    result={'name':name,'kernel_sha256':sha256(kernel),'journal_sha256':hashlib.sha256(code.encode()).hexdigest(),'status':'INCOMPLETE','oracle_outcomes_checked':0,'commands':args.commands,'build_command':command}
    expect_pass=name in ('baseline','restored')
    for record,image,selected,ack,operation in outcomes(initial,records):
        result['oracle_outcomes_checked']+=1
        reason=illegal(image,states,ack,operation)
        if reason is None:continue
        if expect_pass:raise AssertionError(name+' source failed independent oracle: '+reason)
        counterexample=directory/'counterexample';counterexample.mkdir()
        result['counterexample']={'cut_sequence':record['sequence'],'cut_event':record['event'],'selected_versions':selected,'acknowledged_operations':ack,'current_operation':operation,'reason':reason,'before_sha256':hashlib.sha256(image).hexdigest()}
        result['counterexample'].update(boot_counterexample(args,kernel,firmware,image,counterexample,states,ack,operation))
        if not result['counterexample']['detected']:raise AssertionError('candidate recovery did not reproduce negative control')
        result['status']='PASS';break
    if expect_pass:
        final=(directory/'captured-final.img').read_bytes()
        if illegal(final,states,2,2):raise AssertionError(name+' final state mismatch')
        reboot=directory/'final-reboot';reboot.mkdir()
        result['final_boot']=boot_counterexample(args,kernel,firmware,final,reboot,states,2,2)
        if result['final_boot']['detected']:raise AssertionError(name+' final reboot failed')
        result['status']='PASS'
    if result['status']!='PASS':raise AssertionError(name+' produced no guest counterexample')
    (directory/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--qemu',default='qemu-system-riscv64')
    p.add_argument('--firmware',type=Path,required=True)
    p.add_argument('--init',type=Path,required=True)
    p.add_argument('--fswork',type=Path,required=True)
    args=p.parse_args();root=Path(__file__).resolve().parents[1];output=args.output.resolve()
    if output.is_relative_to(root):p.error('evidence must be outside source candidate')
    report={'schema':1,'status':'INCOMPLETE','scope':'Actual guest journal mutation controls through VirtIO/NBD and counterexample recovery boots','results':[],'reproduction_command':[sys.executable]+sys.argv,'working_directory':str(Path.cwd())};made=False
    try:
        output.mkdir(parents=True,exist_ok=False);made=True
        qemu=probe('qemu-system-riscv64',args.qemu)
        if qemu['status']!='MATCH':raise RuntimeError('QEMU 11.1.3 required')
        report['qemu']=qemu;args.qemu=qemu['path'];args.workload='unlink'
        inputs=output/'inputs';inputs.mkdir();snapshot=inputs/'source';snapshot.mkdir()
        for name in ('Cargo.toml','Cargo.lock'):shutil.copyfile(root/name,snapshot/name)
        for name in ('.cargo','crates','kernel','user'):shutil.copytree(root/name,snapshot/name)
        manifest={str(path.relative_to(snapshot)):sha256(path) for path in sorted(snapshot.rglob('*')) if path.is_file()}
        (inputs/'source-hashes.json').write_text(json.dumps(manifest,indent=2)+'\n')
        firmware=inputs/'fw_dynamic.bin';init=inputs/'init';fswork=inputs/'fswork'
        shutil.copyfile(args.fswork.resolve(strict=True),fswork)
        shutil.copyfile(args.firmware.resolve(strict=True),firmware);shutil.copyfile(args.init.resolve(strict=True),init)
        report.update(firmware_sha256=sha256(firmware),init_sha256=sha256(init),fswork_sha256=sha256(fswork),compiler=subprocess.check_output(['rustc','--version'],text=True).strip())
        payload=inputs/'payload';payload.write_bytes(b'original contents\n')
        mkfs.create(inputs/'initial.img',uuid.UUID('4b465300-0001-4000-8000-0000000000ce').bytes,[('/fswork',fswork),('/producer',payload),('/victim',payload)])
        initial=(inputs/'initial.img').read_bytes();states=expected_states(initial)
        (inputs/'oracle-states.json').write_text(json.dumps(states,indent=2)+'\n')
        original=(snapshot/'crates/disk-format/src/lib.rs').read_text()
        for name in ['baseline']+NAMES+['restored']:
            report['results'].append(candidate(args,snapshot,output,name,original,firmware,init,initial,states))
            (output/'guest-mutation-report.json').write_text(json.dumps(report,indent=2)+'\n')
        report['status']='PASS'
    except Exception as error:report.update(status='INCOMPLETE' if isinstance(error,TimeoutError) else 'FAIL',reason=str(error))
    finally:
        if made:(output/'guest-mutation-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({key:value for key,value in report.items() if key!='results'},indent=2))
    return 0 if report['status']=='PASS' else 2


if __name__=='__main__':raise SystemExit(main())
