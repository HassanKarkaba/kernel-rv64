#!/usr/bin/env python3
"""Interrupt actual guest journal recovery three times before final completion."""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import shutil
import socket
import tempfile
import threading
import time
import fsck
import nbd_fault as nbd
from crash_test import NbdGuest, logical, sparse_output
from doctor import probe, sha256
from smoke import Guest


def reconstruct(directory, case_index):
    initial=(directory/'initial.img').read_bytes()
    case=json.loads((directory/f'case-{case_index:05d}'/'case.json').read_text())
    stable=bytearray(initial)
    pending=[]
    for line in (directory/'nbd.jsonl').read_text().splitlines():
        record=json.loads(line)
        if record['event']=='sector_issue':
            pending.append((record['version'],record['sector'],base64.b64decode(record['data'],validate=True)))
        elif record['event']=='flush_completion':
            for _,sector,data in pending:
                stable[sector*512:(sector+1)*512]=data
            pending=[]
        if record['sequence']==case['cut_sequence']:
            selected=set(case['selected_versions'])
            for version,sector,data in pending:
                if version in selected:
                    stable[sector*512:(sector+1)*512]=data
            if hashlib.sha256(stable).hexdigest()!=case['image_sha256']:
                raise ValueError('reconstructed crash image hash mismatch')
            if not fsck.Image(io.BytesIO(stable)).inspect()['needs_replay']:
                raise ValueError('selected source case has no committed journal')
            return stable,case
    raise ValueError('source trace does not contain selected cut')


def nbd_boot(args,initial,kernel,firmware,output,cut=None,policy='none'):
    output.mkdir()
    errors=[]
    hit=threading.Event()
    with tempfile.TemporaryDirectory(prefix='krv-replay-') as temporary,(output/'nbd.jsonl').open('x') as log:
        trace=nbd.Trace(log,cut)
        store=nbd.SectorStore(initial,trace)
        path=Path(temporary)/'disk.sock'
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
            listener.bind(str(path));listener.listen(1);listener.settimeout(60)
            def serve():
                try:
                    connection,_=listener.accept()
                    with connection:
                        connection.settimeout(180)
                        nbd.session(connection,store)
                except nbd.PowerCut:
                    hit.set()
                except EOFError:
                    pass
                except Exception as error:
                    errors.append(str(error))
            thread=threading.Thread(target=serve,daemon=True)
            thread.start()
            guest=NbdGuest(args.qemu,kernel,firmware,path,output/'guest')
            try:
                if cut is None:
                    guest.boot();trace.emit('recovery_ready',elapsed_host_seconds=time.monotonic()-guest.started);guest.shutdown()
                else:
                    deadline=time.monotonic()+180
                    while not hit.is_set():
                        if time.monotonic()>deadline:
                            raise TimeoutError('recovery cut event was not reached')
                        try:
                            guest.pump(0.05)
                        except RuntimeError:
                            if not hit.is_set():
                                raise
                        if guest.child.poll() is not None and not hit.is_set():
                            raise RuntimeError('guest exited before recovery cut')
                    # Deliberate VM crash; sector survival comes from the model.
                    guest.close()
            finally:
                guest.close()
            thread.join(10)
            if thread.is_alive():
                raise RuntimeError('recovery backend still running')
            if errors:
                raise RuntimeError(errors[0])
        image,selected=store.outcome(policy)
        trace.cut=None
        trace.emit('persistence_outcome',policy=policy,selected_versions=selected,image_sha256=hashlib.sha256(image).hexdigest(),cut_reached=hit.is_set())
        sparse_output(output/'outcome.img',image)
    events=[json.loads(line) for line in (output/'nbd.jsonl').read_text().splitlines()]
    return image,events


def replay_boundaries(records):
    result=[]
    first_read=None
    current=None
    for record in records:
        event=record['event']
        if event=='recovery_ready':
            break
        if event=='request_submission':
            current=record['command']
            if current==0 and first_read is None:
                first_read=record
        if current in (1,3) and event in ('request_submission','sector_issue','request_completion','reply_sent','flush_completion'):
            result.append(record)
    if not result or first_read is None:
        raise ValueError('capture contains no replay writes/barriers')
    return result,first_read


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',choices=('repeated-recovery',),default='repeated-recovery')
    parser.add_argument('--source-run',type=Path,required=True)
    parser.add_argument('--source-case',type=int,help='default: first committed/replayed case in source report')
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--qemu',default='qemu-system-riscv64')
    parser.add_argument('--kernel',type=Path,default=Path('target/riscv64imac-unknown-none-elf/release/kernel'))
    parser.add_argument('--firmware',type=Path,default=Path('build/fw_dynamic.bin'))
    parser.add_argument('--max-cases',type=int)
    args=parser.parse_args()
    output=args.output.resolve()
    if output.is_relative_to(Path(__file__).resolve().parents[1]):
        parser.error('evidence must be outside source candidate')
    report={'schema':1,'status':'INCOMPLETE','scope':'Actual guest repeated recovery of one committed transaction','cases':[],
            'limitations':['Source transaction is one captured create; this is not the seeded-history campaign or a proof over every mutation.']}
    made=False
    try:
        output.mkdir(parents=True,exist_ok=False);made=True
        qemu=probe('qemu-system-riscv64',args.qemu)
        if qemu['status']!='MATCH':
            raise RuntimeError('QEMU 11.1.3 required')
        args.qemu=qemu['path'];report['qemu']=qemu
        inputs=output/'inputs';inputs.mkdir()
        kernel=inputs/'kernel';firmware=inputs/'fw_dynamic.bin'
        shutil.copyfile(args.kernel.resolve(strict=True),kernel)
        shutil.copyfile(args.firmware.resolve(strict=True),firmware)
        report['kernel_sha256']=sha256(kernel);report['firmware_sha256']=sha256(firmware)
        source_run=args.source_run.resolve(strict=True)
        source_index=args.source_case
        if source_index is None:
            source_report=json.loads((source_run/'crash-report.json').read_text())
            source_index=next(case['index'] for case in source_report['cases'] if case.get('replayed'))
        initial,source_case=reconstruct(source_run,source_index)
        sparse_output(inputs/'committed.img',initial)
        expected=fsck.Image(io.BytesIO(initial)).inspect()
        report['source_case']=source_case;report['committed_sequence']=expected['sequence']
        _,baseline=nbd_boot(args,initial,kernel,firmware,output/'baseline')
        boundaries,first_read=replay_boundaries(baseline)
        report['replay_boundaries']=len(boundaries)
        for boundary in boundaries:
            for policy in ('none','all'):
                if args.max_cases is not None and len(report['cases'])>=args.max_cases:
                    raise TimeoutError('explicit --max-cases reached; remaining boundaries NOT RUN')
                index=len(report['cases'])
                case={'index':index,'boundary':boundary,'policy':policy,'status':'INCOMPLETE','interruptions':[]}
                report['cases'].append(case)
                directory=output/f'case-{index:04d}';directory.mkdir()
                image=initial
                for repeat in range(3):
                    before=fsck.Image(io.BytesIO(image)).inspect()
                    target=boundary if before['needs_replay'] else first_read
                    image,events=nbd_boot(args,image,kernel,firmware,directory/f'interruption-{repeat+1}',target['sequence'],policy)
                    after=fsck.Image(io.BytesIO(image)).inspect()
                    if logical(after)!=logical(expected):
                        raise AssertionError('interrupted recovery changed committed state/generation/sequence')
                    case['interruptions'].append({'cut_sequence':target['sequence'],'phase':'replay' if before['needs_replay'] else 'post-retirement mount scan','needs_replay_after':after['needs_replay'],'image_sha256':hashlib.sha256(image).hexdigest()})
                path=directory/'final.img';sparse_output(path,image)
                guest=Guest(args.qemu,kernel,firmware,path,directory/'final-boot')
                try:
                    guest.boot();guest.shutdown()
                finally:
                    guest.close()
                actual=fsck.inspect(path)
                if actual['needs_replay'] or logical(actual)!=logical(expected):
                    raise AssertionError('final recovery failed independent committed-state oracle')
                case['status']='PASS'
                (directory/'case.json').write_text(json.dumps(case,indent=2)+'\n')
                print(json.dumps({'event':'repeated_recovery_case','case':index,'boundary':boundary['sequence'],'policy':policy,'status':'PASS'}),flush=True)
        report.update(status='PASS',completed_cases=len(report['cases']),live_interruptions=3*len(report['cases']),final_boots=len(report['cases']))
    except Exception as error:
        report.update(status='INCOMPLETE' if isinstance(error,TimeoutError) else 'FAIL',reason=str(error))
    finally:
        if made:
            (output/'recovery-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='cases'},indent=2))
    return 0 if report['status']=='PASS' else 2


if __name__=='__main__':
    raise SystemExit(main())
