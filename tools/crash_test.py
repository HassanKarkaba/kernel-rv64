#!/usr/bin/env python3
"""Capture real NBD transactions, reconstruct sector outcomes, and reboot KFS.

The selected profile is a bounded crash regression. exhaustive-small enumerates
all declared small-profile persistence subspaces of the captured workload. It
is not the separate 100x100 seeded-history or repeated-recovery acceptance gate.
"""
import argparse
import base64
from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import selectors
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

import fsck
import mkfs
import nbd_fault as nbd
from doctor import probe, sha256
from run import command
from smoke import Guest


class NbdGuest(Guest):
    def __init__(self,qemu,kernel,firmware,nbd_socket,output):
        self.output=output
        output.mkdir()
        self.stack=ExitStack()
        self.closed=False
        self.data=bytearray()
        self.cursor=0
        self.fatal_scan_cursor=0
        self.fatal_line_start=0
        self.qmp_events=[]
        self.qmp_buffer=bytearray()
        self.identity={}
        try:
            control=Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix='krv-crash-qmp-')))
            qmp_path=control/'qmp.sock'
            self.cmd=command(qemu,kernel,firmware,Path('unused'),qmp_path)
            first=self.cmd.index('-blockdev')
            self.cmd[first+1]=json.dumps({'driver':'nbd','server':{'type':'unix','path':str(nbd_socket)},'export':'kfs','node-name':'diskfile','cache':{'direct':False,'no-flush':False}})
            # The equivalent file backend preserves guest-visible topology while
            # preflight avoids consuming the single real NBD connection.
            dummy=control/'dtb-only.img'
            with dummy.open('xb') as stream:stream.truncate(64*1024*1024)
            dtb_cmd=command(qemu,kernel,firmware,dummy,qmp_path)
            dtb_cmd[dtb_cmd.index('virt,aia=none')]+=',dumpdtb='+str(output/'machine.dtb')
            preflight=subprocess.run(dtb_cmd,stdin=subprocess.DEVNULL,capture_output=True,timeout=15)
            if preflight.returncode!=0:raise RuntimeError('NBD topology DTB preflight failed: '+preflight.stderr.decode('utf8','replace'))
            self.cmd+=['-dtb',str(output/'machine.dtb')]
            self.log=self.stack.enter_context((output/'serial.log').open('xb'))
            self.child=subprocess.Popen(self.cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            self.started=time.monotonic()
            self.sel=self.stack.enter_context(selectors.DefaultSelector())
            self.sel.register(self.child.stdout,selectors.EVENT_READ,'serial')
            self.qmp=self.stack.enter_context(socket.socket(socket.AF_UNIX))
            self.qmp.settimeout(0.1)
            deadline=time.monotonic()+10
            while True:
                try:
                    self.qmp.connect(str(qmp_path))
                    break
                except (FileNotFoundError,ConnectionRefusedError):
                    if time.monotonic()>deadline or self.child.poll() is not None:
                        raise RuntimeError('capture QMP unavailable')
                    time.sleep(0.02)
            self.qmp.setblocking(False)
            self.sel.register(self.qmp,selectors.EVENT_READ,'qmp')
            self.qmp.sendall(b'{"execute":"qmp_capabilities"}\n')
            self.identity={'schema':1,'command':self.cmd,'kernel_sha256':sha256(kernel),'firmware_sha256':sha256(firmware),'dtb_input_sha256':sha256(output/'machine.dtb'),'dtb_scope':'Exact QEMU input blob; identified OpenSBI may apply its normal fixups'}
            (output/'launch.json').write_text(json.dumps(self.identity,indent=2)+'\n')
        except Exception:
            self.close()
            raise


def logical(report):
    return (report['sequence'],tuple((f['name'],f['inode'],f['generation'],f['size'],f['sha256']) for f in report['files']))


def sparse_output(path,data):
    zero=bytes(4096)
    with open(path,'xb') as stream:
        stream.truncate(len(data))
        for offset in range(0,len(data),4096):
            block=data[offset:offset+4096]
            if block!=zero:
                stream.seek(offset)
                stream.write(block)
        stream.flush()
        os.fsync(stream.fileno())


def legacy_commands():
    return ['write /crash before','write /crash after','mv /crash /renamed','rm /renamed','run /writer','run /writer']


def workload(args,inputs,programs):
    """Preformat boundary data so each added operation is one bounded transaction."""
    names=['compute','writer','fault','demo3','producer','consumer']
    imports=[('/'+name,programs/name) for name in names]
    commands=['rm /producer'] if args.workload=='unlink' else legacy_commands()
    classes=['unlink'] if args.workload=='unlink' else ['create','aligned_write','truncate','rename_replacement','unlink']
    if args.workload in ('all','complement'):
        unaligned=inputs/'unaligned-initial';unaligned.write_bytes(bytes(4094)+b'pqrs'+bytes(4094))
        indirect=inputs/'indirect-initial';indirect.write_bytes(b'I'*(12*4096))
        imports += [('/fswork',programs/'fswork'),('/unaligned',unaligned),('/indirect',indirect)]
        complement=['run /fswork write /unaligned 4095 2 90','run /fswork write /indirect 49152 1 65']
        if args.workload=='complement':commands=[];classes=[]
        commands += complement;classes += ['unaligned_overwrite','append']
    return imports,commands,classes


def check_complement(path):
    """Independent known-byte oracle, separate from the captured transaction-prefix oracle."""
    state=fsck.inspect(path);files={f['name']:f for f in state['files']}
    expected={'/unaligned':bytes(4094)+b'pZ[s'+bytes(4094),'/indirect':b'I'*(12*4096)+b'A'}
    for name,data in expected.items():
        if name not in files or files[name]['size']!=len(data) or files[name]['sha256']!=hashlib.sha256(data).hexdigest():raise AssertionError('independent complement byte oracle mismatch '+name)
    return {name:{'size':len(data),'sha256':hashlib.sha256(data).hexdigest()} for name,data in expected.items()}


def capture(args,initial,kernel,firmware,output):
    errors=[]
    log_path=output/'nbd.jsonl'
    with tempfile.TemporaryDirectory(prefix='krv-nbd-') as temporary, log_path.open('x') as log:
        path=Path(temporary)/'disk.sock'
        trace=nbd.Trace(log)
        store=nbd.SectorStore(initial,trace)
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
            listener.bind(str(path));listener.listen(1);listener.settimeout(60)
            def serve():
                try:
                    connection,_=listener.accept()
                    with connection:
                        connection.settimeout(180)
                        nbd.session(connection,store)
                except EOFError:
                    pass
                except Exception as error:
                    errors.append(str(error))
            thread=threading.Thread(target=serve,daemon=True)
            thread.start()
            guest=NbdGuest(args.qemu,kernel,firmware,path,output/'capture')
            try:
                guest.boot()
                for text in getattr(args,'commands',(['rm /producer'] if args.workload=='unlink' else legacy_commands())):
                    guest.issue(text,b'FSWORK OK' if text.startswith('run /fswork ') else None)
                    trace.emit('guest_ack',command=text)
                guest.shutdown()
            finally:
                guest.close()
            thread.join(10)
            if thread.is_alive():
                raise RuntimeError('NBD capture did not disconnect')
            if errors:
                raise RuntimeError('NBD capture error: '+errors[0])
        final,_=store.outcome('none')
        sparse_output(output/'captured-final.img',final)
    return [json.loads(line) for line in log_path.read_text().splitlines()]


def states_and_cuts(initial,records,profile):
    """Replay issued sector versions and completed flushes, without guest timing.

    Each yielded cut is after its named event. The preceding yielded event also
    represents the before-window. Identical byte images can reuse boot evidence.
    """
    stable=bytearray(initial)
    pending=[]
    durable_delta={}
    current_request=None
    last_ack_sequence=0
    for record in records:
        event=record['event']
        if event=='request_submission':
            current_request=record['command']
        if event=='sector_issue':
            pending.append((record['version'],record['sector'],base64.b64decode(record['data'],validate=True)))
        elif event=='flush_completion':
            for _,sector,data in pending:
                stable[sector*512:(sector+1)*512]=data
                if data==initial[sector*512:(sector+1)*512]:
                    durable_delta.pop(sector,None)
                else:
                    durable_delta[sector]=data
            pending=[]
        elif event=='guest_ack':
            report=fsck.Image(io.BytesIO(stable)).inspect()
            last_ack_sequence=report['sequence']
        relevant=event in ('sector_issue','flush_completion') or event in ('request_submission','request_completion','reply_sent') and current_request in (1,3)
        if not relevant:
            continue
        if profile=='selected':
            # Cover each distinct transaction stage, commit-sector alternatives,
            # and tears in descriptor/payload/home sectors at bounded intervals.
            if event=='sector_issue' and record['sector']!=8 and record['sector']%8 not in (0,3,7):
                continue
            selections=[(),tuple(v for v,_,_ in pending),tuple(v for i,(v,_,_) in enumerate(pending) if i%2==0)]
        else:
            selections=nbd.exhaustive_small_versions(pending)
        yield record,stable,pending,selections,last_ack_sequence,durable_delta


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--profile',choices=('selected','exhaustive-small'),default='selected')
    parser.add_argument('--workload',choices=('all','legacy','complement','unlink'),default='all',help='all includes legacy classes plus named unaligned-overwrite and indirect-append traces; complement runs only those two additions')
    parser.add_argument('--qemu',default='qemu-system-riscv64')
    parser.add_argument('--kernel',type=Path,default=Path('target/riscv64imac-unknown-none-elf/release/kernel'))
    parser.add_argument('--firmware',type=Path,default=Path('build/fw_dynamic.bin'))
    parser.add_argument('--program-dir',type=Path,default=Path('target/riscv64imac-unknown-none-elf/release'))
    parser.add_argument('--max-boots',type=int,help='explicit bounded partial run; reports INCOMPLETE if reached')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    output=args.output.resolve()
    if output.is_relative_to(root):
        parser.error('evidence must be outside source candidate')
    report={'schema':1,'status':'INCOMPLETE','profile':args.profile,'workload':args.workload,'cases':[],'limitations':['Recovery oracle checks recorded transaction-prefix consistency; workload semantics are covered by separate filesystem/smoke cases.','No 100x100 seeded histories, three-interruption repeated-recovery campaign, or storage negative controls in this command.']}
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
        imports,args.commands,classes=workload(args,inputs,args.program_dir.resolve(strict=True))
        report.update(mutation_classes=classes,commands=args.commands,allocation_boundary='append from12 complete data blocks to13 with indirect allocation' if args.workload in ('all','complement') else None)
        mkfs.create(output/'initial.img',uuid.UUID('4b465300-0001-4000-8000-0000000000c1').bytes,imports)
        initial=(output/'initial.img').read_bytes();report['initial_sha256']=hashlib.sha256(initial).hexdigest()
        records=capture(args,initial,kernel,firmware,output)
        if args.workload in ('all','complement'):report['complement_byte_oracle']=check_complement(output/'captured-final.img')
        # Every fully durable commit contributes a complete reference state. This
        # source-independent decoder never imports kernel filesystem code.
        prefixes={logical(fsck.Image(io.BytesIO(initial)).inspect())}
        stable=bytearray(initial);pending=[]
        for record in records:
            if record['event']=='sector_issue':
                pending.append((record['sector'],base64.b64decode(record['data'],validate=True)))
            elif record['event']=='flush_completion':
                for sector,data in pending:stable[sector*512:(sector+1)*512]=data
                pending=[]
                prefixes.add(logical(fsck.Image(io.BytesIO(stable)).inspect()))
        report['reference_prefix_count']=len(prefixes)
        seen={};booted=0;outcomes=0;content_hashes={}
        for cut,stable,pending,selections,ack_sequence,durable_delta in states_and_cuts(initial,records,args.profile):
            for selected in selections:
                selected=set(selected);delta=dict(durable_delta)
                for version,sector,data in pending:
                    if version in selected:
                        if data==initial[sector*512:(sector+1)*512]:
                            delta.pop(sector,None)
                        else:
                            delta[sector]=data
                # Canonical changes relative to the immutable initial image let
                # identical outcomes share evidence without hashing 64 MiB for
                # every duplicate subset. New images still receive full SHA256.
                identity=hashlib.sha256()
                for sector,data in sorted(delta.items()):
                    if data not in content_hashes:
                        content_hashes[data]=hashlib.sha256(data).digest()
                    identity.update(sector.to_bytes(4,'little'));identity.update(content_hashes[data])
                fingerprint=identity.digest();outcomes+=1
                if fingerprint in seen:
                    if seen[fingerprint][1] < ack_sequence:
                        raise AssertionError('previously tested outcome loses a later observed acknowledgment')
                    continue
                image=bytearray(initial)
                for sector,data in delta.items():
                    image[sector*512:(sector+1)*512]=data
                digest=hashlib.sha256(image).hexdigest()
                if args.max_boots is not None and booted>=args.max_boots:
                    raise TimeoutError('explicit --max-boots reached; remaining outcomes NOT RUN')
                case={'index':booted,'cut_sequence':cut['sequence'],'cut_event':cut['event'],'selected_versions':sorted(selected),'image_sha256':digest,'acknowledged_sequence':ack_sequence,'status':'INCOMPLETE'}
                report['cases'].append(case)
                directory=output/f'case-{booted:05d}';directory.mkdir()
                path=directory/'crash.img';sparse_output(path,image)
                before=fsck.inspect(path)
                if logical(before) not in prefixes or before['sequence']<ack_sequence:
                    raise AssertionError('crash outcome is not a legal acknowledged transaction prefix')
                (directory/'oracle-before.json').write_text(json.dumps(before,indent=2)+'\n')
                guest=Guest(args.qemu,kernel,firmware,path,directory/'recovery')
                try:
                    guest.boot();guest.shutdown()
                finally:
                    guest.close()
                after=fsck.inspect(path)
                if after['needs_replay'] or logical(after)!=logical(before):
                    raise AssertionError('real guest recovery diverged from independent journal oracle')
                (directory/'oracle-after.json').write_text(json.dumps(after,indent=2)+'\n')
                case.update(status='PASS',replayed=before['needs_replay'],recovered_sequence=after['sequence'])
                (directory/'case.json').write_text(json.dumps(case,indent=2)+'\n')
                seen[fingerprint]=(booted,before['sequence']);booted+=1
                print(json.dumps({'event':'case_complete','booted':booted,'cut':cut['sequence'],'replayed':before['needs_replay']}),flush=True)
        report.update(status='PASS',enumerated_outcomes=outcomes,unique_boots=booted,scope='Captured-workload '+args.profile+' sector outcomes and real guest replay')
    except Exception as error:
        report.update(status='INCOMPLETE' if isinstance(error,TimeoutError) else 'FAIL',reason=str(error))
    finally:
        if made:
            (output/'crash-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='cases'},indent=2))
    return 0 if report['status']=='PASS' else 2


if __name__=='__main__':
    raise SystemExit(main())
