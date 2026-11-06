#!/usr/bin/env python3
"""Exercise real guest storage-failure containment through an NBD backend.

Unsupported backend errors are identified as NBD errors; this does not claim
that QEMU returned the VirtIO UNSUPP status byte or a malformed used ring.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import socket
import tempfile
import threading
import time
import uuid
import fsck
import mkfs
import nbd_fault as nbd
from crash_test import NbdGuest,sparse_output
from doctor import probe,sha256


class FaultStore(nbd.SectorStore):
    def __init__(self,initial,trace):
        super().__init__(initial,trace)
        self.armed=None
        self.triggered=threading.Event()
    def read(self,offset,length):
        mode=self.armed
        if mode is not None:
            self.armed=None
            self.trace.emit('injected_backend_fault',mode=mode,offset=offset,length=length)
            self.triggered.set()
            if mode=='ioerr':raise nbd.CommandError(5)
            if mode=='unsupported':raise nbd.CommandError(95)
            if mode=='timeout':time.sleep(6.5)
        return super().read(offset,length)


def one(args,mode,initial,kernel,firmware,directory):
    directory.mkdir();errors=[]
    with tempfile.TemporaryDirectory(prefix='krv-iofault-') as temporary,(directory/'nbd.jsonl').open('x') as log:
        trace=nbd.Trace(log);store=FaultStore(initial,trace);path=Path(temporary)/'disk.sock'
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
            listener.bind(str(path));listener.listen(1);listener.settimeout(60)
            def serve():
                try:
                    connection,_=listener.accept()
                    with connection:
                        connection.settimeout(30);nbd.session(connection,store)
                except (EOFError,BrokenPipeError,ConnectionResetError):pass
                except Exception as error:errors.append(str(error))
            thread=threading.Thread(target=serve,daemon=True);thread.start()
            guest=NbdGuest(args.qemu,kernel,firmware,path,directory/'guest')
            try:
                guest.boot()
                guest.child.stdin.write(b'run /fsfailure\r');guest.child.stdin.flush()
                guest.expect(rb'FSFAIL ARMED\r?\n')
                store.armed=mode
                guest.child.stdin.write(b'g');guest.child.stdin.flush()
                reply=guest.expect(rb'> ',timeout=20)
                if not store.triggered.is_set():raise AssertionError('fault injection was not reached')
                if b'FSFAIL CONTAINED' not in reply or not re.search(rb'child \d+ ended kind=0 code=0',reply):raise AssertionError('guest did not establish EIO + pipe/memory/console containment: '+repr(reply))
                guest.issue('ps',b'PID PARENT STATE PAGES')
                guest.shutdown()
                if b'SHUTDOWN_UNCERTAIN' not in guest.data or b'SHUTDOWN_CLEAN' in guest.data:raise AssertionError('failed storage shutdown was falsely labeled clean')
            finally:guest.close()
            thread.join(12)
            if thread.is_alive():raise RuntimeError('fault backend still running')
            if errors:raise RuntimeError(errors[0])
        final,_=store.outcome('none');sparse_output(directory/'final.img',final)
        if hashlib.sha256(final).digest()!=hashlib.sha256(initial).digest():raise AssertionError('read failure changed persistent bytes')
        fsck.inspect(directory/'final.img')
    return {'mode':mode,'status':'PASS','observations':['injected backend request observed','read returns EIO','later filesystem operations reject with EIO','valid zero-length read succeeds','descriptor close succeeds','pipe bytes and memory allocation/free succeed','console and process snapshot progress','uncertain shutdown and QMP guest exit','persistent image unchanged']}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--qemu',default='qemu-system-riscv64')
    p.add_argument('--kernel',type=Path,default=Path('target/riscv64imac-unknown-none-elf/release/kernel'))
    p.add_argument('--firmware',type=Path,default=Path('build/fw_dynamic.bin'))
    p.add_argument('--program',type=Path,default=Path('target/riscv64imac-unknown-none-elf/release/fsfailure'))
    args=p.parse_args();output=args.output.resolve()
    if output.is_relative_to(Path(__file__).resolve().parents[1]):p.error('evidence must be outside candidate tree')
    report={'schema':1,'status':'INCOMPLETE','cases':[],'limitations':['NBD error 95 is an unsupported backend request outcome, not proof of a VirtIO status byte of 2.','No forged descriptor/used length, failed reset, or late-DMA corruption injection in these cases.']};made=False
    try:
        output.mkdir(parents=True,exist_ok=False);made=True
        qemu=probe('qemu-system-riscv64',args.qemu)
        if qemu['status']!='MATCH':raise RuntimeError('QEMU 11.1.3 required')
        args.qemu=qemu['path'];report['qemu']=qemu
        inputs=output/'inputs';inputs.mkdir();kernel=inputs/'kernel';firmware=inputs/'fw_dynamic.bin';program=inputs/'fsfailure'
        for source,destination in [(args.kernel,kernel),(args.firmware,firmware),(args.program,program)]:shutil.copyfile(source.resolve(strict=True),destination)
        report['kernel_sha256']=sha256(kernel);report['firmware_sha256']=sha256(firmware);report['program_sha256']=sha256(program)
        payload=inputs/'payload';payload.write_bytes(b'P'*4096)
        mkfs.create(inputs/'initial.img',uuid.UUID('4b465300-0001-4000-8000-0000000000f1').bytes,[('/fsfailure',program),('/payload',payload)])
        initial=(inputs/'initial.img').read_bytes()
        for mode in ['ioerr','unsupported','timeout']:
            result=one(args,mode,initial,kernel,firmware,output/mode);report['cases'].append(result)
            print(json.dumps(result),flush=True)
        report['status']='PASS'
    except Exception as error:report.update(status='INCOMPLETE' if isinstance(error,TimeoutError) else 'FAIL',reason=str(error))
    finally:
        if made:(output/'driver-fault-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2));return 0 if report['status']=='PASS' else 2


if __name__=='__main__':raise SystemExit(main())
