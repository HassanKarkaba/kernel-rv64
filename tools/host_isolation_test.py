#!/usr/bin/env python3
"""Actual launcher SIGTERM/SIGKILL tests with inherited image-lock observation."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import shutil
from accept import source_identity
from doctor import sha256
import mkfs
from run import locked_image


def lock_held(path):
    try:
        with locked_image(path):
            return False
    except BlockingIOError:
        return True


def qmp_connect(path):
    qmp=socket.socket(socket.AF_UNIX);qmp.settimeout(3);qmp.connect(str(path))
    qmp.recv(8192);qmp.sendall(b'{"execute":"qmp_capabilities"}\n');qmp.recv(8192)
    return qmp


def case(args, root, output, signum, sentinel):
    output.mkdir();image=output/'test.img';mkfs.create(image,bytes.fromhex('12121212121242128212121212121212'),[])
    before=sha256(image);child=None;qmp=None;launch=None;control=None
    command=[sys.executable,str(root/'tools/run.py'),'--image',str(image),'--kernel',str(args.kernel),'--firmware',str(args.firmware),'--qemu',args.qemu,'--output',str(output/'run'),'--run-root',str(output)]
    try:
        with (output/'launcher.log').open('xb') as log:
            child=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT)
            deadline=time.monotonic()+60
            serial=output/'run/serial.log'
            while not serial.exists() or b'\nREADY\r\n' not in serial.read_bytes():
                if child.poll() is not None or time.monotonic()>deadline:raise RuntimeError('launcher failed before READY')
                time.sleep(.02)
            launch=json.loads((output/'run/launch.json').read_text())
            qmp_arg=launch['command'][launch['command'].index('-qmp')+1]
            control=Path(qmp_arg.split(',',1)[0][5:]);qmp=qmp_connect(control)
            if not lock_held(image):raise AssertionError('image was not locked while launcher alive')
            child.send_signal(signum);exit_code=child.wait(timeout=10)
            if signum==signal.SIGTERM:
                result=json.loads((output/'run/result.json').read_text())
                if exit_code!=2 or result['status']!='INCOMPLETE' or not result['forced_termination'] or result.get('reason')!='operator signal 15':raise AssertionError('SIGTERM did not record bounded owned-child cleanup')
                if lock_held(image):raise AssertionError('image still locked after completed SIGTERM cleanup')
            else:
                if exit_code!=-signal.SIGKILL:raise AssertionError('owned launcher was not killed as requested')
                qmp.sendall(b'{"execute":"query-status","id":"after-parent-death"}\n')
                response=b''
                while b'after-parent-death' not in response:response+=qmp.recv(8192)
                if b'"running": true' not in response and b'"running":true' not in response:raise AssertionError('guest did not survive parent for lock test')
                if not lock_held(image):raise AssertionError('orphan guest lost the image lock')
                qmp.sendall(b'{"execute":"quit"}\n')
                deadline=time.monotonic()+5
                while lock_held(image):
                    if time.monotonic()>deadline:raise AssertionError('lock not released after owned guest quit')
                    time.sleep(.02)
            if sha256(image)!=before or sentinel.poll() is not None:raise AssertionError('test image or unrelated sentinel changed')
            return dict(name=signal.Signals(signum).name,status='PASS',command=command,launcher_exit=exit_code,image_sha256_before=before,image_sha256_after=sha256(image),qemu_pid=launch['qemu_pid'],guest_survived_parent=signum==signal.SIGKILL,lock_retained_until_guest_exit=True,unrelated_process_alive=True)
    finally:
        if child and child.poll() is None:child.terminate();child.wait(timeout=10)
        if qmp:
            try:qmp.sendall(b'{"execute":"quit"}\n')
            except OSError:pass
            qmp.close()
        # Exact PID comes from this launch; use only if its image is still locked.
        if launch and lock_held(image):
            try:os.kill(launch['qemu_pid'],signal.SIGTERM)
            except ProcessLookupError:pass
        if control and control.parent.name.startswith('krv-control-') and control.parent.parent.resolve()==Path(tempfile.gettempdir()).resolve():
            shutil.rmtree(control.parent,ignore_errors=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path);p.add_argument('--qemu',default='qemu-system-riscv64');p.add_argument('--kernel',type=Path,required=True);p.add_argument('--firmware',type=Path,required=True);args=p.parse_args()
    root=Path(__file__).resolve().parents[1];out=args.output.resolve()
    if out.is_relative_to(root):p.error('evidence must be outside source')
    out.mkdir(parents=True,exist_ok=False);report=dict(schema=1,status='INCOMPLETE',source_identity=source_identity(root),cases=[])
    executable=shutil.which(args.qemu)
    if executable is None:p.error("QEMU executable is not available: "+args.qemu)
    args.qemu=str(Path(executable).resolve(strict=True))
    args.kernel=args.kernel.resolve(strict=True);args.firmware=args.firmware.resolve(strict=True)
    sentinel=None
    try:
        ordinary=out/'ordinary.img';mkfs.create(ordinary,bytes.fromhex('34343434343444348434343434343434'),[]);original=sha256(ordinary)
        sentinel=subprocess.Popen([sys.executable,'-c','import time;time.sleep(180)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for signum in [signal.SIGTERM,signal.SIGKILL]:report['cases'].append(case(args,root,out/signal.Signals(signum).name,signum,sentinel))
        if sha256(ordinary)!=original:raise AssertionError('ordinary development fixture changed')
        report.update(status='PASS',ordinary_image_sha256=original,kernel_sha256=sha256(args.kernel),firmware_sha256=sha256(args.firmware),qemu_sha256=sha256(Path(args.qemu)),source_unchanged=source_identity(root)==report['source_identity'])
    except Exception as error:report.update(status='FAIL',reason=str(error))
    finally:
        if sentinel:sentinel.terminate();sentinel.wait(timeout=5)
        (out/'host-isolation-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2));return 0 if report['status']=='PASS' else 2
if __name__=='__main__':raise SystemExit(main())
