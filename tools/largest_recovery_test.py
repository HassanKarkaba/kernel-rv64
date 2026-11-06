#!/usr/bin/env python3
"""Time actual guest recovery of a full KFS image with all 16 redo slots used."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import struct
import uuid
import fsck
import mkfs
from crash_test import logical, sparse_output
from doctor import probe, sha256
from recovery_test import nbd_boot


def fixture(directory):
    """256 files, 16 indirect blocks, every disk allocation bit set."""
    large=directory/'four-mib';large.write_bytes(bytes(range(256))*16384)
    rest=directory/'tail';rest.write_bytes(bytes(range(256))*15616)
    empty=directory/'empty';empty.write_bytes(b'')
    files=[(f'/f{i:03d}',large if i<15 else rest if i==15 else empty) for i in range(256)]
    path=directory/'before.img'
    volume=uuid.UUID('a4000000-0000-4000-8000-000000000016').bytes
    created=mkfs.create(path,volume,files)
    if created['used_blocks']!=16384:raise AssertionError('fixture does not fill allocation capacity')
    image=bytearray(path.read_bytes());targets=[19]+list(range(32,47));images=[]
    bitmap=bytearray(image[19*4096:20*4096]);struct.pack_into('<Q',bitmap,2048,1);mkfs.sealed(bitmap)
    images.append(bitmap)
    for target in targets[1:]:images.append(bytearray(bytes([target])*4096))
    desc=bytearray(4096);desc[:8]=b'KJDES001';desc[8:24]=volume
    struct.pack_into('<QII',desc,24,1,16,1)
    for index,(target,payload) in enumerate(zip(targets,images)):
        struct.pack_into('<IIII',desc,64+16*index,target,index,mkfs.crc(payload),0)
        image[(3+index)*4096:(4+index)*4096]=payload
    mkfs.sealed(desc);image[2*4096:3*4096]=desc
    commit=bytearray(512);commit[:8]=b'KJCOM001';commit[8:24]=volume
    struct.pack_into('<IIQI',commit,24,1,16,1,struct.unpack_from('<I',desc,4092)[0]);mkfs.sealed(commit)
    image[4096:4096+512]=commit
    sparse_output(directory/'committed.img',image)
    expected=fsck.Image(io.BytesIO(image)).inspect()
    if not expected['needs_replay'] or expected['used_blocks']!=16384 or len(expected['files'])!=256:
        raise AssertionError('largest image fixture failed independent validation')
    (directory/'expected.json').write_text(json.dumps(expected,indent=2)+'\n')
    return image,expected,targets


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--qemu',default='qemu-system-riscv64')
    p.add_argument('--kernel',type=Path,default=Path('target/riscv64imac-unknown-none-elf/release/kernel'))
    p.add_argument('--firmware',type=Path,default=Path('build/fw_dynamic.bin'))
    args=p.parse_args();output=args.output.resolve()
    if output.is_relative_to(Path(__file__).resolve().parents[1]):p.error('evidence must be outside source candidate')
    report={'schema':1,'status':'INCOMPLETE','scope':'Maximum occupancy image with 16 committed redo payloads; real guest recovery and full mount scan','limit_seconds':180};made=False
    try:
        output.mkdir(parents=True,exist_ok=False);made=True
        qemu=probe('qemu-system-riscv64',args.qemu)
        if qemu['status']!='MATCH':raise RuntimeError('QEMU 11.1.3 required')
        args.qemu=qemu['path'];report['qemu']=qemu
        inputs=output/'inputs';inputs.mkdir();kernel=inputs/'kernel';firmware=inputs/'fw_dynamic.bin'
        for source,dest in [(args.kernel,kernel),(args.firmware,firmware)]:shutil.copyfile(source.resolve(strict=True),dest)
        report['kernel_sha256']=sha256(kernel);report['firmware_sha256']=sha256(firmware)
        initial,expected,targets=fixture(inputs)
        report.update(image_bytes=len(initial),allocated_blocks=expected['used_blocks'],live_files=len(expected['files']),indirect_blocks=16,redo_count=len(targets),redo_targets=targets,committed_sha256=hashlib.sha256(initial).hexdigest())
        outcome,records=nbd_boot(args,initial,kernel,firmware,output/'boot')
        ready=next(record for record in records if record['event']=='recovery_ready')
        before_ready=[record for record in records if record['sequence']<ready['sequence']]
        reads=[record for record in before_ready if record['event']=='request_submission' and record['command']==0]
        report.update(boot_to_ready_host_seconds=ready['elapsed_host_seconds'],block_read_requests_before_ready=len(reads),block_read_bytes_before_ready=sum(record['length'] for record in reads),measurement='Host monotonic time from QEMU process start through recovery, mount scan, READY and first shell prompt; excludes DTB preflight. Read bytes count every NBD READ request including repeated reads.')
        actual=fsck.Image(io.BytesIO(outcome)).inspect()
        if actual['needs_replay'] or logical(actual)!=logical(expected):raise AssertionError('recovered image differs from independent committed-state oracle')
        if report['boot_to_ready_host_seconds']>180:raise AssertionError('180 second ready deadline exceeded')
        (output/'after.json').write_text(json.dumps(actual,indent=2)+'\n')
        report.update(status='PASS',after_sha256=hashlib.sha256(outcome).hexdigest())
    except Exception as error:report.update(status='INCOMPLETE' if isinstance(error,TimeoutError) else 'FAIL',reason=str(error))
    finally:
        if made:(output/'largest-recovery-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return 0 if report['status']=='PASS' else 2


if __name__=='__main__':raise SystemExit(main())
