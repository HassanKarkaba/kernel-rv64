#!/usr/bin/env python3
"""Real-kernel refusal of malformed KFS images and sequence-exhaustion behavior."""
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
from crash_test import sparse_output
from recovery_test import reconstruct
from smoke import Guest
from doctor import probe,sha256


class RefusalGuest(Guest):
    def pump(self,timeout):
        try:
            super().pump(timeout)
        except RuntimeError:
            expected=b'BOOT_FAILED phase=mount reason=FILESYSTEM_MOUNT'
            if b'KERNEL_PANIC' in self.data:
                raise
            marker=self.data.find(b'BOOT_FAILED')
            if marker<0:
                raise
            tail=self.data[marker:]
            if b'\n' not in tail:
                return
            if expected not in tail.split(b'\n',1)[0]:
                raise


def seal_region(image,start,length):
    struct.pack_into('<I',image,start+length-4,mkfs.crc(image[start:start+length-4]))


def cases(base,journal):
    image=bytearray(base);struct.pack_into('<I',image,8,2);seal_region(image,0,4096)
    yield 'unsupported_version',image
    image=bytearray(base);image[4096]=1
    yield 'malformed_commit',image
    image=bytearray(base);image[19*4096+100//8]|=1<<(100%8);seal_region(image,19*4096,4096)
    yield 'stray_allocation',image
    image=bytearray(base);struct.pack_into('<I',image,20*4096+128+16,32);seal_region(image,20*4096+128,128)
    yield 'duplicate_data_owner',image
    image=bytearray(base);struct.pack_into('<Q',image,28*4096+4,2);seal_region(image,28*4096,64)
    yield 'directory_generation_mismatch',image
    image=bytearray(base);image[20*4096+68]=1;seal_region(image,20*4096,128)
    yield 'inode_padding',image
    image=bytearray(base);image[32*4096+1]=1
    yield 'nonzero_after_eof',image
    image=bytearray(base);image[19*4096+50]^=1
    yield 'metadata_checksum',image
    image=bytearray(journal);image[4096+256:4096+512]=bytes(256)
    yield 'torn_commit_sector',image
    image=bytearray(journal);image[4096+8]^=1;seal_region(image,4096,512)
    yield 'wrong_journal_uuid',image
    image=bytearray(journal);image[3*4096+100]^=1
    yield 'journal_payload_checksum',image
    for name,target in [('forged_reserved_target',0),('duplicate_journal_target',19)]:
        image=bytearray(journal);entry=64 if target==0 else 80
        struct.pack_into('<I',image,2*4096+entry,target);seal_region(image,2*4096,4096)
        descriptor_crc=struct.unpack_from('<I',image,2*4096+4092)[0]
        struct.pack_into('<I',image,4096+40,descriptor_crc);seal_region(image,4096,512)
        yield name,image


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--source-run',type=Path,required=True)
    p.add_argument('--source-case',type=int,help='default: first committed/replayed case in source report')
    p.add_argument('--qemu',default='qemu-system-riscv64')
    p.add_argument('--kernel',type=Path,default=Path('target/riscv64imac-unknown-none-elf/release/kernel'))
    p.add_argument('--firmware',type=Path,default=Path('build/fw_dynamic.bin'))
    args=p.parse_args();output=args.output.resolve()
    if output.is_relative_to(Path(__file__).resolve().parents[1]):p.error('evidence must be outside source candidate')
    report={'schema':1,'status':'INCOMPLETE','cases':[],'limitations':['Corruption cases lie outside the atomic-sector power-loss model and establish refusal only for the named checked corruptions.']};made=False
    try:
        output.mkdir(parents=True,exist_ok=False);made=True
        qemu=probe('qemu-system-riscv64',args.qemu)
        if qemu['status']!='MATCH':raise RuntimeError('QEMU 11.1.3 required')
        report['qemu']=qemu;inputs=output/'inputs';inputs.mkdir();kernel=inputs/'kernel';firmware=inputs/'fw_dynamic.bin'
        for source,destination in [(args.kernel,kernel),(args.firmware,firmware)]:shutil.copyfile(source.resolve(strict=True),destination)
        report['kernel_sha256']=sha256(kernel);report['firmware_sha256']=sha256(firmware)
        a=inputs/'a';b=inputs/'b';a.write_bytes(b'A');b.write_bytes(b'B')
        mkfs.create(inputs/'base.img',uuid.UUID('4b465300-0001-4000-8000-0000000000c0').bytes,[('/a',a),('/b',b)])
        base=(inputs/'base.img').read_bytes()
        source_run=args.source_run.resolve(strict=True)
        source_case=args.source_case
        if source_case is None:
            source_report=json.loads((source_run/'crash-report.json').read_text())
            source_case=next(case['index'] for case in source_report['cases'] if case.get('replayed'))
        journal,_=reconstruct(source_run,source_case)
        report['source_case']=source_case
        for name,image in cases(base,journal):
            directory=output/name;directory.mkdir();path=directory/'bad.img';sparse_output(path,image);before=sha256(path)
            try:fsck.inspect(path)
            except fsck.Corruption:pass
            else:raise AssertionError(name+' not rejected by independent decoder')
            guest=RefusalGuest(qemu['path'],kernel,firmware,path,directory/'guest')
            try:
                guest.expect(rb'Recovery console: status help shutdown\r?\n')
                if b'\nREADY\r\n' in guest.data:raise AssertionError('corrupt mount admitted users')
                guest.child.stdin.write(b'status\r');guest.child.stdin.flush()
                guest.expect(rb'FAILED recovery required\r?\n')
                guest.shutdown()
            finally:guest.close()
            if sha256(path)!=before:raise AssertionError(name+' silently changed the rejected image')
            record={'name':name,'status':'PASS','image_sha256':before,'observations':['independent decoder refusal','kernel mount refusal before READY','restricted status console','guest shutdown','image unchanged']}
            report['cases'].append(record);print(json.dumps(record),flush=True)
        directory=output/'sequence_exhaustion';directory.mkdir();image=bytearray(base)
        struct.pack_into('<Q',image,19*4096+2048,2**64-1);seal_region(image,19*4096,4096)
        path=directory/'readonly.img';sparse_output(path,image);before=sha256(path)
        guest=Guest(qemu['path'],kernel,firmware,path,directory/'guest')
        try:
            guest.boot();guest.issue('ls',b'/a');guest.issue('cat /a',b'A')
            for command in ['write /a nope','mv /a /a','rm /a']:
                guest.child.stdin.write(command.encode()+b'\r');guest.child.stdin.flush();reply=guest.expect(rb'> ')
                if b'error -30' not in reply:raise AssertionError('readonly mutation did not return EROFS')
            guest.issue('cat /a',b'A');guest.shutdown()
            if b'SHUTDOWN_CLEAN' not in guest.data:raise AssertionError('healthy read-only shutdown was not clean')
        finally:guest.close()
        if sha256(path)!=before:raise AssertionError('read-only operations changed disk')
        report['cases'].append({'name':'sequence_exhaustion','status':'PASS','observations':['READY in read-only state','reads/list work','write/create/same-name rename/unlink return EROFS','clean shutdown','image unchanged']})
        report['status']='PASS'
    except Exception as error:report.update(status='INCOMPLETE' if isinstance(error,TimeoutError) else 'FAIL',reason=str(error))
    finally:
        if made:(output/'corruption-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='cases'},indent=2));return 0 if report['status']=='PASS' else 2


if __name__=='__main__':raise SystemExit(main())
