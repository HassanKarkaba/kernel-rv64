#!/usr/bin/env python3
"""Explicit checked-field corruption matrix: resealed metadata, independent refusal, real boot refusal.

This finite field/boundary matrix is not exhaustive over all malformed bitstrings.
Journal cases validate the complete redo description before any replay writes.
"""
import argparse,hashlib,io,json,shutil,struct,uuid
from pathlib import Path
import fsck,mkfs
from corruption_test import RefusalGuest,seal_region
from crash_test import sparse_output,logical
from doctor import probe,sha256
from smoke import Guest

B=4096

def fixture(directory):
    paths=[]
    for name,data in [('a',b'A'),('b',b'B'),('long',b'L'*(13*B))]:
        p=directory/name;p.write_bytes(data);paths.append(('/'+name,p))
    path=directory/'valid.img';mkfs.create(path,uuid.UUID('4b465300-0001-4000-8000-00000000c002').bytes,paths);base=path.read_bytes()
    journal=bytearray(base);volume=base[24:40];bitmap=bytearray(base[19*B:20*B]);struct.pack_into('<Q',bitmap,2048,1);mkfs.sealed(bitmap)
    payloads=[bitmap,base[20*B:21*B]];desc=bytearray(B);desc[:8]=b'KJDES001';desc[8:24]=volume;struct.pack_into('<QII',desc,24,1,2,1)
    for i,(target,data) in enumerate(zip([19,20],payloads)):
        struct.pack_into('<IIII',desc,64+i*16,target,i,mkfs.crc(data),0);journal[(3+i)*B:(4+i)*B]=data
    mkfs.sealed(desc);journal[2*B:3*B]=desc;commit=bytearray(512);commit[:8]=b'KJCOM001';commit[8:24]=volume;struct.pack_into('<IIQI',commit,24,1,2,1,struct.unpack_from('<I',desc,4092)[0]);mkfs.sealed(commit);journal[B:B+512]=commit
    if not fsck.Image(io.BytesIO(journal)).inspect()['needs_replay']:raise AssertionError('valid committed fixture not recognized')
    return base,bytes(journal)

def catalog(base,journal):
    result=[]
    def add(name,structure,field,changes,seals=(),source='base',desc=False,payload=False):
        result.append(dict(name=name,structure=structure,field=field,changes=changes,seals=seals,source=source,bind_descriptor=desc,bind_bitmap_payload=payload))
    def byte(name,structure,field,offset,value,start,length,source='base',desc=False):add(name,structure,field,[(offset,bytes([value]))],[(start,length)],source,desc)
    def number(name,structure,field,offset,value,fmt,start,length,source='base',desc=False):add(name,structure,field,[(offset,struct.pack(fmt,value))],[(start,length)],source,desc)
    # Fixed geometry fields are each checked independently with a valid checksum.
    for offset,label in [(12,'block_size'),(40,'sector_size'),(44,'inode_count'),(48,'directory_count'),(52,'journal_capacity'),(56,'commit_block'),(60,'descriptor_block'),(64,'payload_start'),(68,'bitmap_block'),(72,'inode_start'),(76,'inode_blocks'),(80,'directory_start'),(84,'directory_blocks'),(88,'data_start'),(92,'feature_flags')]:
        number('super_'+label,'superblock',label,offset,struct.unpack_from('<I',base,offset)[0]+1,'<I',0,B)
    number('super_block_count','superblock','block_count',16,16385,'<Q',0,B)
    number('super_version','superblock','version',8,2,'<I',0,B)
    byte('super_magic','superblock','magic',0,0,0,B);byte('super_padding_first','superblock','padding_start',96,1,0,B);byte('super_padding_last','superblock','padding_end',4091,1,0,B)
    add('super_checksum','superblock','checksum',[(4092,bytes([base[4092]^1]))])
    bm=19*B
    for label,offset,value in [('reserved_allocation',0,base[bm]&254),('missing_data_allocation',4,base[bm+4]&254),('unowned_allocation',100//8,base[bm+100//8]|(1<<(100%8))),('padding_first',2056,1),('padding_last',4091,1)]:byte('bitmap_'+label,'bitmap',label,bm+offset,value,bm,B)
    add('bitmap_checksum','bitmap','checksum',[(bm+4092,bytes([base[bm+4092]^1]))])
    ino=20*B;long=ino+256;unused=ino+384;indirect=struct.unpack_from('<I',base,long+64)[0]*B
    for label,offset,value in [('live_flag',0,2),('flags_padding',1,1),('padding_first',68,1),('padding_last',123,1)]:byte('inode_'+label,'inode',label,ino+offset,value,ino,128)
    for label,offset,value,fmt in [('oversize',4,4194305,'<I'),('live_generation_zero',8,0,'<Q'),('missing_data_pointer',16,0,'<I'),('reserved_data_pointer',16,19,'<I'),('out_of_range_data_pointer',16,16384,'<I'),('unused_direct_pointer',20,33,'<I'),('unexpected_indirect',64,indirect//B,'<I')]:number('inode_'+label,'inode',label,ino+offset,value,fmt,ino,128)
    for label,offset,value in [('inactive_size',4,1),('inactive_direct',16,32),('inactive_indirect',64,indirect//B)]:number('inode_'+label,'inactive_inode',label,unused+offset,value,'<I',unused,128)
    for label,value in [('missing',0),('reserved',19),('out_of_range',16384)]:number('inode_indirect_'+label,'inode','indirect_'+label,long+64,value,'<I',long,128)
    number('inode_duplicate_data','inode','duplicate_data_owner',ino+128+16,32,'<I',ino+128,128)
    add('inode_checksum','inode','checksum',[(ino+124,bytes([base[ino+124]^1]))])
    for label,offset,value in [('missing_pointer',0,0),('reserved_pointer',0,19),('out_of_range_pointer',0,16384),('duplicate_pointer',0,32),('unused_pointer',4,32),('trailing_pointer',1012*4,32)]:add('indirect_'+label,'indirect',label,[(indirect+offset,struct.pack('<I',value))])
    d=28*B
    for label,offset,value,fmt in [('inode_zero',0,0,'<H'),('inode_out_of_range',0,257,'<H'),('length_zero',2,0,'<B'),('length_too_long',2,48,'<B'),('flags',3,1,'<B'),('generation_zero',4,0,'<Q'),('generation_mismatch',4,2,'<Q'),('unlinked_inode',0,4,'<H')]:number('directory_'+label,'directory',label,d+offset,value,fmt,d,64)
    for label,offset,value in [('name_dot',12,ord('.')),('name_slash',12,ord('/')),('name_nonascii',12,255),('padding_first',13,1),('padding_last',59,1)]:byte('directory_'+label,'directory',label,d+offset,value,d,64)
    add('directory_name_dotdot','directory','name_dotdot',[(d+2,b'\2'),(d+12,b'..')],[(d,64)])
    number('directory_duplicate_inode','namespace','one_link_per_inode',d+64,1,'<H',d+64,64)
    byte('directory_duplicate_name','namespace','unique_name',d+64+12,ord('a'),d+64,64)
    add('directory_live_orphan','namespace','live_inode_bijection',[(d,bytes(64))])
    add('directory_checksum','directory','checksum',[(d+60,bytes([base[d+60]^1]))])
    add('data_nonzero_eof_tail','data','zero_after_eof',[(32*B+1,b'X')])
    # Header/payload checksums are recomputed except when that checksum is the field under test.
    c=B;q=2*B
    for label,offset,value,fmt in [('version',24,2,'<I'),('count_zero',28,0,'<I'),('count_too_large',28,17,'<I'),('sequence_zero',32,0,'<Q'),('descriptor_checksum_binding',40,struct.unpack_from('<I',journal,c+40)[0]^1,'<I')]:number('commit_'+label,'commit',label,c+offset,value,fmt,c,512,'journal')
    for label,offset,value in [('magic',0,0),('uuid',8,journal[c+8]^1),('padding_first',44,1),('padding_last',507,1)]:byte('commit_'+label,'commit',label,c+offset,value,c,512,'journal')
    add('commit_checksum','commit','checksum',[(c+508,bytes([journal[c+508]^1]))],source='journal')
    for offset in [512,4095]:add('commit_block_padding_'+str(offset),'commit_block','padding_'+str(offset),[(c+offset,b'X')],source='journal')
    for label,offset,value,fmt in [('sequence_binding',24,2,'<Q'),('count_binding',32,1,'<I'),('version',36,2,'<I'),('target_reserved',64,18,'<I'),('target_out_of_range',80,16384,'<I'),('target_duplicate',80,19,'<I'),('target_descending',80,18,'<I'),('target_bitmap_missing',64,20,'<I'),('payload_index',68,1,'<I'),('entry_reserved',76,1,'<I'),('payload_checksum',72,struct.unpack_from('<I',journal,q+72)[0]^1,'<I')]:number('descriptor_'+label,'descriptor',label,q+offset,value,fmt,q,B,'journal',True)
    for label,offset,value in [('magic',0,0),('uuid',8,journal[q+8]^1),('header_padding_first',40,1),('header_padding_last',63,1),('unused_entry',96,1),('padding_last',4091,1)]:byte('descriptor_'+label,'descriptor',label,q+offset,value,q,B,'journal',True)
    add('descriptor_checksum','descriptor','checksum',[(q+4092,bytes([journal[q+4092]^1]))],source='journal')
    add('payload_checksum','payload','checksum',[(4*B+100,bytes([journal[4*B+100]^1]))],source='journal')
    add('payload_bitmap_sequence','payload_bitmap','sequence_binding',[(3*B+2048,struct.pack('<Q',2))],[(3*B,B)],'journal',True,True)
    add('payload_bitmap_reserved','payload_bitmap','reserved_allocation',[(3*B,b'\xfe')],[(3*B,B)],'journal',True,True)
    add('payload_bitmap_padding','payload_bitmap','padding',[(3*B+2056,b'X')],[(3*B,B)],'journal',True,True)
    add('payload_bitmap_checksum','payload_bitmap','checksum',[(3*B+4092,bytes([journal[3*B+4092]^1]))],[],'journal',True,True)
    # Three legal distinct targets isolate descending order while preserving
    # bitmap-first and valid payloads for every referenced home block.
    descending=next(case for case in result if case['name']=='descriptor_target_descending')
    second=base[21*B:22*B];third=base[20*B:21*B]
    descending['changes']=[(c+28,struct.pack('<I',3)),(q+32,struct.pack('<I',3)),(q+80,struct.pack('<IIII',21,1,mkfs.crc(second),0)),(q+96,struct.pack('<IIII',20,2,mkfs.crc(third),0)),(4*B,second),(5*B,third)]
    descending['seals']=[(c,512),(q,B)]
    # Preserve ordering when testing absence of the mandatory bitmap target.
    missing=next(case for case in result if case['name']=='descriptor_target_bitmap_missing')
    missing['changes'].append((q+80,struct.pack('<I',21)))
    if len({r['name'] for r in result})!=len(result):raise AssertionError('duplicate case name')
    return result

def materialize(case,base,journal):
    image=bytearray(journal if case['source']=='journal' else base)
    for offset,data in case['changes']:image[offset:offset+len(data)]=data
    for start,length in case['seals']:seal_region(image,start,length)
    if case['bind_bitmap_payload']:struct.pack_into('<I',image,2*B+72,mkfs.crc(image[3*B:4*B]))
    if case['bind_descriptor']:
        seal_region(image,2*B,B);struct.pack_into('<I',image,B+40,struct.unpack_from('<I',image,3*B-4)[0]);seal_region(image,B,512)
    return image

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--qemu',default='qemu-system-riscv64');p.add_argument('--kernel',type=Path,default=Path('target/riscv64imac-unknown-none-elf/release/kernel'));p.add_argument('--firmware',type=Path,default=Path('build/fw_dynamic.bin'));args=p.parse_args();output=args.output.resolve();root=Path(__file__).resolve().parents[1]
    if output.is_relative_to(root):p.error('evidence must be outside source')
    output.mkdir(parents=True,exist_ok=False);report={'schema':1,'status':'INCOMPLETE','scope':__doc__,'cases':[],'controls':[],'limitations':['Finite checked-field and selected bound matrix; not all malformed bitstrings or every pair of simultaneous corruptions.','Image-length/device-capacity refusal is covered by platform/device fixtures, not this64MiB metadata matrix.']}
    try:
        qemu=probe('qemu-system-riscv64',args.qemu);report['qemu']=qemu
        if qemu['status']!='MATCH':raise RuntimeError('pinned QEMU11.1.3 required')
        inputs=output/'inputs';inputs.mkdir();kernel=inputs/'kernel';firmware=inputs/'fw_dynamic.bin';shutil.copyfile(args.kernel.resolve(strict=True),kernel);shutil.copyfile(args.firmware.resolve(strict=True),firmware);report.update(kernel_sha256=sha256(kernel),firmware_sha256=sha256(firmware));base,journal=fixture(inputs)
        for name,image in [('valid_base',base),('valid_committed',journal)]:
            directory=output/name;directory.mkdir();path=directory/'image.img';sparse_output(path,image);expected=fsck.inspect(path);guest=Guest(qemu['path'],kernel,firmware,path,directory/'guest')
            try:guest.boot();guest.shutdown()
            finally:guest.close()
            actual=fsck.inspect(path)
            if actual['needs_replay'] or logical(actual)!=logical(expected):raise AssertionError('valid control changed logical state')
            report['controls'].append({'name':name,'status':'PASS','before_sha256':hashlib.sha256(image).hexdigest(),'after_sha256':sha256(path)})
        entries=catalog(base,journal);report['required_cases']=len(entries)
        for case in entries:
            image=materialize(case,base,journal);directory=output/case['name'];directory.mkdir();path=directory/'bad.img';sparse_output(path,image);before=sha256(path)
            try:fsck.inspect(path)
            except fsck.Corruption as error:reason=str(error)
            else:raise AssertionError('independent decoder accepted '+case['name'])
            guest=RefusalGuest(qemu['path'],kernel,firmware,path,directory/'guest')
            try:
                guest.expect(rb'Recovery console: status help shutdown\r?\n')
                if b'\nREADY\r\n' in guest.data:raise AssertionError('malformed image admitted users')
                guest.child.stdin.write(b'status\r');guest.child.stdin.flush();guest.expect(rb'FAILED recovery required\r?\n');guest.shutdown()
            finally:guest.close()
            if sha256(path)!=before:raise AssertionError('refusal mutated image '+case['name'])
            record={'name':case['name'],'structure':case['structure'],'field':case['field'],'source':case['source'],'status':'PASS','image_sha256':before,'independent_reason':reason,'mutation_bytes':[{'offset':offset,'hex':data.hex()} for offset,data in case['changes']],'resealed_regions':case['seals'],'descriptor_binding_updated':case['bind_descriptor'],'bitmap_payload_checksum_updated':case['bind_bitmap_payload']};report['cases'].append(record);print(json.dumps(record),flush=True)
        report.update(status='PASS',completed_cases=len(report['cases']))
    except Exception as error:report.update(status='INCOMPLETE' if isinstance(error,TimeoutError) else 'FAIL',reason=str(error))
    (output/'corruption-matrix-report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ['cases','controls']},indent=2));return 0 if report['status']=='PASS' else 2

if __name__=='__main__':raise SystemExit(main())
