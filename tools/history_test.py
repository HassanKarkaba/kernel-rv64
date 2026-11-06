#!/usr/bin/env python3
"""Seeded filesystem histories with an independent serial model and real replay.

Default coverage is 100 histories x 100 operations and 20 modeled crash cuts per
history. Each history crosses the twelfth data block into indirect addressing.
Smaller explicit development budgets retain INCOMPLETE status.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import random
import re
import shutil
import socket
import tempfile
import threading
import uuid

import fsck
import mkfs
import nbd_fault as nbd
from crash_test import NbdGuest, logical, sparse_output
from doctor import probe, sha256
from smoke import Guest


class MemoryFile:
    def __init__(self,data):self.data=data;self.position=0
    def seek(self,offset,whence=0):
        self.position=offset if whence==0 else self.position+offset if whence==1 else len(self.data)+offset
        return self.position
    def tell(self):return self.position
    def read(self,length=-1):
        if length<0:length=len(self.data)-self.position
        result=bytes(self.data[self.position:self.position+length]);self.position+=len(result);return result


def inspect_bytes(data):return fsck.Image(MemoryFile(data)).inspect()
def pattern(length,value):return bytes((value+i%251)&255 for i in range(length))
def fnv(data):
    value=0xcbf29ce484222325
    for byte in data:value=((value^byte)*0x100000001b3)&((1<<64)-1)
    return value


class Model:
    def __init__(self,files):
        self.files={}
        self.generations=[0]*257
        self.sequence=0
        for inode,(name,data) in enumerate(sorted(files.items()),1):
            self.files[name]=(inode,1,data);self.generations[inode]=1
    def signature(self):
        return (self.sequence,tuple((name,inode,generation,len(data),hashlib.sha256(data).hexdigest()) for name,(inode,generation,data) in sorted(self.files.items())))
    def apply(self,operation):
        kind=operation['kind'];name=operation['name']
        if kind=='create':
            if name in self.files:raise ValueError('model create collision')
            used={inode for inode,_,_ in self.files.values()}
            inode=next(n for n in range(1,257) if n not in used)
            self.generations[inode]+=1;self.files[name]=(inode,self.generations[inode],b'');self.sequence+=1
        elif kind in ('write','append'):
            inode,generation,data=self.files[name]
            offset=operation['offset'];content=pattern(operation['length'],operation['value'])
            if not 0<=offset<=len(data):raise ValueError('model sparse write')
            new=data[:offset]+content+data[offset+len(content):]
            self.files[name]=(inode,generation,new)
            if content:self.sequence+=1
        elif kind=='read':
            data=self.files[name][2]
            start=operation['offset'];length=operation['length']
            if len(data[start:start+length])!=length:raise ValueError('model read outside file')
            operation['expected']=fnv(data[start:start+length])
        elif kind=='truncate':
            inode,generation,data=self.files[name]
            self.files[name]=(inode,generation,b'')
            if data:self.sequence+=1
        elif kind=='rename':
            destination=operation['destination']
            if name!=destination:
                item=self.files.pop(name);self.files.pop(destination,None);self.files[destination]=item;self.sequence+=1
        elif kind=='unlink':
            del self.files[name];self.sequence+=1
        else:raise ValueError(kind)
    def command(self,operation):
        kind=operation['kind'];name=operation['name']
        if kind in ('write','append'):return f'run /fswork write {name} {operation["offset"]} {operation["length"]} {operation["value"]}'
        if kind=='read':return f'run /fswork read {name} {operation["offset"]} {operation["length"]} {operation["expected"]}'
        if kind=='rename':return f'run /fswork rename {name} {operation["destination"]}'
        return f'run /fswork {kind} {name}'


def history(seed,files,count):
    rng=random.Random(seed);model=Model(files);operations=[];states=[model.signature()]
    mandatory=[{'kind':'append','name':'/h0','offset':49152,'length':4096,'value':seed%256},
               {'kind':'write','name':'/h0','offset':4093,'length':4096,'value':(seed+31)%256},
               {'kind':'read','name':'/h0','offset':4093,'length':4096},
               {'kind':'create','name':'/h1'},
               {'kind':'rename','name':'/h0','destination':'/h1'},
               {'kind':'truncate','name':'/h1'},
               {'kind':'unlink','name':'/h1'}]
    for index in range(count):
        if index<len(mandatory):op=mandatory[index].copy()
        else:
            existing=sorted(name for name in model.files if name.startswith('/h'))
            absent=[f'/h{i}' for i in range(8) if f'/h{i}' not in model.files]
            kind=rng.choice(['create','read','write','append','truncate','rename','unlink'])
            if not existing:kind='create'
            if kind=='create' and not absent:kind='write'
            name=rng.choice(absent if kind=='create' else existing)
            op={'kind':kind,'name':name}
            if kind in ('write','append'):
                size=len(model.files[name][2]);offset=size if kind=='append' else rng.randrange(size+1)
                op.update(offset=offset,length=rng.choice([1,17,511,1025,4096]),value=rng.randrange(256))
            elif kind=='read':
                size=len(model.files[name][2]);offset=rng.randrange(size+1)
                op.update(offset=offset,length=rng.randrange(min(4096,size-offset)+1))
            elif kind=='rename':
                op['destination']=rng.choice([f'/h{i}' for i in range(8) if f'/h{i}'!=name])
        model.apply(op);op['command']=model.command(op);operations.append(op);states.append(model.signature())
    return operations,states


def capture(args,initial,kernel,firmware,output,operations,states):
    errors=[]
    with tempfile.TemporaryDirectory(prefix='krv-history-') as temporary,(output/'nbd.jsonl').open('x') as log:
        trace=nbd.Trace(log);store=nbd.SectorStore(initial,trace);path=Path(temporary)/'disk.sock'
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
            listener.bind(str(path));listener.listen(1);listener.settimeout(60)
            def serve():
                try:
                    connection,_=listener.accept()
                    with connection:
                        connection.settimeout(180);nbd.session(connection,store)
                except EOFError:pass
                except Exception as error:errors.append(str(error))
            thread=threading.Thread(target=serve,daemon=True);thread.start()
            guest=NbdGuest(args.qemu,kernel,firmware,path,output/'capture')
            try:
                guest.boot()
                if logical(inspect_bytes(store.stable))!=states[0]:raise AssertionError('initial image disagrees with independent model')
                for index,op in enumerate(operations):
                    trace.emit('operation_begin',operation=index,kind=op['kind'])
                    reply=guest.issue(op['command'],b'FSWORK OK')
                    if not re.search(rb'child \d+ ended kind=0 code=0',reply):raise AssertionError('fswork did not exit successfully')
                    actual=inspect_bytes(store.stable)
                    if logical(actual)!=states[index+1]:raise AssertionError(f'operation {index} diverged from independent serial model')
                    trace.emit('guest_ack',operation=index,sequence_expected=states[index+1][0])
                guest.shutdown()
            finally:guest.close()
            thread.join(10)
            if thread.is_alive():raise RuntimeError('history backend still running')
            if errors:raise RuntimeError(errors[0])
        final,_=store.outcome('none');sparse_output(output/'final.img',final)
    return [json.loads(line) for line in (output/'nbd.jsonl').read_text().splitlines()]


def choose_cuts(records,seed,count):
    candidates=[];first=[];operation=-1;command=None
    for record in records:
        event=record['event']
        if event=='operation_begin':operation=record['operation']
        if event=='request_submission':command=record['command']
        if operation>=0 and command in (1,3) and event in ('request_submission','sector_issue','request_completion','flush_completion','reply_sent'):
            candidates.append(record['sequence'])
            if operation==0:first.append(record['sequence'])
    if len(candidates)<count:raise ValueError('history has fewer requested fault cut events')
    rng=random.Random(seed^0xC4A5);selected={rng.choice(first)}
    selected.update(rng.sample([n for n in candidates if n not in selected],count-1))
    return selected


def cut_states(initial,records,cuts):
    stable=bytearray(initial);pending=[];active=-1;ack=-1
    for record in records:
        event=record['event']
        if event=='operation_begin':active=record['operation']
        elif event=='guest_ack':ack=record['operation']
        elif event=='sector_issue':pending.append((record['version'],record['sector'],base64.b64decode(record['data'],validate=True)))
        elif event=='flush_completion':
            for _,sector,data in pending:stable[sector*512:(sector+1)*512]=data
            pending=[]
        if record['sequence'] in cuts:yield record,stable,pending,active,ack


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',choices=('seeded-history',),default='seeded-history')
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--qemu',default='qemu-system-riscv64')
    parser.add_argument('--kernel',type=Path,default=Path('target/riscv64imac-unknown-none-elf/release/kernel'))
    parser.add_argument('--firmware',type=Path,default=Path('build/fw_dynamic.bin'))
    parser.add_argument('--fswork',type=Path,default=Path('target/riscv64imac-unknown-none-elf/release/fswork'))
    parser.add_argument('--seed',type=int,default=1)
    parser.add_argument('--histories',type=int,default=100)
    parser.add_argument('--operations',type=int,default=100)
    parser.add_argument('--cuts',type=int,default=20)
    args=parser.parse_args();output=args.output.resolve()
    if output.is_relative_to(Path(__file__).resolve().parents[1]):parser.error('evidence must be outside candidate tree')
    if min(args.histories,args.operations,args.cuts)<1:parser.error('coverage counts must be positive')
    report={'schema':1,'status':'INCOMPLETE','scope':'Independent serial-model seeded histories and actual guest crash recovery','histories':[],
            'requested_histories':args.histories,'operations_per_history':args.operations,'cuts_per_history':args.cuts,'seed':args.seed}
    made=False
    try:
        output.mkdir(parents=True,exist_ok=False);made=True
        qemu=probe('qemu-system-riscv64',args.qemu)
        if qemu['status']!='MATCH':raise RuntimeError('QEMU 11.1.3 required')
        args.qemu=qemu['path'];report['qemu']=qemu
        inputs=output/'inputs';inputs.mkdir();kernel=inputs/'kernel';firmware=inputs/'fw_dynamic.bin';program=inputs/'fswork'
        for source,destination in [(args.kernel,kernel),(args.firmware,firmware),(args.fswork,program)]:shutil.copyfile(source.resolve(strict=True),destination)
        report['kernel_sha256']=sha256(kernel);report['firmware_sha256']=sha256(firmware);report['fswork_sha256']=sha256(program)
        program_bytes=program.read_bytes()
        for number in range(args.histories):
            seed=args.seed+number;directory=output/f'history-{number:03d}';directory.mkdir()
            initial_data=pattern(12*4096,seed%256);payload=directory/'initial-h0';payload.write_bytes(initial_data)
            files={'/fswork':program_bytes,'/h0':initial_data}
            operations,states=history(seed,files,args.operations)
            (directory/'operations.json').write_text(json.dumps({'seed':seed,'operations':operations,'expected_states':states},indent=2)+'\n')
            image_path=directory/'initial.img';mkfs.create(image_path,uuid.UUID(int=0x4b465300000140008000000000000000+seed).bytes,[('/fswork',program),('/h0',payload)])
            initial=image_path.read_bytes();records=capture(args,initial,kernel,firmware,directory,operations,states)
            cuts=choose_cuts(records,seed,args.cuts);rng=random.Random(seed^0xA5C4)
            item={'seed':seed,'status':'INCOMPLETE','operations':len(operations),'cuts':[],'indirect_crossing':'first append extends exactly 12 to 13 data blocks'};report['histories'].append(item)
            for index,(record,stable,pending,active,ack) in enumerate(cut_states(initial,records,cuts)):
                selected=[v for v,_,_ in pending if index==1 or index>1 and rng.getrandbits(1)]
                chosen=set(selected);candidate=bytearray(stable)
                for version,sector,data in pending:
                    if version in chosen:candidate[sector*512:(sector+1)*512]=data
                case_dir=directory/f'cut-{index:02d}';case_dir.mkdir();path=case_dir/'crash.img';sparse_output(path,candidate)
                before=fsck.inspect(path)
                allowed=states[ack+1:active+2]
                if logical(before) not in allowed:raise AssertionError('crash state violates independent serial prefix and observed acknowledgment')
                case={'event_sequence':record['sequence'],'event':record['event'],'active_operation':active,'last_acknowledged_operation':ack,'selected_versions':selected,'image_sha256':hashlib.sha256(candidate).hexdigest(),'status':'INCOMPLETE'}
                item['cuts'].append(case)
                guest=Guest(args.qemu,kernel,firmware,path,case_dir/'recovery')
                try:guest.boot();guest.shutdown()
                finally:guest.close()
                after=fsck.inspect(path)
                if after['needs_replay'] or logical(after)!=logical(before):raise AssertionError('guest replay disagrees with independent serial oracle')
                case.update(status='PASS',replayed=before['needs_replay'],recovered_sequence=after['sequence'])
                (case_dir/'case.json').write_text(json.dumps(case,indent=2)+'\n')
            item['status']='PASS';(directory/'history.json').write_text(json.dumps(item,indent=2)+'\n')
            print(json.dumps({'event':'history_complete','history':number,'seed':seed,'operations':args.operations,'recovery_boots':len(item['cuts']),'status':'PASS'}),flush=True)
            (output/'history-report.json').write_text(json.dumps(report,indent=2)+'\n')
        sufficient=args.histories>=100 and args.operations>=100 and args.cuts>=20
        report.update(status='PASS' if sufficient else 'INCOMPLETE',completed_histories=len(report['histories']),completed_operations=args.histories*args.operations,recovery_boots=sum(len(h['cuts']) for h in report['histories']))
        if not sufficient:report['reason']='Explicit development counts are below the 100x100 histories and 20 cuts/history acceptance budget.'
    except KeyboardInterrupt:report.update(status='INCOMPLETE',reason='Owned campaign interrupted; completed evidence retained.')
    except Exception as error:report.update(status='INCOMPLETE' if isinstance(error,TimeoutError) else 'FAIL',reason=str(error))
    finally:
        if made:(output/'history-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='histories'},indent=2))
    return 0 if report['status']=='PASS' else 2


if __name__=='__main__':raise SystemExit(main())
