#!/usr/bin/env python3
"""One-client Unix-socket NBD server for explicit 512-byte persistence cuts.

The input image is locked read-only. The server never changes it. A new output
image contains the durable map plus the selected pending sector versions at the
cut. This is a persistence simulator, not a claim about physical sector writes.

Protocol source: https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
QEMU source: https://www.qemu.org/docs/master/interop/nbd.html
"""
import argparse
import base64
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import random
import socket
import struct
import sys

MAGIC = 0x4E42444D41474943
OPTIONS_MAGIC = 0x49484156454F5054
OPTION_REPLY_MAGIC = 0x3E889045565A9
REQUEST_MAGIC = 0x25609513
REPLY_MAGIC = 0x67446698
SIZE = 64*1024*1024
MAX_REQUEST = 32*1024*1024
TRANSMISSION_FLAGS = 1 | 4  # HAS_FLAGS, SEND_FLUSH only.


class PowerCut(Exception):
    pass


class ProtocolError(ValueError):
    pass


class CommandError(Exception):
    """A deliberately injected standardized NBD error code (test backends)."""
    def __init__(self,code):
        if code not in (1,5,12,22,28,75,95,108):
            raise ValueError('unsupported standardized NBD error code')
        self.code=code
        super().__init__(f'NBD error {code}')


class Trace:
    def __init__(self, stream=None, cut=None):
        self.stream = stream
        self.cut = cut
        self.sequence = 0
        self.records = [] if stream is None else None

    def emit(self, event, **fields):
        record = {'schema':1, 'sequence':self.sequence, 'event':event, **fields}
        if self.stream is not None:
            self.stream.write(json.dumps(record, sort_keys=True)+'\n')
            self.stream.flush()
        else:
            self.records.append(record)
        selected = self.cut == self.sequence
        self.sequence += 1
        if selected:
            raise PowerCut()


class SectorStore:
    def __init__(self, initial, trace=None):
        if len(initial) != SIZE:
            raise ValueError('input image must be exactly 64 MiB')
        self.stable = bytearray(initial)
        self.current = bytearray(initial)
        self.pending = []
        self.next_version = 1
        self.trace = trace or Trace()

    @staticmethod
    def bounds(offset, length):
        if offset < 0 or length < 0 or offset%512 or length%512 or length>MAX_REQUEST or offset>SIZE or length>SIZE-offset:
            raise ValueError('unaligned or out-of-range transfer')

    def read(self, offset, length):
        self.bounds(offset, length)
        return bytes(self.current[offset:offset+length])

    def write(self, offset, data):
        self.bounds(offset, len(data))
        for relative in range(0, len(data), 512):
            sector = (offset+relative)//512
            content = bytes(data[relative:relative+512])
            version = self.next_version
            self.next_version += 1
            self.pending.append((version, sector, content))
            self.current[sector*512:(sector+1)*512] = content
            self.trace.emit('sector_issue', version=version, sector=sector,
                            sha256=hashlib.sha256(content).hexdigest(), data=base64.b64encode(content).decode('ascii'))

    def flush(self):
        versions = []
        for version, sector, content in self.pending:
            self.stable[sector*512:(sector+1)*512] = content
            versions.append(version)
        self.pending.clear()
        self.trace.emit('flush_completion', durable_versions=versions)

    def outcome(self, policy='none', seed=1, versions=None):
        """Choose final versions only from writes issued after latest flush.

        Explicit version sets permit arbitrary sector selection and repeated
        writes. For one sector, the latest selected version wins. Older stable
        versions cannot be resurrected after a completed flush.
        """
        rng = random.Random(seed)
        selected = set(versions or [])
        known = {v for v, _, _ in self.pending}
        if versions is not None and not selected <= known:
            raise ValueError('selected version is not pending')
        result = bytearray(self.stable)
        chosen = []
        for version, sector, data in self.pending:
            keep = (version in selected) if versions is not None else (policy == 'all' or (policy == 'seeded' and rng.getrandbits(1)))
            if keep:
                result[sector*512:(sector+1)*512] = data
                chosen.append(version)
        return result, chosen


def exhaustive_small_versions(pending):
    """Enumerate exactly the contract's declared bounded persistence subspaces.

    A pending record is (version_id, sector_index, 512-byte content). Repeated
    outstanding writes to one sector are excluded from this small profile.
    """
    if len(pending)>136 or len({sector for _,sector,_ in pending})!=len(pending):
        raise ValueError('small profile requires <=136 unique pending sectors')
    ids = tuple(version for version,_,_ in pending)
    seen = set()
    def unique(values):
        value = tuple(sorted(values))
        if value not in seen:
            seen.add(value)
            return value
        return None
    if len(ids)<=12:
        for mask in range(1<<len(ids)):
            yield tuple(version for index,version in enumerate(ids) if mask&(1<<index))
        return
    groups = {}
    for version,sector,_ in pending:
        groups.setdefault(sector//8,[]).append(version)
    for values in ((),ids):
        value=unique(values)
        if value is not None:
            yield value
    for group in groups.values():
        others=tuple(version for version in ids if version not in group)
        for mask in range(1<<len(group)):
            selected=tuple(version for index,version in enumerate(group) if mask&(1<<index))
            for values in (selected,selected+others):
                value=unique(values)
                if value is not None:
                    yield value


def receive(connection, size):
    pieces = bytearray()
    while len(pieces) < size:
        part = connection.recv(size-len(pieces))
        if not part:
            raise EOFError('client disconnected')
        pieces.extend(part)
    return bytes(pieces)


def option_reply(connection, option, kind, data=b''):
    connection.sendall(struct.pack('>QIII', OPTION_REPLY_MAGIC, option, kind, len(data))+data)


def negotiate(connection, trace):
    connection.sendall(struct.pack('>QQH', MAGIC, OPTIONS_MAGIC, 3))
    flags = struct.unpack('>I', receive(connection,4))[0]
    if flags & ~3 or not flags & 1:
        raise ProtocolError('fixed-newstyle client flags required')
    for _ in range(64):
        magic, option, length = struct.unpack('>QII',receive(connection,16))
        if magic != OPTIONS_MAGIC or length > 1048576:
            raise ProtocolError('invalid option header')
        data = receive(connection,length)
        trace.emit('option', option=option, length=length)
        if option == 1:  # EXPORT_NAME
            if data not in (b'', b'kfs'):
                raise ProtocolError('unknown export')
            connection.sendall(struct.pack('>QH',SIZE,TRANSMISSION_FLAGS)+(b'' if flags&2 else bytes(124)))
            return True
        if option == 2:  # ABORT
            option_reply(connection,option,1)
            return False
        if option in (6,7):  # INFO / GO
            if len(data) < 6:
                option_reply(connection,option,0x80000003)
                continue
            size = struct.unpack_from('>I',data)[0]
            if size > len(data)-6:
                option_reply(connection,option,0x80000003)
                continue
            name = data[4:4+size]
            count = struct.unpack_from('>H',data,4+size)[0]
            if len(data) != 6+size+2*count:
                option_reply(connection,option,0x80000003)
                continue
            requested = [struct.unpack_from('>H',data,6+size+i*2)[0] for i in range(count)]
            if len(set(requested)) != count:
                option_reply(connection,option,0x80000003)
                continue
            if name not in (b'',b'kfs'):
                option_reply(connection,option,0x80000006)
                continue
            option_reply(connection,option,3,struct.pack('>HQH',0,SIZE,TRANSMISSION_FLAGS))
            option_reply(connection,option,3,struct.pack('>HIII',3,512,4096,MAX_REQUEST))
            option_reply(connection,option,1)
            if option == 7:
                return True
        else:
            option_reply(connection,option,0x80000001)  # ERR_UNSUP
    raise ProtocolError('too many negotiation options')


def session(connection, store):
    if not negotiate(connection,store.trace):
        return
    while True:
        magic, flags, command, handle, offset, length = struct.unpack('>IHHQQI', receive(connection,28))
        if magic != REQUEST_MAGIC or length>MAX_REQUEST:
            raise ProtocolError('invalid transmission header')
        payload = receive(connection,length) if command == 1 else b''
        store.trace.emit('request_submission', command=command, flags=flags, handle=handle, offset=offset,length=length)
        if command == 2:  # DISC has no reply and is not an implicit flush.
            if flags or offset or length:
                raise ProtocolError('invalid disconnect fields')
            store.trace.emit('disconnect')
            return
        error = 0
        output = b''
        if flags:
            error = errno.EINVAL
        else:
            try:
                if command == 0:
                    output = store.read(offset,length)
                elif command == 1:
                    store.write(offset,payload)
                elif command == 3:
                    if offset or length:
                        raise ValueError('flush reserved fields must be zero')
                    store.flush()
                else:
                    error = errno.EINVAL
            except CommandError as failure:
                error = failure.code
            except ValueError:
                error = errno.EINVAL
        store.trace.emit('request_completion',command=command,handle=handle,error=error)
        connection.sendall(struct.pack('>IIQ',REPLY_MAGIC,error,handle)+(output if not error else b''))
        store.trace.emit('reply_sent',command=command,handle=handle,error=error)


def persist_output(output, data):
    with open(output, 'xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',type=Path,required=True)
    parser.add_argument('--socket',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--trace',type=Path,required=True)
    parser.add_argument('--cut-event',type=int)
    parser.add_argument('--persist',choices=('none','all','seeded'),default='none')
    parser.add_argument('--versions',help='comma-separated pending version IDs; overrides --persist')
    parser.add_argument('--seed',type=int,default=1)
    parser.add_argument('--timeout',type=float,default=180)
    args = parser.parse_args()
    if args.output.exists() or args.socket.exists() or args.trace.exists():
        parser.error('output, socket, and trace paths must be new')
    if args.cut_event is not None and args.cut_event < 0:
        parser.error('--cut-event must be nonnegative')
    if args.timeout <= 0:
        parser.error('--timeout must be positive')
    try:
        versions = None if args.versions is None else [int(n) for n in args.versions.split(',') if n]
        with open(args.image,'rb') as source, open(args.trace,'x') as log:
            fcntl.flock(source,fcntl.LOCK_SH|fcntl.LOCK_NB)
            initial = source.read(SIZE+1)
            trace = Trace(log,args.cut_event)
            store = SectorStore(initial,trace)
            status = 'disconnect'
            failure = None
            owned_socket = False
            try:
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
                    listener.bind(str(args.socket))
                    owned_socket = True
                    os.chmod(args.socket,0o600)
                    listener.listen(1)
                    listener.settimeout(args.timeout)
                    print(json.dumps({'event':'LISTENING','socket':str(args.socket)}),flush=True)
                    connection,_ = listener.accept()
                    with connection:
                        connection.settimeout(args.timeout)
                        session(connection,store)
            except PowerCut:
                status = 'power_cut'
            except EOFError:
                status = 'client_disconnected'
            except (OSError, ValueError) as error:
                status = 'incomplete'
                failure = str(error)
            finally:
                if owned_socket:
                    args.socket.unlink()
            trace.cut = None
            image, chosen = store.outcome(args.persist,args.seed,versions)
            persist_output(args.output,image)
            trace.emit('persistence_outcome',status=status,failure=failure,policy=args.persist,seed=args.seed,selected_versions=chosen,image_sha256=hashlib.sha256(image).hexdigest())
            print(json.dumps({'event':'COMPLETE','status':status,'output':str(args.output),'events':trace.sequence}),flush=True)
        return 1 if failure else 0
    except (OSError,ValueError,ProtocolError) as error:
        print(f'nbd_fault: {error}',file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
