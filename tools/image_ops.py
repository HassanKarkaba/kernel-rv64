#!/usr/bin/env python3
"""Validated image export and explicitly authorized atomic image reset."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import stat
import struct
import sys
import uuid

import fsck
import mkfs


def export_image(image, destination):
    with open(image,'rb') as source:
        fcntl.flock(source,fcntl.LOCK_SH|fcntl.LOCK_NB)
        decoded=fsck.Image(source)
        report=decoded.inspect()
        destination.mkdir(mode=0o700)
        files=destination/'files'
        files.mkdir(mode=0o700)
        for entry in report['files']:
            index=entry['inode']-1
            raw=decoded.block(20+index//32)[index%32*128:(index%32+1)*128]
            pointers=list(struct.unpack_from('<12I',raw,16))
            indirect=struct.unpack_from('<I',raw,64)[0]
            if indirect:
                pointers.extend(struct.unpack('<1024I',decoded.block(indirect))[:1012])
            remaining=entry['size']
            with open(files/entry['name'][1:],'xb') as output:
                for pointer in pointers[:(remaining+4095)//4096]:
                    content=decoded.block(pointer)[:min(4096,remaining)]
                    output.write(content)
                    remaining-=len(content)
                output.flush()
                os.fsync(output.fileno())
        with open(destination/'manifest.json','x') as manifest:
            json.dump(report,manifest,indent=2,sort_keys=True)
            manifest.write('\n')
        return report


def reset(image, files, volume):
    # Lock the old inode through the atomic replace, and reject links/devices.
    fd=os.open(image,os.O_RDWR|getattr(os,'O_NOFOLLOW',0))
    temporary=image.parent/('.kfs-reset-'+uuid.uuid4().hex+'.img')
    made=False
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        old=os.fstat(fd)
        if not stat.S_ISREG(old.st_mode):
            raise ValueError('reset requires an existing regular image')
        report=mkfs.create(temporary,volume,files)
        made=True
        current=os.stat(image,follow_symlinks=False)
        if (current.st_dev,current.st_ino)!=(old.st_dev,old.st_ino):
            raise ValueError('image path changed while preparing reset')
        os.replace(temporary,image)
        made=False
        parent=os.open(image.resolve().parent,os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        return report
    finally:
        os.close(fd)
        if made:
            temporary.unlink()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    export=commands.add_parser('export')
    export.add_argument('--image',type=Path,required=True)
    export.add_argument('--output',type=Path,required=True)
    reset_parser=commands.add_parser('reset')
    reset_parser.add_argument('--image',type=Path,required=True)
    reset_parser.add_argument('--destroy-existing',action='store_true',required=True)
    reset_parser.add_argument('--import',dest='imports',action='append',default=[])
    args=parser.parse_args()
    try:
        if args.command=='export':
            result=export_image(args.image,args.output)
        else:
            imports=[]
            for value in args.imports:
                name,separator,path=value.partition('=')
                if not separator:
                    raise ValueError('--import requires /name=path')
                imports.append((name,Path(path)))
            result=reset(args.image,imports,uuid.uuid4().bytes)
        print(json.dumps(result,sort_keys=True))
        return 0
    except (OSError,ValueError) as error:
        print(f'image: {error}',file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
