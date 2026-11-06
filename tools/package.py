#!/usr/bin/env python3
"""Create a deterministic source ZIP, or verify and safely extract that exact ZIP."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import zipfile
from accept import source_identity
from doctor import sha256

EXCLUDED={".git","target","build","var",".venv","__pycache__",".pytest_cache",".DS_Store","__MACOSX"}
FORBIDDEN={".env",".aws",".ssh",".codex","evidence","id_rsa","id_ed25519","credentials"}

def forbidden(path):
    return any(part in FORBIDDEN or part.startswith(".env.") and part not in {".env.example",".env.template"} for part in path.parts) or path.suffix in {".img",".qcow2",".raw",".log",".docx",".pyc"}


def inventory(root):
    files=[]
    for path in sorted(root.rglob("*")):
        rel=path.relative_to(root)
        if any(part in EXCLUDED for part in rel.parts):continue
        if path.is_symlink():raise ValueError("source symlink: "+str(rel))
        if path.is_dir():continue
        if not stat.S_ISREG(path.stat().st_mode):raise ValueError("unsupported source file type: "+str(rel))
        if forbidden(rel):raise ValueError("non-source material: "+str(rel))
        files.append(dict(path=rel.as_posix(),size=path.stat().st_size,sha256=sha256(path),mode=0o755 if path.stat().st_mode&0o111 else 0o644))
    if len(files)>5000 or sum(f["size"] for f in files)>64*1024*1024:raise ValueError("source inventory exceeds bound")
    return files


def pack(root,archive,manifest):
    if archive.is_relative_to(root) or manifest.is_relative_to(root):raise ValueError("delivery ZIP and manifest must be external")
    if archive.exists() or manifest.exists():raise FileExistsError("delivery path exists")
    baseline=source_identity(root);files=inventory(root)
    with zipfile.ZipFile(archive,"x",compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for item in files:
            info=zipfile.ZipInfo("kernel-rv64/"+item["path"],date_time=(2026,11,6,0,0,0))
            info.create_system=3;info.external_attr=(stat.S_IFREG|item["mode"])<<16
            info.compress_type=zipfile.ZIP_DEFLATED
            z.writestr(info,(root/item["path"]).read_bytes(),compresslevel=9)
    if source_identity(root)!=baseline:raise ValueError("source changed while packaging")
    result=dict(schema=1,archive_sha256=sha256(archive),source_identity=baseline,files=files)
    with manifest.open("x") as out:json.dump(result,out,indent=2);out.write("\n")
    return result


def unpack(archive,manifest,destination):
    expected=json.loads(manifest.read_text())
    if expected.get("schema")!=1 or sha256(archive)!=expected.get("archive_sha256"):raise ValueError("archive digest/schema mismatch")
    items=expected["files"]
    names={"kernel-rv64/"+item["path"]:item for item in items}
    if not items or len(names)!=len(items) or len(items)>5000 or sum(i["size"] for i in items)>64*1024*1024:raise ValueError("invalid manifest bounds")
    verified=[]
    with zipfile.ZipFile(archive) as z:
        infos=z.infolist()
        if len({i.filename for i in infos})!=len(infos) or set(i.filename for i in infos)!=set(names):raise ValueError("duplicate or unexpected ZIP member")
        for info in infos:
            path=PurePosixPath(info.filename);item=names[info.filename]
            if path.is_absolute() or path.as_posix()!=info.filename or ".." in path.parts or "\\" in info.filename or path.parts[0]!="kernel-rv64":raise ValueError("unsafe ZIP path")
            if forbidden(path) or any(part in EXCLUDED for part in path.parts):raise ValueError("non-source archive member")
            if item["mode"] not in (0o644,0o755):raise ValueError("unsafe ZIP permission mode")
            mode=info.external_attr>>16
            if not stat.S_ISREG(mode) or stat.S_IMODE(mode)!=item["mode"] or info.file_size!=item["size"]:raise ValueError("ZIP type/mode/size mismatch")
            data=z.read(info)
            if hashlib.sha256(data).hexdigest()!=item["sha256"]:raise ValueError("member digest mismatch")
            verified.append((path,data,item["mode"]))
    destination.mkdir(parents=True,exist_ok=False)
    for path,data,mode in verified:
        target=destination/str(path);target.parent.mkdir(parents=True,exist_ok=True)
        with target.open("xb") as out:out.write(data)
        target.chmod(mode)
    extracted=destination/"kernel-rv64"
    if source_identity(extracted)!=expected["source_identity"]:raise ValueError("reconstructed source identity mismatch")
    return extracted


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive",type=Path,required=True)
    p.add_argument("--manifest",type=Path,required=True)
    p.add_argument("--extract",type=Path,help="New directory: verify/extract rather than create ZIP")
    args=p.parse_args()
    try:
        if args.extract:
            print(unpack(args.archive.resolve(strict=True),args.manifest.resolve(strict=True),args.extract.resolve()))
        else:
            result=pack(Path(__file__).resolve().parents[1],args.archive.resolve(),args.manifest.resolve())
            print(json.dumps({k:v for k,v in result.items() if k!="files"},indent=2))
    except (OSError,ValueError,KeyError,zipfile.BadZipFile) as error:p.exit(2,f"package: {error}\n")


if __name__=="__main__":main()
