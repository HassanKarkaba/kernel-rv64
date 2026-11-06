import json
import sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"tools"))
from package import pack,unpack


def candidate(tmp_path):
    root=tmp_path/"source";root.mkdir();(root/"hello.rs").write_text("fn main() {}\n")
    script=root/"run.sh";script.write_text("#!/bin/sh\nexit 0\n");script.chmod(0o755)
    return root


def test_exact_roundtrip_and_deterministic_archive(tmp_path):
    root=candidate(tmp_path)
    first=pack(root,tmp_path/"one.zip",tmp_path/"one.json")
    second=pack(root,tmp_path/"two.zip",tmp_path/"two.json")
    assert first==second
    extracted=unpack(tmp_path/"one.zip",tmp_path/"one.json",tmp_path/"clean")
    assert (extracted/"hello.rs").read_bytes()==(root/"hello.rs").read_bytes()
    assert (extracted/"run.sh").stat().st_mode&0o111
    with pytest.raises(FileExistsError):unpack(tmp_path/"one.zip",tmp_path/"one.json",tmp_path/"clean")


def test_archive_tampering_rejected_before_extraction(tmp_path):
    root=candidate(tmp_path);archive=tmp_path/"one.zip";manifest=tmp_path/"one.json"
    pack(root,archive,manifest);archive.write_bytes(archive.read_bytes()+b"tampered")
    with pytest.raises(ValueError,match="digest"):unpack(archive,manifest,tmp_path/"clean")
    assert not (tmp_path/"clean").exists()


def test_symlink_and_local_secret_rejected(tmp_path):
    root=candidate(tmp_path);(root/"alias.rs").symlink_to(root/"hello.rs")
    with pytest.raises(ValueError,match="symlink"):pack(root,tmp_path/"one.zip",tmp_path/"one.json")
    (root/"alias.rs").unlink();(root/".env").write_text("LOCAL_ONLY=1")
    with pytest.raises(ValueError,match="non-source"):pack(root,tmp_path/"one.zip",tmp_path/"one.json")


def test_macos_metadata_excluded_and_environment_variant_refused(tmp_path):
    root=candidate(tmp_path);metadata=root/'__MACOSX';metadata.mkdir();(metadata/'._hello.rs').write_bytes(b'host metadata')
    result=pack(root,tmp_path/'clean.zip',tmp_path/'clean.json')
    assert all('__MACOSX' not in item['path'] for item in result['files'])
    (root/'.env.local').write_text('LOCAL_ONLY=1')
    with pytest.raises(ValueError,match='non-source'):pack(root,tmp_path/'bad.zip',tmp_path/'bad.json')


def test_manifest_cannot_authorize_special_permissions(tmp_path):
    import hashlib
    import stat
    import zipfile
    root=candidate(tmp_path);archive=tmp_path/'one.zip';manifest=tmp_path/'one.json'
    result=pack(root,archive,manifest)
    payloads={}
    with zipfile.ZipFile(archive) as z:
        for item in z.infolist():payloads[item.filename]=z.read(item)
    bad=tmp_path/'mode.zip'
    with zipfile.ZipFile(bad,'w') as z:
        for item in result['files']:
            item['mode']=0o4755
            info=zipfile.ZipInfo('kernel-rv64/'+item['path']);info.create_system=3;info.external_attr=(stat.S_IFREG|item['mode'])<<16
            z.writestr(info,payloads[info.filename])
    result['archive_sha256']=hashlib.sha256(bad.read_bytes()).hexdigest();manifest.write_text(json.dumps(result))
    with pytest.raises(ValueError,match='permission'):unpack(bad,manifest,tmp_path/'extract')
    assert not (tmp_path/'extract').exists()
