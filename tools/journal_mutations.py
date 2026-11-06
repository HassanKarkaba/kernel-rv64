#!/usr/bin/env python3
"""Run journal negative controls against isolated copies of the actual Rust code.

A passing campaign requires baseline tests to pass, every deliberately broken
candidate to compile and fail the crash assertion, and the restored source to
pass again. This is host execution of the Rust journal, not mutated guest proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

TEST='tests::every_sector_and_barrier_cut_preserves_a_complete_mutation'


def replace_once(text,before,after):
    if text.count(before)!=1:
        raise ValueError('mutation anchor changed; inspect the current journal before rerunning')
    return text.replace(before,after,1)


def mutate(source,name):
    if name=='early_ack':
        return replace_once(source,'        dev.trace(103, self.sequence);',
                            '        return Ok(());\n        dev.trace(103, self.sequence);')
    if name=='missing_prepare_flush':
        return replace_once(source,'        dev.flush()?;\n        dev.trace(103, self.sequence);',
                            '        dev.trace(103, self.sequence);')
    if name=='missing_commit_flush':
        return replace_once(source,'        dev.flush()?;\n        dev.trace(105, self.sequence);',
                            '        dev.trace(105, self.sequence);')
    if name=='early_retirement':
        return replace_once(source,'        dev.flush()?;\n        dev.trace(107, self.sequence);',
                            '        dev.trace(107, self.sequence);')
    if name=='stale_payload_reuse':
        changed=replace_once(source,
            '        dev.write_commit(&self.commit_sector)?;\n        dev.flush()?;\n        dev.trace(101, self.sequence);',
            '        dev.trace(101, self.sequence);')
        return replace_once(changed,'        dev.flush()?;\n        dev.trace(109, self.sequence);',
                            '        dev.trace(109, self.sequence);')
    raise ValueError(name)


def run_candidate(root,output,name,source,expect_pass):
    candidate=output/name
    candidate.mkdir()
    (candidate/'crates').mkdir()
    for crate in ('disk-format','filesystem'):
        shutil.copytree(root/'crates'/crate,candidate/'crates'/crate)
    (candidate/'Cargo.toml').write_text('[workspace]\nresolver = "3"\nmembers = ["crates/disk-format", "crates/filesystem"]\n')
    (candidate/'crates/disk-format/src/lib.rs').write_text(source)
    env=os.environ.copy();env['CARGO_TARGET_DIR']=str(output/'targets'/name)
    cmd=['cargo','test','--offline','-p','filesystem',TEST,'--','--exact','--nocapture']
    result=subprocess.run(cmd,cwd=candidate,env=env,capture_output=True,text=True,timeout=120)
    transcript=result.stdout+result.stderr
    (candidate/'test.log').write_text(transcript)
    detected=result.returncode!=0 and 'test result: FAILED' in transcript and TEST in transcript
    passed=result.returncode==0 and '1 passed; 0 failed' in transcript
    status='PASS' if (passed if expect_pass else detected) else 'FAIL'
    return {'candidate':name,'source_sha256':hashlib.sha256(source.encode()).hexdigest(),'command':cmd,'exit_code':result.returncode,'status':status,'expected':'baseline succeeds' if expect_pass else 'compiled mutation fails crash test','log':str((candidate/'test.log').relative_to(output))}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    output=args.output.resolve()
    if output.is_relative_to(root):
        parser.error('evidence and mutated candidates must be outside source tree')
    report={'schema':1,'status':'INCOMPLETE','scope':'Actual Rust journal mutated host candidates','results':[],
            'limitations':['Does not establish mutated-kernel behavior across real VirtIO, traps, or DMA.']}
    made=False
    try:
        output.mkdir(parents=True,exist_ok=False);made=True
        original=(root/'crates/disk-format/src/lib.rs').read_text()
        report['compiler']=subprocess.check_output(['rustc','--version'],text=True).strip()
        report['results'].append(run_candidate(root,output,'baseline',original,True))
        if report['results'][-1]['status']!='PASS':
            raise RuntimeError('baseline crash test failed')
        for name in ['early_ack','missing_prepare_flush','missing_commit_flush','early_retirement','stale_payload_reuse']:
            result=run_candidate(root,output,name,mutate(original,name),False)
            report['results'].append(result)
            print(json.dumps(result),flush=True)
            if result['status']!='PASS':
                raise RuntimeError(name+' was not detected by a compiled crash assertion')
        if (root/'crates/disk-format/src/lib.rs').read_text()!=original:
            raise RuntimeError('original source changed during campaign')
        report['results'].append(run_candidate(root,output,'restored',original,True))
        if report['results'][-1]['status']!='PASS':
            raise RuntimeError('restored source failed')
        report['status']='PASS'
    except Exception as error:
        report.update(status='FAIL',reason=str(error))
    finally:
        if made:
            (output/'mutation-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return 0 if report['status']=='PASS' else 2


if __name__=='__main__':
    raise SystemExit(main())
