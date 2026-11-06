"""Read-only, fail-closed qualification of external evidence for edition1.0.

Digests establish identity. Verified assessment records describe who inspected
which raw observations; this program does not manufacture reviewer independence.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile
from qualification_policy import (CASES, CHECKS, CONTRACT_SHA256, GATE_CASES,
                                  GATE_REVIEWS, MUTATIONS, NEGATIVE_CONTROLS, REQ_FAMILIES)

INDEX_SCHEMA = 'kernel-rv64.qualification/v1'
RECORD_SCHEMA = 'kernel-rv64.evidence-record/v1'
HEX = re.compile(r'[0-9a-f]{64}\Z')
KINDS = {'execution','review','verification','reconstruction','applicability','resolution'}


class InvalidEvidence(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise InvalidEvidence(message)


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def read_json(path):
    require(path.stat().st_size <= 256 * 1024 * 1024, 'JSON artifact exceeds256MiB')
    return json.loads(path.read_text(), object_pairs_hook=object_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(InvalidEvidence('nonfinite JSON value: '+value)))


def text(value, label, minimum=1):
    require(isinstance(value,str) and len(value.strip()) >= minimum, label+' is missing or non-substantive')


def unique(values, label):
    require(isinstance(values,list) and all(isinstance(x,str) for x in values), label+' must be a string list')
    require(len(values)==len(set(values)), label+' contains duplicates')
    return values


def pointer(value, path):
    require(isinstance(path,str) and (path=='' or path.startswith('/')), 'invalid JSON pointer')
    for part in path.split('/')[1:] if path else []:
        part=part.replace('~1','/').replace('~0','~')
        if isinstance(value,list):
            require(part.isdecimal() and int(part)<len(value), 'JSON pointer index absent')
            value=value[int(part)]
        else:
            require(isinstance(value,dict) and part in value, 'JSON pointer member absent: '+part)
            value=value[part]
    return value


class Qualifier:
    def __init__(self,index_path,source_root=None,fixture_mode=False):
        self.index_path=Path(index_path).resolve(strict=True)
        self.base=self.index_path.parent
        self.index=read_json(self.index_path)
        self.source_root=Path(source_root).resolve() if source_root else None
        self.fixture_mode=fixture_mode
        self.paths={};self.jsons={};self.records={};self.verified=set();self.applicable={};self.applicable_checks={}
        self.invalid=[];self.pending=[];self.open_findings=set();self.executions={};self.reviews={};self.build_checks=set();self.budgets={};self.reconstructed=False
        self.case_evidence={case:[] for case in CASES}

    def artifact(self,name):
        require(isinstance(name,str) and name in self.index['artifacts'],'unknown artifact: '+str(name))
        if name in self.paths:return self.paths[name]
        entry=self.index['artifacts'][name]
        require(isinstance(entry,dict) and HEX.fullmatch(entry.get('sha256','')),'invalid artifact digest: '+name)
        relative=PurePosixPath(entry.get('path',''))
        require(str(relative) not in ('','.') and not relative.is_absolute() and '..' not in relative.parts and '\\' not in str(relative),'unsafe artifact path: '+name)
        path=self.base/str(relative)
        require(path.resolve(strict=True).is_relative_to(self.base),'artifact escapes bundle: '+name)
        for parent in [path,*path.parents]:
            if parent==self.base:break
            require(not parent.is_symlink(),'artifact path contains symlink: '+name)
        require(path.is_file(),'artifact is not a file: '+name)
        require(digest(path)==entry['sha256'],'artifact digest mismatch: '+name)
        text(entry.get('kind'),'artifact kind')
        self.paths[name]=path
        return path

    def json(self,name):
        if name not in self.jsons:self.jsons[name]=read_json(self.artifact(name))
        return self.jsons[name]

    def refs(self,names,label,minimum=1):
        unique(names,label);require(len(names)>=minimum,label+' has no supporting artifacts')
        for name in names:self.artifact(name)

    def validate_archive(self,candidate=None):
        c=candidate or self.index['candidate'];manifest=self.json(c['manifest']);archive=self.artifact(c['archive'])
        require(manifest.get('schema')==1 and manifest.get('archive_sha256')==digest(archive),'archive/manifest identity mismatch')
        require(manifest.get('source_identity')==c['source_identity'],'manifest source identity mismatch')
        files=manifest.get('files');require(isinstance(files,list) and 0<len(files)<=5000,'invalid archive inventory')
        names={'kernel-rv64/'+f['path']:f for f in files};require(len(names)==len(files),'duplicate manifest members')
        require(sum(f['size'] for f in files)<=64*1024*1024,'source archive too large')
        h=hashlib.sha256();contents={}
        with zipfile.ZipFile(archive) as z:
            infos=z.infolist();require(len(infos)==len(names) and {i.filename for i in infos}==set(names),'archive members differ from manifest')
            for info in infos:
                path=PurePosixPath(info.filename);f=names[info.filename];mode=info.external_attr>>16
                require(not path.is_absolute() and '..' not in path.parts and '\\' not in info.filename and str(path)==info.filename and str(PurePosixPath(f['path']))==f['path'],'unsafe archive member')
                require(stat.S_ISREG(mode) and stat.S_IMODE(mode)==f['mode'] and f['mode'] in (0o644,0o755),'archive type/mode mismatch')
                require(info.file_size==f['size'],'archive size mismatch')
                require(Path(f['path']).suffix.lower() not in {'.img','.qcow2','.raw','.log','.docx','.pyc'},'non-source archive payload')
                basename=Path(f['path']).name
                require(not (basename.startswith('.env.') and basename not in {'.env.example','.env.template'}),'secret environment archive member')
                require(basename not in {'id_rsa','id_dsa','id_ecdsa','id_ed25519','credentials','credentials.json','authorized_keys','known_hosts'},'private credential archive member')
                require(not any(p in {'target','build','var','.git','.venv','__pycache__','.pytest_cache','.DS_Store','__MACOSX','.env','.aws','.ssh','.codex','evidence'} for p in path.parts),'excluded archive member')
                data=z.read(info);require(hashlib.sha256(data).hexdigest()==f['sha256'],'archive member digest mismatch')
                contents[f['path']]=data
        for name,data in sorted(contents.items()):
            wire=name.encode();h.update(len(wire).to_bytes(8,'big')+wire+len(data).to_bytes(8,'big')+data)
        require(h.hexdigest()==c['source_identity'],'archive source identity mismatch')
        if self.source_root and candidate is None:
            from accept import source_identity
            require(source_identity(self.source_root)==c['source_identity'],'current source differs from candidate archive')
        if candidate is None:self.manifest=manifest;self.archive_contents=contents
        return manifest

    def common(self,r):
        require(isinstance(r,dict),'evidence record is not an object')
        require(r.get('schema')==RECORD_SCHEMA and r.get('kind') in KINDS,'record schema/kind unsupported')
        text(r.get('id'),'record id');require(HEX.fullmatch(r.get('source_identity','')),'record source identity missing')
        require(r.get('contract_sha256')==CONTRACT_SHA256,'record contract mismatch')
        require(r.get('evidence_class')==('unit-fixture' if self.fixture_mode else 'real-execution'),'synthetic or unclassified evidence cannot qualify delivery')
        require(r.get('status') in ('PASS','FAIL','INCOMPLETE','NOT RUN'),'invalid record disposition')
        text(r.get('assessor',{}).get('id'),'assessor identity')
        text(r.get('method'),'assessment/execution method',40)
        self.refs(r.get('artifacts'),'record artifacts')
        findings=r.get('findings');require(isinstance(findings,list),'findings inventory missing')
        for f in findings:
            text(f.get('id'),'finding id');text(f.get('observation'),'finding observation',20)
            require(f.get('disposition') in ('RESOLVED','OPEN','NOT_APPLICABLE'),'invalid finding disposition')
            if f['disposition']=='RESOLVED':self.refs(f.get('evidence'),'finding resolution evidence')
            if f['disposition']=='NOT_APPLICABLE':text(f.get('reason'),'finding applicability reason',40)
        return not any(f['disposition']=='OPEN' for f in findings)

    def check_assertions(self,assertions):
        require(isinstance(assertions,list) and assertions,'no executable artifact assertions')
        for item in assertions:
            require(isinstance(item,dict),'invalid assertion')
            def value(side):
                require(isinstance(side,dict),'invalid assertion operand')
                if 'sha256' in side:return digest(self.artifact(side['sha256']))
                if 'artifact' in side:return pointer(self.json(side['artifact']),side.get('pointer',''))
                require(set(side)=={'value'},'assertion operand must reference artifact or literal value')
                return side['value']
            require('artifact' in item.get('left',{}),'left assertion must read an artifact')
            a,b=value(item['left']),value(item['right']);op=item.get('op')
            if op=='eq':ok=type(a) is type(b) and a==b
            elif op=='ge':ok=type(a) in (int,float) and type(b) in (int,float) and a>=b
            elif op=='le':ok=type(a) in (int,float) and type(b) in (int,float) and a<=b
            elif op=='contains':ok=isinstance(a,(list,dict,str)) and b in a
            else:raise InvalidEvidence('unsupported assertion operation')
            require(ok,'artifact assertion failed: '+str(item))

    def current(self,r,cases=None):
        if r['source_identity']==self.index['candidate']['source_identity']:return True
        allowed=self.applicable.get(r['id'],set())
        return bool(allowed) and (cases is None or set(cases)<=allowed)

    def verification(self,r):
        require(r['status']=='PASS' and r['source_identity']==self.index['candidate']['source_identity'],'verification must assess current candidate')
        target=self.records.get(r.get('target'))
        require(target is not None and target['kind'] in ('review','reconstruction','applicability','resolution'),'verification target absent or wrong kind')
        require(r['assessor']['id']!=target['assessor']['id'],'self-verification is not independent')
        require(r.get('assessment_performed') is True,'review was not verified as performed')
        text(r.get('independence_method'),'verification independence',40)
        self.check_assertions(r.get('checks'))
        self.verified.add(target['id'])

    def applicability(self,r):
        require(r['id'] in self.verified and r['status']=='PASS','unverified applicability assessment')
        require(r['source_identity']==self.index['candidate']['source_identity'],'applicability target is stale')
        target=self.records.get(r.get('execution'))
        require(target is not None and target['kind']=='execution','applicability target execution absent')
        old=self.validate_archive({'manifest':r['previous_manifest'],'archive':r['previous_archive'],'source_identity':target['source_identity']})
        a={f['path']:f for f in old['files']};b={f['path']:f for f in self.manifest['files']}
        changed=sorted(p for p in a.keys()|b.keys() if a.get(p)!=b.get(p))
        require(r.get('changed_paths')==changed,'applicability omits or invents candidate changes')
        cases=unique(r.get('unaffected_cases'),'unaffected cases');require(cases and set(cases)<=set(CASES),'unknown applicability case')
        require(set(cases)<=set(c['id'] for c in target.get('cases',[])),'applicability adds unexecuted cases')
        for row in r.get('unchanged_inputs',[]):
            require(row['path'] in a and a[row['path']]==b.get(row['path']),'claimed unchanged source input differs')
        require(r.get('unchanged_inputs'),'applicability needs exact unchanged input inventory')
        checks=unique(r.get('unaffected_build_checks',[]),'unaffected build checks')
        require(set(checks)<=set(CHECKS) and set(checks)<=set(target.get('build_checks',[])),'applicability adds unexecuted build checks')
        text(r.get('independence_method'),'applicability independence method',40)
        text(r.get('impact_analysis'),'substantive change impact analysis',100)
        self.check_assertions(r.get('checks'))
        self.applicable.setdefault(target['id'],set()).update(cases)
        self.applicable_checks.setdefault(target['id'],set()).update(checks)

    def execution(self,r):
        require(r['status']=='PASS','execution did not pass')
        require(r.get('exit_code')==0 and r.get('completed') is True and r.get('truncated') is False,'execution incomplete, capped or failed')
        require(r.get('environment') in ('reference-linux','native'),'execution environment unspecified')
        require(r.get('binary_kind') in ('release','instrumented','host'),'binary kind unspecified')
        unique(r.get('substitutions'),'boundary substitutions')
        invocation=r.get('invocation');require(isinstance(invocation,list) and invocation and all(isinstance(x,str) for x in invocation),'invocation absent')
        start=datetime.fromisoformat(r['started_utc']);end=datetime.fromisoformat(r['completed_utc']);require(start.tzinfo and end.tzinfo and end>=start,'invalid execution timestamps')
        identities=r.get('identities',{})
        required={'toolchain','configuration','environment','workload'}
        if r['binary_kind']!='host':required|={'kernel','firmware','image'}
        if r['environment']=='reference-linux':required.add('packages')
        require(required<=set(identities),'execution identities incomplete')
        for name in required:self.artifact(identities[name])
        environment=self.json(identities['environment'])
        text(environment.get('system'),'observed host system')
        if r['environment']=='reference-linux':
            require(environment.get('system')=='Linux' and environment.get('distribution')=='ubuntu' and environment.get('version_id')=='24.04','reference environment is not observed Ubuntu24.04 Linux')
            require(re.fullmatch(r'sha256:[0-9a-f]{64}',environment.get('base_image_digest','')),'reference base-image digest missing')
            require(re.fullmatch(r'3\.12\.[0-9]+',environment.get('python','')) and environment.get('pytest')=='8.4.2','reference Python/pytest versions differ')
            dockerfile=self.archive_contents.get('containers/Dockerfile',b'').decode()
            bases=re.findall(r'^FROM ubuntu:24\.04@(sha256:[0-9a-f]{64})\s*$',dockerfile,re.MULTILINE)
            require(len(bases)==1 and environment['base_image_digest']==bases[0],'observed base image differs from archived reference pin')
            package_path=self.artifact(identities['packages'])
            pinned=self.archive_contents.get('containers/debian-packages-arm64.lock')
            require(pinned is not None and hashlib.sha256(pinned).hexdigest()==digest(package_path),'observed package inventory differs from archived reference lock')
            require(environment.get('package_inventory_sha256')==digest(package_path),'observed package inventory digest mismatch')
            packages={}
            for line in package_path.read_text().splitlines():
                parts=line.split('\t');require(len(parts)==2 and all(parts) and parts[0] not in packages,'invalid observed package inventory')
                packages[parts[0]]=parts[1]
            for name in ('gcc-13-riscv64-linux-gnu','binutils-riscv64-linux-gnu','gdb-multiarch'):
                require(name in packages and environment.get('packages',{}).get(name)==packages[name],'observed compiler/binutils/GDB package differs: '+name)
        tool=self.json(identities['toolchain'])
        require(tool.get('rust')=='1.99.1' and tool.get('target')=='riscv64imac-unknown-none-elf','compiler/target substitution not qualified')
        if r['binary_kind']!='host':require(tool.get('qemu')=='11.1.3' and tool.get('opensbi')=='1.7','QEMU/firmware substitution not qualified')
        bindings=r.get('bindings',{})
        for key in {'source_identity'}|({'kernel','firmware','image'} if r['binary_kind']!='host' else set()):
            binding=bindings.get(key,{})
            expected=r['source_identity'] if key=='source_identity' else digest(self.artifact(identities[key]))
            require(binding.get('artifact') in r['artifacts'],'execution identity binding is not a retained supporting artifact')
            require(pointer(self.json(binding['artifact']),binding['pointer'])==expected,'execution raw identity mismatch: '+key)
        self.check_assertions(r.get('checks'))
        case_ids=[]
        for case in r.get('cases',[]):
            cid=case.get('id');require(cid in CASES and cid not in case_ids,'unknown/duplicate case identity')
            case_ids.append(cid)
            host_case=cid.startswith(('AC-20.','AC-21.')) or cid=='AC-01.reference-build'
            require(host_case or r['binary_kind']!='host','host algorithm evidence cannot qualify machine boundary: '+cid)
            if not host_case:
                boundary=r.get('boundaries',{})
                require(boundary.get('cpu')=='real-qemu','machine boundary not actually executed')
                if boundary.get('syscall')=='not-reached-boot-refusal':
                    # Platform and corrupt-mount refusals are required to stop
                    # before U-mode. Requiring an ecall would make truthful
                    # evidence for these negative cases impossible.
                    require(cid=='AC-01.boot-refusals' or cid.startswith('AC-16.'),'boot-refusal boundary cannot qualify a user execution case')
                    binding=r.get('boundary_observations',{}).get('boot_refusal',{})
                    require(binding.get('artifact') in r['artifacts'],'boot-refusal observation is not retained execution evidence')
                    observed=pointer(self.json(binding['artifact']),binding['pointer'])
                    require(isinstance(observed,dict) and observed.get('refused') is True and observed.get('user_entry') is False,'boot refusal or absence of user entry not observed')
                    require(observed.get('persistent_image_unchanged') is True,'boot refusal changed persistent image or lacks observation')
                else:
                    require(boundary.get('syscall')=='actual-ecall','machine boundary not actually executed')
            if cid.startswith(('AC-12.','AC-13.','AC-14.','AC-15.','AC-16.','AC-17.')):
                require(r['boundaries'].get('storage')=='real-virtio','fake block device cannot qualify storage')
            require(case.get('status')=='PASS','case skipped or unsuccessful: '+cid)
            for field in ('inputs','public_result','authoritative_state','forbidden_effects','completion_window','cleanup','limitations'):
                text(case.get(field),'case '+cid+' '+field)
            self.check_assertions(case.get('checks'))
        require(case_ids or r.get('build_checks'),'execution has no named coverage')
        require(self.current(r,case_ids),'execution source is stale without verified scoped applicability')
        qualified_checks=set()
        for check in r.get('build_checks',[]):
            require(check in CHECKS,'unknown build check')
            require(r['source_identity']==self.index['candidate']['source_identity'] or check in self.applicable_checks.get(r['id'],set()),'stale build check lacks specific applicability')
            require(r['environment']=='reference-linux','mandatory build checks need reference Linux evidence')
            qualified_checks.add(check)
        qualified_budgets=self.validate_budgets(r) if 'budgets' in r else {}
        # Publish coverage only after every identity, case, check and budget in
        # this record has passed; a failed late budget cannot leak partial PASS.
        for cid in case_ids:self.case_evidence[cid].append(r['id'])
        self.build_checks.update(qualified_checks)
        self.budgets.update(qualified_budgets)
        self.executions[r['id']]=r

    def validate_budgets(self,r):
        qualified={}
        require(r['environment']=='reference-linux','mandatory measurement budgets need reference runner')
        budget_cases={
            'fairness4':{'AC-19.fairness4'},'fairness8':{'AC-19.fairness8'},
            'wakeup':{'AC-19.wakeup10000'},'context':{'AC-19.context10000-calibration'},
            'masking':{'AC-19.masking-debug'},'reclaim':{'AC-19.reclaim10000'},
            'histories':{'AC-14.100x100-histories','AC-14.20-cuts-each'},
            'exhaustive':{'AC-14.every-mutation-class','AC-14.submission-completion-flush-cuts','AC-14.sector-subsets','AC-14.small-combinations','AC-14.commit-sector-both','AC-14.descriptor-payload-reorder'},
            'recovery':{'AC-15.replay-each-write','AC-15.replay-flush','AC-15.clear-write','AC-15.clear-flush','AC-15.three-interruptions'},
            'largest-recovery':{'AC-19.largest-recovery'},
            'negative-controls':{'AC-22.'+c for c in NEGATIVE_CONTROLS}|{'AC-22.intended-assertions','AC-22.baseline-restored'},
        }
        for name,b in r['budgets'].items():
            require(name in budget_cases,'unknown budget: '+name)
            require(budget_cases[name]<={c['id'] for c in r.get('cases',[])},'budget lacks its qualified named cases: '+name)
            require(isinstance(b,dict),'invalid budget record')
            report=self.json(b['report']);require(report.get('status')=='PASS','budget raw report did not pass')
            self.check_assertions(b.get('checks'))
            if name in ('fairness4','fairness8','wakeup','context','masking','reclaim'):
                from bench import analyze,analyze_extended
                require(r['binary_kind']=='instrumented','measurement budget requires instrumented binary identity')
                require(report.get('host',{}).get('system')=='Linux','measurement was not observed on Linux')
                require(b['report'] in r['artifacts'],'measurement report absent from execution artifacts')
                require(all(r['bindings'][key]['artifact']==b['report'] for key in ('source_identity','kernel','firmware','image')),'measurement report is not the execution identity chain')
                require(report.get('run_id')==b['run_id'] and report.get('boot_id')==b['boot_id'],'measurement report/serial run identity differs')
                require(report.get('serial_sha256')==digest(self.artifact(b['serial'])),'measurement report/serial digest differs or missing')
                serial=self.artifact(b['serial']).read_bytes()
                if name.startswith('fairness'):observed,_=analyze(serial,int(name[-1]),b['run_id'],b['boot_id'])
                else:observed,_=analyze_extended(serial,name,b['run_id'],b['boot_id'])
                config=self.json(r['identities']['configuration'])
                require(config.get('icount')=='shift=0,align=off,sleep=off','wrong measurement virtual-time mode')
                require(report.get('icount')==config['icount'] and report.get('profile')==config.get('profile'),'measurement report/configuration mismatch')
                if name=='masking':require(config.get('profile')=='debug','masking was not measured in debug profile')
                qualified[name]={'execution':r['id'],'observation':observed}
            elif name=='histories':
                histories=report.get('histories',[])
                require(len(histories)>=100,'history budget below100')
                seeds=[]
                for h in histories:
                    require(h.get('status')=='PASS','history incomplete')
                    require(type(h.get('operations')) is int and h['operations']>=100 and isinstance(h.get('cuts'),list) and len(h['cuts'])>=20,'history operation/cut budget short')
                    require(all(c.get('status')=='PASS' and HEX.fullmatch(c.get('image_sha256','')) for c in h['cuts']),'history cut missing real recovery result')
                    seeds.append(h['seed'])
                require(len(set(seeds))==len(seeds),'history seeds duplicated')
                qualified[name]={'execution':r['id'],'histories':len(histories)}
            elif name=='exhaustive':
                require(report.get('profile')=='exhaustive-small' and report.get('workload')=='all','reduced crash profile')
                inventory=self.json(b['inventory'])
                require(report.get('enumerated_outcomes')==inventory.get('expected_outcomes') and type(inventory.get('expected_outcomes')) is int and inventory['expected_outcomes']>0,'truncated outcome matrix')
                require(report.get('unique_boots')==inventory.get('expected_unique_boots')==len(report.get('cases',[])) and all(c.get('status')=='PASS' for c in report['cases']),'incomplete unique real recovery boots')
                self.refs(inventory.get('input_artifacts'),'independent enumeration input artifacts')
                require(set(inventory.get('mutation_classes',[]))>=set(MUTATIONS),'missing mutation classes')
                require(set(inventory.get('subspaces',[]))>= {'submission','completion','flush','all-lost','all-persisted','256-per-block','all-combinations-at-most12','commit-sector-both','descriptor-payload-reorder'},'missing persistence subspace')
                require(inventory.get('declared_cuts')==inventory.get('completed_cuts') and inventory.get('declared_cuts',0)>0,'missing declared cuts')
                qualified[name]={'execution':r['id'],'outcomes':report['enumerated_outcomes']}
            elif name=='recovery':
                cases=report.get('cases',[]);require(cases,'recovery case inventory missing')
                require(set(b.get('phases',[]))>= {'replay-write','replay-flush','clear-write','clear-flush'},'replay phase missing')
                for case in cases:
                    require(case.get('status')=='PASS' and isinstance(case.get('interruptions'),list) and len(case['interruptions'])>=3,'replay case incomplete or insufficient repetitions')
                    require(all(HEX.fullmatch(c.get('image_sha256','')) for c in case['interruptions']),'replay interruption image identity missing')
                require(report.get('completed_cases')==len(cases)==2*report.get('replay_boundaries',0),'replay cut inventory incomplete')
                require({c.get('policy') for c in cases}=={'none','all'},'replay persistence policies incomplete')
                qualified[name]={'execution':r['id'],'cases':len(cases)}
            elif name=='largest-recovery':
                require(report.get('boot_to_ready_host_seconds',181)<=180 and report.get('image_bytes')==64*1024*1024 and report.get('redo_count')==16,'largest recovery geometry or deadline failed')
                require(type(report.get('block_read_bytes_before_ready')) is int and report['block_read_bytes_before_ready']>0,'recovery scan bytes missing')
                qualified[name]={'execution':r['id'],'ready_seconds':report['boot_to_ready_host_seconds']}
            elif name=='negative-controls':
                controls=report.get('controls',[]);require({c.get('name') for c in controls}>=set(NEGATIVE_CONTROLS),'negative control omitted')
                for c in controls:
                    require(c.get('status')=='PASS' and c.get('baseline')=='PASS' and c.get('restored')=='PASS','control baseline/restoration failed')
                    require(c.get('outcome')=='intended-assertion' and c.get('expected_assertion')==c.get('observed_assertion') and c.get('observed_assertion'),'wrong mutant failure or timeout')
                    self.refs(c.get('artifacts'),'negative-control evidence',3)
                    self.check_assertions(c.get('checks'))
                qualified[name]={'execution':r['id'],'controls':len(controls)}
            else:raise InvalidEvidence('unknown budget: '+name)
        return qualified

    def review(self,r):
        require(r['id'] in self.verified and self.current(r) and r['status']=='PASS','review is unverified or stale')
        gate=r.get('gate');require(gate in GATE_REVIEWS,'review gate invalid')
        obligations=unique(r.get('obligations'),'review obligations');require(obligations and set(obligations)<=set(GATE_REVIEWS[gate]),'review obligation invalid')
        authors=unique(r.get('reviewed_authors'),'reviewed authors');require(authors and r['assessor']['id'] not in authors,'review assessor authored assessed scope')
        text(r.get('independence_method'),'review independence method',40)
        observations=r.get('observations',[])
        require({x.get('obligation') for x in observations}==set(obligations),'review lacks per-obligation assessment')
        for item in observations:
            text(item.get('method'),'review observation method',40);text(item.get('finding'),'review observation finding',40)
            require(item.get('disposition')=='PASS','review obligation unresolved')
            self.refs(item.get('artifacts'),'review observation artifacts');self.check_assertions(item.get('checks'))
        for obligation in obligations:self.reviews.setdefault(gate,{})[obligation]=r['id']

    def reconstruction(self,r):
        require(r['id'] in self.verified and self.current(r) and r['status']=='PASS','reconstruction unverified or stale')
        require(r.get('archive')==self.index['candidate']['archive'] and r.get('manifest')==self.index['candidate']['manifest'],'reconstruction wrong delivery')
        require(r.get('environment')=='reference-linux' and r.get('fresh_extraction') is True and r.get('original_tree_unavailable') is True and r.get('prior_build_outputs_unavailable') is True,'reconstruction isolation incomplete')
        text(r.get('independence_method'),'reconstruction independence',40)
        self.refs(r.get('artifacts'),'reconstruction artifacts',3);self.check_assertions(r.get('checks'))
        binaries=r.get('binaries');require(isinstance(binaries,list) and binaries,'reconstruction binary inventory missing')
        for pair in binaries:
            require(pair['first']!=pair['rebuilt'],'reconstruction compares the same artifact')
            a,b=self.artifact(pair['first']),self.artifact(pair['rebuilt'])
            require(a!=b,'reconstruction compares the same file')
            require(digest(a)==digest(b),'reconstruction binary differs: '+pair.get('name','unknown'))
        expected={'kernel','firmware'}|{Path(f['path']).stem for f in self.manifest['files'] if f['path'].startswith('user/programs/src/bin/') and f['path'].endswith('.rs')}
        require(expected<={p.get('name') for p in binaries},'kernel/firmware/user reconstruction inventory incomplete')
        self.reconstructed=True

    def run(self):
        try:
            require(isinstance(self.index,dict),'qualification index is not an object')
            require(self.index.get('schema')==INDEX_SCHEMA,'qualification index schema unsupported')
            require(self.index.get('evidence_class')==('unit-fixture' if self.fixture_mode else 'real-execution'),'fixture index cannot qualify delivery')
            c=self.index.get('candidate',{});require(c.get('contract_sha256')==CONTRACT_SHA256 and HEX.fullmatch(c.get('source_identity','')),'candidate identity missing/mismatched')
            require(isinstance(self.index.get('artifacts'),dict),'artifact catalog absent')
            self.validate_archive()
            for ref in unique(self.index.get('records'),'record references'):
                try:
                    r=self.json(ref);resolved=self.common(r);require(r['id'] not in self.records,'duplicate record identity')
                    self.records[r['id']]=r
                    if not resolved:self.open_findings.add(r['id'])
                except (KeyError,ValueError,OSError,TypeError,AttributeError,IndexError) as e:self.invalid.append(str(ref)+': '+str(e))
            for kind,method in [('verification',self.verification),('applicability',self.applicability),('execution',self.execution),('review',self.review),('reconstruction',self.reconstruction)]:
                for r in self.records.values():
                    if r['kind']!=kind:continue
                    if r['status']!='PASS':continue
                    try:
                        require(r['id'] not in self.open_findings,'record has unresolved finding')
                        method(r)
                    except (KeyError,ValueError,OSError,TypeError,AttributeError,IndexError) as e:self.invalid.append(r['id']+': '+str(e))
            resolved=set()
            for r in self.records.values():
                if r['kind']!='resolution':continue
                try:
                    require(r['id'] in self.verified and self.current(r) and r['status']=='PASS','resolution unverified')
                    bad,good=self.records[r['failed_record']],self.records[r['passing_record']]
                    require(bad['kind']=='execution' and bad['status']!='PASS' and good['id'] in self.executions,'resolution does not identify a failed and qualified passing execution')
                    failed_cases={c['id'] for c in bad.get('cases',[])}
                    require(failed_cases and failed_cases<={c['id'] for c in good.get('cases',[])},'resolution passing run does not cover failed cases')
                    self.check_assertions(r.get('checks'));text(r.get('repair'),'repair and affected scope',80);resolved.add(bad['id'])
                except (KeyError,ValueError,OSError,TypeError,AttributeError,IndexError) as e:self.invalid.append(r['id']+': '+str(e))
            for rid in self.open_findings-resolved:self.invalid.append(rid+': unresolved finding')
            for r in self.records.values():
                if r['status']!='PASS' and r['id'] not in resolved:self.pending.append(r['id']+': unresolved '+r['status'])
        except (KeyError,ValueError,OSError,TypeError,AttributeError,IndexError,zipfile.BadZipFile) as e:self.invalid.append(str(e))
        if self.source_root:
            try:
                from accept import source_identity
                require(source_identity(self.source_root)==self.index['candidate']['source_identity'],'source changed during final qualification')
            except (KeyError,ValueError,OSError,TypeError) as error:self.invalid.append(str(error))
        gates={}
        for gate,cases in GATE_CASES.items():
            missing=[c for c in cases if not self.case_evidence[c]]
            reviews=[r for r in GATE_REVIEWS[gate] if r not in self.reviews.get(gate,{})]
            extra=[]
            if gate=='G-01':extra+=['check:'+c for c in CHECKS if c not in self.build_checks]
            if gate=='G-04':extra+=['budget:'+b for b in ('fairness4','fairness8','wakeup','context','masking','reclaim') if b not in self.budgets]
            if gate=='G-05':extra+=['budget:'+b for b in ('histories','exhaustive','recovery','largest-recovery') if b not in self.budgets]
            if gate=='G-06' and 'negative-controls' not in self.budgets:extra.append('budget:negative-controls')
            if gate in ('G-02','G-03','G-05'):
                required={'G-02':'AC-01.shell','G-03':'AC-03.three-peer-progress','G-05':'AC-13.independent-reboot-state'}[gate]
                if not any(e.get('binary_kind')=='release' and any(c['id']==required for c in e.get('cases',[])) for e in self.executions.values()):extra.append('release-binary:'+required)
            if gate=='G-07' and not self.reconstructed:extra.append('verified-exact-reconstruction')
            gates[gate]={'status':'PASS' if not missing and not reviews and not extra and not self.invalid and not self.pending else 'INCOMPLETE','missing_cases':missing,'missing_reviews':reviews,'missing_requirements':extra,'qualified_reviews':self.reviews.get(gate,{})}
        full=all(g['status']=='PASS' for g in gates.values())
        status='FAIL' if self.invalid else 'PASS' if full and not self.fixture_mode else 'INCOMPLETE'
        return {'schema':'kernel-rv64.gate-result/v1','status':status,'qualified_delivery':status=='PASS','fixture_mode':self.fixture_mode,'evaluated_utc':datetime.now(timezone.utc).isoformat(),'candidate':self.index.get('candidate') if isinstance(self.index,dict) else None,'index_sha256':digest(self.index_path),'gates':gates,'errors':self.invalid,'pending_records':self.pending,'case_evidence':self.case_evidence,'budgets':self.budgets,'case_families':{f'AC-{n:02d}':{'status':'PASS' if all(self.case_evidence[c] for c in CASES if c.startswith(f'AC-{n:02d}.')) else 'INCOMPLETE'} for n in range(1,23)},'requirements':{f'REQ-{n:02d}':{'case_families':[f'AC-{x:02d}' for x in fam]+(['ABI'] if n==17 else []),'status':'PASS' if all(self.case_evidence[c] for c in CASES if any(c.startswith(f'AC-{x:02d}.') for x in fam)) and (n!=17 or all(self.case_evidence[c] for c in CASES if c.startswith('ABI'))) else 'INCOMPLETE'} for n,fam in REQ_FAMILIES.items()},'limitation':'Digests prove identity. Named assessors and independent verification records describe the actual review; the evaluator cannot establish the truth of fabricated source evidence.'}


def _evaluate(index_path,source_root=None,fixture_mode=False):
    try:
        return Qualifier(index_path,source_root,fixture_mode).run()
    except (KeyError,ValueError,OSError,TypeError,AttributeError,IndexError,zipfile.BadZipFile) as error:
        # Malformed or missing indexes still produce a retained nonpassing gate
        # result; callers must not lose the failure by crashing before reporting.
        return {'schema':'kernel-rv64.gate-result/v1','status':'FAIL','qualified_delivery':False,
                'fixture_mode':fixture_mode,'candidate':None,'errors':[str(error)],
                'gates':{g:{'status':'INCOMPLETE'} for g in GATE_CASES}}


def evaluate(index_path,source_root=None):
    return _evaluate(index_path,source_root)


def evaluate_fixture(index_path):
    """Unit tests may exercise policy coverage; fixtures never qualify delivery."""
    return _evaluate(index_path,fixture_mode=True)
