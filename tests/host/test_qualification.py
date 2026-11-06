"""Synthetic evaluator fixtures are always marked unit-fixture, never delivery."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from package import pack
from qualification import Qualifier,evaluate,evaluate_fixture,RECORD_SCHEMA,INDEX_SCHEMA
from qualification_policy import CONTRACT_SHA256,CHECKS,GATE_REVIEWS,CASES,MUTATIONS,NEGATIVE_CONTROLS


class Bundle:
    def __init__(self,directory):
        self.root=Path(directory);self.artifacts={};self.records=[]
        src=self.root/'source';src.mkdir();(src/'Cargo.toml').write_text('[workspace]\n')
        containers=src/'containers';containers.mkdir();(containers/'Dockerfile').write_text('FROM ubuntu:24.04@sha256:'+'1'*64+'\n')
        packages={'gcc-13-riscv64-linux-gnu':'unit-fixture-gcc','binutils-riscv64-linux-gnu':'unit-fixture-binutils','gdb-multiarch':'unit-fixture-gdb'}
        (containers/'debian-packages-arm64.lock').write_text(''.join(k+'\t'+v+'\n' for k,v in packages.items()))
        self.manifest=pack(src,self.root/'source.zip',self.root/'manifest.json')
        self.add_file('archive',self.root/'source.zip','archive');self.add_file('manifest',self.root/'manifest.json','manifest')
        self.source=self.manifest['source_identity']
        for name in ('kernel','firmware','image','workload'):self.bytes(name,('unit fixture '+name).encode(),name)
        self.json('toolchain',dict(rust='1.99.1',target='riscv64imac-unknown-none-elf',qemu='11.1.3',opensbi='1.7'))
        self.json('configuration',dict(icount='shift=0,align=off,sleep=off',profile='debug'))
        packages={'gcc-13-riscv64-linux-gnu':'unit-fixture-gcc','binutils-riscv64-linux-gnu':'unit-fixture-binutils','gdb-multiarch':'unit-fixture-gdb'}
        self.bytes('packages',''.join(k+'\t'+v+'\n' for k,v in packages.items()).encode(),'package-inventory')
        self.json('environment',dict(system='Linux',distribution='ubuntu',version_id='24.04',base_image_digest='sha256:'+'1'*64,python='3.12.3',pytest='8.4.2',packages=packages,package_inventory_sha256=self.artifacts['packages']['sha256']))
        self.json('observed',dict(status='PASS',source_identity=self.source,kernel_sha256=self.artifacts['kernel']['sha256'],firmware_sha256=self.artifacts['firmware']['sha256'],image_sha256=self.artifacts['image']['sha256'],before=12,after=12))

    def add_file(self,name,path,kind):
        self.artifacts[name]={'path':str(path.relative_to(self.root)),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'kind':kind}
        return name

    def bytes(self,name,value,kind='serial'):
        path=self.root/(name+'.bin');path.write_bytes(value);return self.add_file(name,path,kind)

    def json(self,name,value,kind='report'):
        path=self.root/(name+'.json');path.write_text(json.dumps(value,indent=2)+'\n');return self.add_file(name,path,kind)

    def assertion(self,artifact='observed',pointer='/status',expected='PASS'):
        return {'left':{'artifact':artifact,'pointer':pointer},'op':'eq','right':{'value':expected}}

    def common(self,ident,kind):
        return dict(schema=RECORD_SCHEMA,id=ident,kind=kind,evidence_class='unit-fixture',status='PASS',source_identity=self.source,contract_sha256=CONTRACT_SHA256,assessor={'id':'unit-assessor'},method='Synthetic unit fixture for validator logic only; never used to qualify actual kernel execution.',artifacts=['observed'],findings=[],checks=[self.assertion()])

    def case(self,cid):
        return dict(id=cid,status='PASS',inputs='named synthetic boundary inputs',public_result='synthetic expected result',authoritative_state='synthetic retained observation',forbidden_effects='synthetic before/after census',completion_window='bounded synthetic interval',cleanup='synthetic cleanup observation',limitations='Unit fixture only; no actual guest execution.',checks=[self.assertion(),{'left':{'artifact':'observed','pointer':'/before'},'op':'eq','right':{'artifact':'observed','pointer':'/after'}}])

    def execution(self,ident='E1',case='AC-03.text-write'):
        r=self.common(ident,'execution');r.update(exit_code=0,completed=True,truncated=False,environment='reference-linux',binary_kind='instrumented',substitutions=[],invocation=['unit-fixture'],started_utc='2026-11-06T00:00:00+00:00',completed_utc='2026-11-06T00:00:01+00:00',identities={x:x for x in ('kernel','firmware','image','workload','toolchain','configuration','environment','packages')},bindings={x:{'artifact':'observed','pointer':'/'+(x if x=='source_identity' else x+'_sha256')} for x in ('source_identity','kernel','firmware','image')},boundaries={'cpu':'real-qemu','syscall':'actual-ecall','storage':'real-virtio'},cases=[self.case(case)] if case else [])
        return r

    def record(self,r):
        ref='record-'+r['id'];self.json(ref,r,'record');self.records.append(ref);return r

    def review(self,ident='R1',gate='G-01',obligation='static-protection'):
        r=self.common(ident,'review');r['assessor']={'id':'unit-reviewer'}
        r.update(gate=gate,obligations=[obligation],reviewed_authors=['unit-implementation-author'],independence_method='Synthetic separate reviewer identities exercise independence validation without making a real claim.',observations=[dict(obligation=obligation,method='Synthetic review method with concrete source/artifact inspection description for validator tests.',finding='Synthetic review finding deliberately retained as test-only evidence and not actual delivery.',disposition='PASS',artifacts=['observed'],checks=[self.assertion()])])
        return r

    def verification(self,target,ident='V1'):
        r=self.common(ident,'verification');r['assessor']={'id':'unit-verifier'}
        r.update(target=target,assessment_performed=True,independence_method='Synthetic independent verifier identity for schema tests, not an actual review of the delivered kernel.')
        return r

    def old_execution_with_applicability(self):
        import shutil
        source=self.root/'old-source';shutil.copytree(self.root/'source',source);(source/'README.md').write_text('Older synthetic documentation only.\n')
        previous=pack(source,self.root/'old-source.zip',self.root/'old-manifest.json')
        self.add_file('old-archive',self.root/'old-source.zip','archive');self.add_file('old-manifest',self.root/'old-manifest.json','manifest')
        observed=json.loads((self.root/'observed.json').read_text());observed['source_identity']=previous['source_identity'];self.json('observed',observed)
        execution=self.execution();execution['source_identity']=previous['source_identity']
        applicability=self.common('A1','applicability');applicability.update(execution='E1',previous_archive='old-archive',previous_manifest='old-manifest',changed_paths=['README.md'],unaffected_cases=['AC-03.text-write'],unchanged_inputs=[{'path':'Cargo.toml'}],independence_method='Synthetic separate assessment used only to test exact changed-file and scoped case enforcement.',impact_analysis='Synthetic documentation-only delta with unchanged Cargo input; this is a validator fixture, not an actual independent source-impact assessment of any executed kernel.',checks=[self.assertion()])
        return execution,applicability

    def reconstruction(self, ident='RC1'):
        r=self.common(ident,'reconstruction')
        self.bytes('rebuilt-kernel',(self.root/'kernel.bin').read_bytes(),'binary')
        self.bytes('rebuilt-firmware',(self.root/'firmware.bin').read_bytes(),'binary')
        r.update(archive='archive',manifest='manifest',environment='reference-linux',fresh_extraction=True,original_tree_unavailable=True,prior_build_outputs_unavailable=True,independence_method='Synthetic separately extracted fixture for policy validation; does not claim actual compilation.',artifacts=['observed','archive','manifest'],binaries=[dict(name=n,first=n,rebuilt='rebuilt-'+n) for n in ['kernel','firmware']])
        return r

    def all_budgets(self):
        # Deliberately synthetic full-cardinality records exercise every budget
        # validator. The index remains unit-fixture, so delivery can never PASS.
        from test_bench_oracle import fixture,wire,ExtendedMeasurementOracle
        records={n:wire(fixture(int(n[-1]))) for n in ['fairness4','fairness8']}
        frame=ExtendedMeasurementOracle().frame
        records['wakeup']=frame('wakeup',[dict(event='configuration',frequency=1000,required_samples=10000,peers=7,sleep_ms=10),*[dict(event='wake-sample',sample=i+1,deadline_ticks=i*100,wake_ticks=i*100+1,user_ticks=i*100+21,wake_latency_ticks=20,deadline_latency_ticks=21) for i in range(10000)]])
        records['context']=frame('context',[dict(event='configuration',frequency=1000,required_samples=10000,calibration='consecutive-counter-reads',scope='process-to-scheduler-to-process'),*[dict(event='context-sample',sample=i+1,ticks=28,calibration_ticks=1) for i in range(10000)]])
        records['masking']=frame('masking',[dict(event='masking',frequency=1000000,intervals=9,maximum_ticks=900,location='unit-fixture',line=1,start_ticks=1,end_ticks=10000),*[dict(event='mask-bucket',bucket=i,count=9 if i==3 else 0) for i in range(7)]])
        records['reclaim']=frame('reclaim',[*[dict(event='baseline',owner=i,count=i) for i in range(12)],*[dict(event='progress',completed_cycles=i) for i in range(1000,10001,1000)],*[dict(event='final',owner=i,count=i) for i in range(12)]])
        budgets={}
        for name,serial in records.items():
            self.bytes('serial-'+name,serial);self.json('report-'+name,dict(status='PASS',host={'system':'Linux'},icount='shift=0,align=off,sleep=off',profile='debug',run_id='a'*32,boot_id='b'*32,serial_sha256=self.artifacts['serial-'+name]['sha256'],source_identity=self.source,kernel_sha256=self.artifacts['kernel']['sha256'],firmware_sha256=self.artifacts['firmware']['sha256'],image_sha256=self.artifacts['image']['sha256']))
            budgets[name]=dict(report='report-'+name,serial='serial-'+name,run_id='a'*32,boot_id='b'*32,checks=[self.assertion('report-'+name)])
        reports={
            'histories':dict(status='PASS',histories=[dict(seed=i,status='PASS',operations=100,cuts=[dict(status='PASS',image_sha256='1'*64) for _ in range(20)]) for i in range(100)]),
            'exhaustive':dict(status='PASS',profile='exhaustive-small',workload='all',enumerated_outcomes=256,unique_boots=1,cases=[dict(status='PASS')]),
            'recovery':dict(status='PASS',completed_cases=2,replay_boundaries=1,cases=[dict(status='PASS',policy=p,interruptions=[dict(image_sha256='2'*64) for _ in range(3)]) for p in ['none','all']]),
            'largest-recovery':dict(status='PASS',boot_to_ready_host_seconds=1,image_bytes=64*1024*1024,redo_count=16,block_read_bytes_before_ready=4096),
            'negative-controls':dict(status='PASS',controls=[dict(name=n,status='PASS',baseline='PASS',restored='PASS',outcome='intended-assertion',expected_assertion='expected',observed_assertion='expected',artifacts=['kernel','firmware','observed'],checks=[self.assertion()]) for n in NEGATIVE_CONTROLS]),
        }
        for name,report in reports.items():
            self.json('report-'+name,report);budgets[name]=dict(report='report-'+name,checks=[self.assertion('report-'+name)])
        self.json('inventory',dict(expected_outcomes=256,expected_unique_boots=1,input_artifacts=['observed'],mutation_classes=list(MUTATIONS),subspaces=['submission','completion','flush','all-lost','all-persisted','256-per-block','all-combinations-at-most12','commit-sector-both','descriptor-payload-reorder'],declared_cuts=1,completed_cuts=1))
        budgets['exhaustive']['inventory']='inventory';budgets['recovery']['phases']=['replay-write','replay-flush','clear-write','clear-flush']
        return budgets

    def write(self):
        index={'schema':INDEX_SCHEMA,'evidence_class':'unit-fixture','candidate':{'source_identity':self.source,'contract_sha256':CONTRACT_SHA256,'archive':'archive','manifest':'manifest'},'artifacts':self.artifacts,'records':self.records}
        path=self.root/'qualification.json';path.write_text(json.dumps(index,indent=2)+'\n');return path


class QualificationRejections(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.b=Bundle(self.temp.name)

    def result(self):return evaluate_fixture(self.b.write())

    def rejected(self,phrase):
        result=self.result();self.assertEqual(result['status'],'FAIL');self.assertIn(phrase,' '.join(result['errors']));self.assertFalse(result['qualified_delivery'])

    def test_partial_real_case_mapping_does_not_promote_gate(self):
        self.b.record(self.b.execution());r=self.result()
        self.assertEqual(r['case_evidence']['AC-03.text-write'],['E1']);self.assertFalse(r['errors']);self.assertEqual(r['status'],'INCOMPLETE')
        self.assertIn('ABI-12.cross-page',r['gates']['G-03']['missing_cases'])

    def test_fixture_is_rejected_by_production_evaluator(self):
        self.b.record(self.b.execution());r=evaluate(self.b.write());self.assertEqual(r['status'],'FAIL');self.assertIn('fixture index',' '.join(r['errors']))

    def test_tampered_referenced_artifact(self):
        self.b.record(self.b.execution());(self.b.root/'observed.json').write_text('{}');self.rejected('digest mismatch')

    def test_artifact_traversal_and_absolute_path(self):
        self.b.record(self.b.execution())
        for path in ('../escape.json','/tmp/escape.json'):
            self.b.artifacts['observed']['path']=path;self.rejected('unsafe artifact path')

    def test_source_stale_without_scoped_applicability(self):
        r=self.b.execution();r['source_identity']='1'*64
        observed=json.loads((self.b.root/'observed.json').read_text());observed['source_identity']='1'*64;self.b.json('observed',observed)
        self.b.record(r);self.rejected('stale')

    def test_kernel_identity_must_match_actual_retained_binary(self):
        observed=json.loads((self.b.root/'observed.json').read_text());observed['kernel_sha256']='0'*64;self.b.json('observed',observed)
        self.b.record(self.b.execution());self.rejected('raw identity mismatch: kernel')

    def test_assertion_checks_raw_value_not_claimed_pass(self):
        r=self.b.execution();r['cases'][0]['checks'].append(self.b.assertion(pointer='/after',expected=13));self.b.record(r);self.rejected('artifact assertion failed')

    def test_boot_refusal_can_qualify_only_pre_user_negative_cases(self):
        self.b.json('refusal',dict(refused=True,user_entry=False,persistent_image_unchanged=True))
        r=self.b.execution(case='AC-01.boot-refusals')
        r['cases'].append(self.b.case('AC-16.refusal-no-repair'))
        r['artifacts'].append('refusal')
        r['boundaries']['syscall']='not-reached-boot-refusal'
        r['boundary_observations']={'boot_refusal':{'artifact':'refusal','pointer':''}}
        self.b.record(r);result=self.result()
        self.assertEqual(result['errors'],[])
        self.assertEqual(result['case_evidence']['AC-01.boot-refusals'],['E1'])
        self.assertEqual(result['case_evidence']['AC-16.refusal-no-repair'],['E1'])
        self.assertFalse(result['qualified_delivery'])

    def test_boot_refusal_cannot_replace_abi_or_user_execution(self):
        for cid in ['ABI-00.valid','AC-03.text-write','AC-05.header-fields']:
            with self.subTest(case=cid):
                directory=Path(self.temp.name)/cid.replace('.','-');directory.mkdir();b=Bundle(directory)
                b.json('refusal',dict(refused=True,user_entry=False,persistent_image_unchanged=True))
                r=b.execution(case=cid);r['artifacts'].append('refusal')
                r['boundaries']['syscall']='not-reached-boot-refusal'
                r['boundary_observations']={'boot_refusal':{'artifact':'refusal','pointer':''}}
                b.record(r);result=evaluate_fixture(b.write())
                self.assertIn('boot-refusal boundary cannot qualify',' '.join(result['errors']))
                self.assertFalse(result['case_evidence'][cid])

    def test_boot_refusal_requires_retained_no_user_unchanged_image_observation(self):
        for field,value in [('refused',False),('user_entry',True),('persistent_image_unchanged',False),('persistent_image_unchanged',1)]:
            with self.subTest(field=field,value=value):
                directory=Path(self.temp.name)/(field+str(value));directory.mkdir();b=Bundle(directory)
                observation=dict(refused=True,user_entry=False,persistent_image_unchanged=True);observation[field]=value
                b.json('refusal',observation);r=b.execution(case='AC-16.refusal-no-repair')
                r['artifacts'].append('refusal');r['boundaries']['syscall']='not-reached-boot-refusal'
                r['boundary_observations']={'boot_refusal':{'artifact':'refusal','pointer':''}}
                b.record(r);result=evaluate_fixture(b.write())
                self.assertEqual(result['status'],'FAIL');self.assertFalse(result['case_evidence']['AC-16.refusal-no-repair'])

    def test_host_fake_cannot_qualify_ecall_boundary(self):
        r=self.b.execution();r['binary_kind']='host';self.b.record(r);self.rejected('host algorithm evidence')

    def test_duplicate_and_unknown_case_names_rejected(self):
        r=self.b.execution();r['cases']*=2;self.b.record(r);self.rejected('duplicate case')

    def test_failed_exit_truncation_and_skipped_case(self):
        for field,value in (('exit_code',1),('truncated',True),('completed',False)):
            with self.subTest(field=field):
                r=self.b.execution();r[field]=value;self.b.records=[];self.b.record(r);self.rejected('incomplete, capped or failed')
        r=self.b.execution();r['cases'][0]['status']='NOT RUN';self.b.records=[];self.b.record(r);self.rejected('skipped or unsuccessful')

    def test_unverified_review_and_self_verification_are_not_accepted(self):
        self.b.record(self.b.review());r=self.result();self.assertIn('unverified',' '.join(r['errors']))
        v=self.b.verification('R1');v['assessor']={'id':'unit-reviewer'};self.b.record(v);self.rejected('self-verification')

    def test_substantive_verified_review_is_accepted_for_its_scope_only(self):
        self.b.record(self.b.review());self.b.record(self.b.verification('R1'));r=self.result()
        self.assertFalse(r['errors']);self.assertEqual(r['gates']['G-01']['qualified_reviews'],{'static-protection':'R1'});self.assertEqual(r['status'],'INCOMPLETE')

    def test_open_finding_remains_nonpassing(self):
        r=self.b.execution();r['findings']=[dict(id='F1',observation='Actual unresolved condition represented by a synthetic test',disposition='OPEN')];self.b.record(r);self.rejected('unresolved finding')

    def test_missing_archive_member_or_changed_source_identity(self):
        data=json.loads((self.b.root/'manifest.json').read_text());data['source_identity']='f'*64;self.b.json('manifest',data,'manifest');self.rejected('manifest source identity mismatch')

    def test_wrong_toolchain_version_cannot_qualify(self):
        self.b.json('toolchain',dict(rust='1.80.0',target='riscv64imac-unknown-none-elf',qemu='11.1.3',opensbi='1.7'));self.b.record(self.b.execution());self.rejected('compiler/target substitution')

    def test_history_budget_has_per_history_cut_and_operation_checks(self):
        report=dict(status='PASS',histories=[dict(seed=i,status='PASS',operations=100,cuts=[dict(status='PASS',image_sha256='1'*64) for _ in range(20)]) for i in range(100)])
        self.b.json('history-report',report);r=self.b.execution();r['cases']=[self.b.case(c) for c in CASES];r['budgets']={'histories':{'report':'history-report','checks':[self.b.assertion('history-report')]}};self.b.record(r)
        self.assertIn('histories',self.result()['budgets'])
        report['histories'][-1]['cuts'].pop();self.b.json('history-report',report);self.rejected('operation/cut budget short')

    def test_exhaustive_summary_must_match_independent_inventory(self):
        report=dict(status='PASS',profile='exhaustive-small',workload='all',enumerated_outcomes=256,unique_boots=1,cases=[dict(status='PASS')])
        self.b.json('crash-report',report);self.b.json('inventory',dict(expected_outcomes=257,expected_unique_boots=1,input_artifacts=['observed']))
        r=self.b.execution();r['cases']=[self.b.case(c) for c in CASES];r['budgets']={'exhaustive':{'report':'crash-report','inventory':'inventory','checks':[self.b.assertion('crash-report')]}};self.b.record(r);self.rejected('truncated outcome matrix')

    def test_invalid_late_budget_publishes_no_cases_checks_or_earlier_budget(self):
        report=dict(status='PASS',histories=[dict(seed=i,status='PASS',operations=100,cuts=[dict(status='PASS',image_sha256='1'*64) for _ in range(20)]) for i in range(100)])
        self.b.json('history-report',report);self.b.json('bad-largest',dict(status='PASS',image_bytes=1))
        r=self.b.execution();r['build_checks']=['locked-rust-tests'];r['cases']=[self.b.case(c) for c in CASES];r['budgets']={'histories':{'report':'history-report','checks':[self.b.assertion('history-report')]},'largest-recovery':{'report':'bad-largest','checks':[self.b.assertion('bad-largest')]}}
        self.b.record(r);result=self.result()
        self.assertEqual(result['status'],'FAIL');self.assertFalse(result['case_evidence']['AC-03.text-write']);self.assertFalse(result['budgets'])
        self.assertIn('check:locked-rust-tests',result['gates']['G-01']['missing_requirements'])

    def test_negative_control_timeout_is_not_intended_assertion(self):
        from qualification_policy import NEGATIVE_CONTROLS
        controls=[dict(name=n,status='PASS',baseline='PASS',restored='PASS',outcome='intended-assertion',expected_assertion='expected',observed_assertion='expected',artifacts=['kernel','firmware','observed'],checks=[self.b.assertion()]) for n in NEGATIVE_CONTROLS]
        controls[0]['outcome']='timeout';self.b.json('controls',dict(status='PASS',controls=controls));r=self.b.execution();r['cases']=[self.b.case(c) for c in CASES];r['budgets']={'negative-controls':{'report':'controls','checks':[self.b.assertion('controls')]}};self.b.record(r);self.rejected('wrong mutant failure')

    def test_unresolved_failed_run_cannot_be_hidden_by_passing_run(self):
        bad=self.b.execution('bad');bad['status']='FAIL';self.b.record(bad);self.b.record(self.b.execution('good'));r=self.result();self.assertEqual(r['status'],'INCOMPLETE');self.assertIn('bad: unresolved FAIL',r['pending_records'])

    def test_missing_required_record_does_not_raise_unhandled_exception(self):
        self.b.records=['absent'];r=self.result();self.assertEqual(r['status'],'FAIL');self.assertIn('unknown artifact',' '.join(r['errors']))


    def test_all_eight_policy_gates_attainable_but_fixture_never_qualifies(self):
        budgets=self.b.all_budgets()
        for name in ['fairness4','fairness8','wakeup','context','masking','reclaim']:
            m=self.b.execution('measurement-'+name);report='report-'+name
            m.update(cases=[self.b.case(c) for c in CASES],budgets={name:budgets.pop(name)},artifacts=['observed',report])
            for binding in m['bindings'].values():binding['artifact']=report
            self.b.record(m)
        r=self.b.execution();r.update(binary_kind='release',cases=[self.b.case(c) for c in CASES],build_checks=list(CHECKS),budgets=budgets);self.b.record(r)
        for gate,obligations in GATE_REVIEWS.items():
            for n,obligation in enumerate(obligations):
                rid=gate+'-'+str(n);self.b.record(self.b.review(rid,gate,obligation));self.b.record(self.b.verification(rid,'verify-'+rid))
        self.b.record(self.b.reconstruction());self.b.record(self.b.verification('RC1','verify-reconstruction'))
        result=self.result();self.assertFalse(result['errors'],result['errors'])
        self.assertTrue(all(g['status']=='PASS' for g in result['gates'].values()),result['gates'])
        self.assertTrue(all(r['status']=='PASS' for r in result['requirements'].values()))
        self.assertEqual(result['status'],'INCOMPLETE');self.assertFalse(result['qualified_delivery'])
        production=evaluate(self.b.write());self.assertEqual(production['status'],'FAIL');self.assertFalse(production['qualified_delivery'])

    def test_measurement_serial_must_belong_to_bound_execution_report(self):
        budgets=self.b.all_budgets();r=self.b.execution();r.update(cases=[self.b.case('AC-19.fairness4')],budgets={'fairness4':budgets['fairness4']},artifacts=['observed','report-fairness4'])
        self.b.record(r);self.rejected('not the execution identity chain')
        self.b.records=[]
        for binding in r['bindings'].values():binding['artifact']='report-fairness4'
        self.b.record(r);self.assertFalse(self.result()['errors'])
        # Swapping a fully valid stream while changing the parser's expected IDs
        # cannot detach it from the launch report associated with this binary.
        report=json.loads((self.b.root/'report-fairness4.json').read_text());report['run_id']='c'*32;self.b.json('report-fairness4',report);self.rejected('run identity differs')
        report['run_id']='a'*32;self.b.json('report-fairness4',report)
        self.b.bytes('serial-fairness4',(self.b.root/'serial-fairness4.bin').read_bytes()+b'UOUT \"extra\"\n');self.rejected('serial digest differs')

    def test_reference_label_cannot_override_observed_native_environment(self):
        environment=json.loads((self.b.root/'environment.json').read_text());environment['system']='Darwin';self.b.json('environment',environment)
        r=self.b.execution();r['build_checks']=['locked-rust-tests'];self.b.record(r);self.rejected('not observed Ubuntu24.04 Linux')

    def test_observed_package_inventory_must_match_its_digest_and_revisions(self):
        environment=json.loads((self.b.root/'environment.json').read_text());environment['packages']['gdb-multiarch']='wrong';self.b.json('environment',environment)
        self.b.record(self.b.execution());self.rejected('compiler/binutils/GDB package differs')

    def test_measurement_requires_instrumented_kind_and_observed_linux_host(self):
        budgets=self.b.all_budgets();r=self.b.execution();r.update(binary_kind='release',cases=[self.b.case('AC-19.fairness4')],budgets={'fairness4':budgets['fairness4']},artifacts=['observed','report-fairness4'])
        for binding in r['bindings'].values():binding['artifact']='report-fairness4'
        self.b.record(r);self.rejected('requires instrumented binary')
        self.b.records=[];r['binary_kind']='instrumented';self.b.record(r)
        report=json.loads((self.b.root/'report-fairness4.json').read_text());report['host']['system']='Darwin';self.b.json('report-fairness4',report);self.rejected('not observed on Linux')

    def test_verified_applicability_reuses_only_executed_named_scope(self):
        r,a=self.b.old_execution_with_applicability();self.b.record(r);self.b.record(a);self.b.record(self.b.verification('A1'));result=self.result()
        self.assertFalse(result['errors'],result['errors']);self.assertEqual(result['case_evidence']['AC-03.text-write'],['E1'])
        self.assertFalse(result['case_evidence']['AC-03.data-execute'])

    def test_applicability_rejects_omitted_change_and_unexecuted_case(self):
        r,a=self.b.old_execution_with_applicability();a['changed_paths']=[];self.b.record(r);self.b.record(a);self.b.record(self.b.verification('A1'));self.rejected('omits or invents')
        self.b.records=[];a['changed_paths']=['README.md'];a['unaffected_cases'].append('AC-03.data-execute');self.b.record(r);self.b.record(a);self.b.record(self.b.verification('A1'));self.rejected('adds unexecuted cases')

    def test_applicability_cannot_claim_changed_input_unchanged(self):
        r,a=self.b.old_execution_with_applicability();a['unchanged_inputs']=[{'path':'README.md'}];self.b.record(r);self.b.record(a);self.b.record(self.b.verification('A1'));self.rejected('unchanged source input differs')

    def test_stale_build_check_needs_its_own_assessed_applicability(self):
        r,a=self.b.old_execution_with_applicability();r['build_checks']=['locked-rust-tests'];self.b.record(r);self.b.record(a);self.b.record(self.b.verification('A1'));self.rejected('stale build check')
        self.b.records=[];a['unaffected_build_checks']=['locked-rust-tests'];self.b.record(r);self.b.record(a);self.b.record(self.b.verification('A1'));self.assertFalse(self.result()['errors'])

    def test_reference_base_and_full_inventory_must_match_archive_pins(self):
        self.b.record(self.b.execution());environment=json.loads((self.b.root/'environment.json').read_text());environment['base_image_digest']='sha256:'+'2'*64;self.b.json('environment',environment);self.rejected('base image differs from archived')
        environment['base_image_digest']='sha256:'+'1'*64
        contents=(self.b.root/'packages.bin').read_bytes()+b'unreviewed-package\tchanged-revision\n';self.b.bytes('packages',contents,'package-inventory');environment['package_inventory_sha256']=self.b.artifacts['packages']['sha256'];self.b.json('environment',environment);self.rejected('inventory differs from archived')

    def test_masking_configuration_must_match_bound_launch_report(self):
        budgets=self.b.all_budgets();r=self.b.execution();r.update(cases=[self.b.case('AC-19.masking-debug')],budgets={'masking':budgets['masking']},artifacts=['observed','report-masking'])
        for binding in r['bindings'].values():binding['artifact']='report-masking'
        self.b.record(r);report=json.loads((self.b.root/'report-masking.json').read_text());report['profile']='release';self.b.json('report-masking',report);self.rejected('report/configuration mismatch')

    def test_budget_cannot_attach_to_unrelated_case(self):
        self.b.json('history-report',dict(status='PASS',histories=[]));r=self.b.execution();r['budgets']={'histories':dict(report='history-report',checks=[self.b.assertion('history-report')])};self.b.record(r);self.rejected('budget lacks its qualified named cases')

    def test_reconstruction_rejects_same_file_and_binary_mismatch(self):
        r=self.b.reconstruction();r['binaries'][0]['rebuilt']='kernel';self.b.record(r);self.b.record(self.b.verification('RC1'));self.rejected('same artifact')
        self.b.records=[];r=self.b.reconstruction();self.b.bytes('rebuilt-kernel',b'wrong','binary');self.b.record(r);self.b.record(self.b.verification('RC1'));self.rejected('binary differs')

    def test_reconstruction_requires_isolation_and_independent_verification(self):
        r=self.b.reconstruction();self.b.record(r);self.rejected('reconstruction unverified')
        self.b.records=[];r['original_tree_unavailable']=False;self.b.record(r);self.b.record(self.b.verification('RC1'));self.rejected('reconstruction isolation incomplete')

    def test_malformed_index_always_returns_nonpassing_report(self):
        for value in ([],None,{'schema':INDEX_SCHEMA,'evidence_class':'unit-fixture','candidate':[]}):
            path=self.b.root/'malformed.json';path.write_text(json.dumps(value));r=evaluate_fixture(path);self.assertEqual(r['status'],'FAIL');self.assertFalse(r['qualified_delivery'])
        self.assertEqual(evaluate_fixture(self.b.root/'absent.json')['status'],'FAIL')
        path.write_text('{"duplicate":1,"duplicate":2}')
        self.assertEqual(evaluate_fixture(path)['status'],'FAIL')

    def test_fresh_incomplete_check_cannot_be_overridden(self):
        from accept import combined_status
        self.assertEqual(combined_status(True,[{'status':'INCOMPLETE'}],{'status':'PASS'}),'INCOMPLETE')
        self.assertEqual(combined_status(True,[{'status':'FAIL'}],{'status':'PASS'}),'FAIL')
        self.assertEqual(combined_status(False,[{'status':'PASS'}],{'status':'PASS'}),'FAIL')
        self.assertEqual(combined_status(True,[],{'status':'PASS'}),'INCOMPLETE')
        self.assertEqual(combined_status(True,[{'status':'PASS'}],{'status':'PASS'}),'PASS')


if __name__=='__main__':unittest.main()
