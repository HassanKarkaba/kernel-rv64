"""Edition1.0 acceptance inventory: case names are obligations, not test counts."""
CONTRACT_SHA256 = 'b1c14e08f41b6710f7c6b4d629428ae9e76bbcde199975e2abca86d7ea2557a5'
CASE_FAMILIES = {
 'AC-01': ('reference-build','fresh-image-boot','shell','device-identities','boot-refusals'),
 'AC-02': ('process-slots','descriptor-slots','open-descriptions','pipes','inodes','data-blocks','extents','per-process-pages','global-frames','release-retry-owner-census'),
 'AC-03': ('three-peer-progress','peer-memory','kernel-memory','text-write','data-execute','user-guard','kernel-guard','overflow-pointer','privileged-instruction'),
 'AC-04': ('zero-allocation','exact-free','partial-free','double-free','reuse-zero','translation-invalidation','exit-reclaim'),
 'AC-05': ('valid-lower-upper','header-fields','header-table-bounds','file-limit','segment-types','flags','permissions','alignment-congruence','file-virtual-arithmetic','rounded-overlap','entry-range','no-publication-no-leak'),
 'AC-06': ('duplicate-stdio','missing-stdio','wrong-rights','exhausted-tables','copied-argv','max-argv','shared-offset','private-publication'),
 'AC-07': ('normal-exit','fault-exit','any-child-order','nohang','copyout-preserves-zombie','stale-pid','parent-exit','orphan-reap'),
 'AC-08': ('user-timer','supervisor-timer-deferred','complete-registers','untrusted-sp','nested-frame','guard-fatal'),
 'AC-09': ('pipe-before-predicate','pipe-protected-registration','pipe-after-registration','pipe-before-wake','pipe-before-user-return','last-writer-close','child-selection-block','io-complete-before-sleep','one-ready-owner','no-leaked-lock'),
 'AC-10': ('empty-full','atomic512-competitors','short513','last-reader-epipe','last-writer-buffered-eof','inherited-refs','invalid-full-output'),
 'AC-11': ('cr-lf-backspace-delete','line-limit','nonascii-control','quotes-escapes','pipeline-eof','second-spawn-failure','temporary-collision-capacity','uart-overflow-counter','subsequent-progress'),
 'AC-12': ('create-exclusive-truncate','unaligned-write','eof','shared-independent-offsets','seek-clamp','full-list-snapshot','stat-full-output','rename-replace','open-target-ebusy','max-file','readonly-open-matrix','readonly-permitted','failed-precedence','invalid-no-block-request'),
 'AC-13': ('acknowledged-create','acknowledged-write','acknowledged-append-indirect','acknowledged-truncate','acknowledged-rename-replace','acknowledged-unlink','independent-reboot-state'),
 'AC-14': ('every-mutation-class','submission-completion-flush-cuts','sector-subsets','small-combinations','commit-sector-both','descriptor-payload-reorder','100x100-histories','20-cuts-each','indirect-crossing','whole-image-oracle'),
 'AC-15': ('stable-commit-partial-home','replay-each-write','replay-flush','clear-write','clear-flush','three-interruptions','same-committed-state'),
 'AC-16': ('superblock-fields','allocation-fields','inode-fields','directory-fields','indirect-pointers','checksums','journal-targets','uuid-sequence','reserved-padding','pointer-alias','torn-commit','refusal-no-repair'),
 'AC-17': ('ioerr','unsupp','delayed-completion','used-identity','used-length','reset-success','reset-failure','timeout-deadline','dma-retained'),
 'AC-18': ('active-pipe-compute-during-failure','failed-file-consistency','cleanup-after-failure','unauthorized-shutdown','clean-shutdown','uncertain-shutdown','active-transaction-drain','admitted-waiter-recheck','five-second-drain'),
 'AC-19': ('fairness4','fairness8','wakeup10000','masking-debug','context10000-calibration','reclaim10000','largest-recovery','raw-records-no-loss','trace-overflow-lost-counter'),
 'AC-20': ('symlink-image','occupied-lock','failed-build','interrupted-test','ordinary-data-preserved','unrelated-process-preserved'),
 'AC-21': ('unsafe-callers','lock-order','elf-permissions','unresolved-symbols','dependency-provenance','archive-exclusions'),
 'AC-22': ('early-ack','missing-prepare-flush','missing-commit-flush','early-clear','stale-journal-reuse','copyout-before-consume','unprotected-waiter','writable-executable','missing-tlb-invalidation','intended-assertions','baseline-restored'),
}
# Boundary applicability follows ABI3B. Unused arguments are universal; omitted
# pointer/rights/flag categories are inapplicable, not silent test exemptions.
ABI_BOUNDARIES = {
 0:'valid null unmapped cross-page overflow full-output',
 1:'valid-min valid-max low32-exit-code', 2:'valid', 3:'valid',
 4:'valid-min valid-max invalid-scalar positive-no-round-down', 5:'valid monotonic',
 6:'valid-min valid-max invalid-scalar', 7:'valid-min valid-max invalid-scalar unaligned partial double-free overflow no-effect',
 8:'valid-min valid-max invalid-scalar invalid-handle wrong-rights null unmapped cross-page overflow argv-no-effect',
 9:'valid invalid-flags invalid-handle wrong-owner null unmapped cross-page overflow full-output no-effect',
 10:'valid-min valid-max invalid-flags invalid-path null unmapped cross-page overflow no-effect readonly-write readonly-readwrite readonly-create-existing readonly-create-missing readonly-truncate',
 11:'valid invalid-handle',
 12:'valid-min valid-max invalid-scalar invalid-handle wrong-rights null unmapped cross-page overflow full-output zero-length no-effect',
 13:'valid-min valid-max invalid-scalar invalid-handle wrong-rights null unmapped cross-page overflow zero-length copy-before-effect',
 14:'valid-min valid-max invalid-scalar invalid-handle pipe-console',
 15:'valid invalid-handle readonly failed',
 16:'valid invalid-path null unmapped cross-page overflow full-output',
 17:'valid-min valid-max invalid-scalar null unmapped cross-page overflow capacity full-output',
 18:'valid invalid-path null unmapped cross-page overflow open-target no-effect',
 19:'valid invalid-path null unmapped cross-page overflow open-target same-name no-effect',
 20:'valid null unmapped cross-page overflow full-output no-effect',
 21:'valid invalid-handle exhaustion',
 22:'valid-min valid-max invalid-scalar null unmapped cross-page overflow capacity full-output',
 23:'init-only child-denied',
}
CASES = {f'{family}.{name}':family for family,names in CASE_FAMILIES.items() for name in names}
CASES.update({f'ABI-{number:02d}.{name}':'ABI' for number,names in ABI_BOUNDARIES.items() for name in names.split()+['unused']})
CASES['ABI.unknown-number']='ABI'
GATE_CASES = {
 'G-01': ['AC-21.unsafe-callers','AC-21.lock-order','AC-01.reference-build','AC-21.elf-permissions','AC-21.unresolved-symbols','AC-21.dependency-provenance'],
 'G-02': [c for c in CASES if c.startswith(('AC-01.','AC-11.'))],
 'G-03': [c for c in CASES if c.startswith(('ABI','AC-02.','AC-03.','AC-04.','AC-05.','AC-06.','AC-07.'))],
 'G-04': [c for c in CASES if c.startswith(('AC-08.','AC-09.','AC-10.','AC-19.'))],
 'G-05': [c for c in CASES if c.startswith(('AC-12.','AC-13.','AC-14.','AC-15.'))]+['AC-19.largest-recovery'],
 'G-06': [c for c in CASES if c.startswith(('AC-16.','AC-17.','AC-18.','AC-22.'))],
 'G-07': [c for c in CASES if c.startswith('AC-20.')]+['AC-01.reference-build'],
 'G-08': ['AC-21.archive-exclusions'],
}
assert set(CASES)==set().union(*map(set,GATE_CASES.values())), 'every mandatory case must belong to a release gate'
GATE_REVIEWS = {
 'G-01':['compiler-firmware-provenance','static-protection'],
 'G-02':['boot-platform-journeys'],
 'G-03':['ownership-isolation','syscall-precedence-effects','process-publication-lifetime'],
 'G-04':['atomic-wait-windows','scheduler-accounting-instrumentation'],
 'G-05':['journal-order-recovery','independent-storage-oracle','complete-crash-inventory'],
 'G-06':['failure-reset-shutdown','meaningful-negative-controls'],
 'G-07':['independent-reconstruction-host-isolation'],
 'G-08':['archive-delivery-consistency','complete-requirement-ledger'],
}
CHECKS = ('locked-rust-tests','full-pytest','rustfmt','clippy-host','clippy-rv64','clippy-instrumented','release-build','static-elf')
NEGATIVE_CONTROLS = ('early-ack','missing-prepare-flush','missing-commit-flush','early-clear','stale-journal-reuse','copyout-before-consume','unprotected-waiter','writable-executable','missing-tlb-invalidation')
MUTATIONS = ('create','write','append','truncate','rename','rename-replace','unlink')
REQ_FAMILIES = {
 1:[1,8,17],2:[1,3,10,12,13],3:[2,4,6],4:[3,4,8],5:[2,6,7],6:[8,9,19],7:[9,19],8:[9,10,11],9:[2,12,13],10:[9,12,17],11:[13,14,22],12:[13,14,15],13:[14,15,16],14:[12,17,18],15:[1,11],16:[3,7,16,18,21],17:[6,7,10,12],18:[3,5],19:[4,8,21],20:[14,15,16],21:[22],22:[1,20,21,22],23:[1,8,18],24:[17],25:[11,19],26:[1,20],
}

def catalog():
    return {'schema':'kernel-rv64.coverage/v1','contract_sha256':CONTRACT_SHA256,'cases':CASES,'gates':{g:{'cases':v,'reviews':GATE_REVIEWS[g]} for g,v in GATE_CASES.items()},'build_checks':CHECKS,'negative_controls':NEGATIVE_CONTROLS,'requirements':{f'REQ-{n:02d}':[f'AC-{x:02d}' for x in ac]+(['ABI'] if n==17 else []) for n,ac in REQ_FAMILIES.items()}}
