# Qualification records, version 1

`tools/accept.py --suite host` remains a host algorithm/tool check. It cannot qualify the kernel. `--suite all` executes the available real families, including full storage and measurement budgets, and can evaluate a supplied external index. `--finalize` evaluates previously captured evidence without rerunning expensive campaigns:

```sh
python3 tools/accept.py --catalog --output /evidence/new-catalog
python3 tools/accept.py --suite all --evidence-index /bundle/qualification.json --output /evidence/new-run
python3 tools/accept.py --finalize /bundle/qualification.json --output /evidence/new-finalization
```

Outputs must be new directories outside the source. Finalization exits0 only when every G-01–G-08 gate qualifies for the current source and its packaged archive. Missing cases/reviews, old identities, inadequate budgets and unresolved runs remain non-passing. `--catalog` only writes the obligation inventory and never qualifies execution. The catalog expands AC-01–AC-22 and the applicable ABI boundaries; case IDs are stable names, not a target test count.

## Index and artifact catalog

The index has `schema: "kernel-rv64.qualification/v1"`, `evidence_class: "real-execution"`, `candidate`, `artifacts`, and `records`. Candidate fields are `source_identity`, the edition1.0 `contract_sha256`, and artifact IDs `archive` and `manifest`. The source identity must equal both the archive's independently recomputed identity and the current source tree. Source archive members, modes, exclusions, sizes and digests are checked without extracting anything.

`artifacts` maps stable IDs to `{ "path": "relative/path", "sha256": "64 lowercase hex", "kind": "report" }`. All paths are relative to the index's directory. Absolute paths, traversal, symlinks and digest mismatches are rejected. Place the index at a common bundle root that contains the archive, manifest and retained evidence. Every referenced file must exist locally. `records` lists artifact IDs for the versioned JSON records below; record contents are themselves hash checked. Use meaningful artifact kinds such as `report`, `serial`, `kernel`, `firmware`, `image`, `configuration`, `tool-identity`, `review-notes`, `archive`, `manifest` and `record`.

All records have:

- `schema: "kernel-rv64.evidence-record/v1"`, a unique `id`, `kind`, `evidence_class: "real-execution"`, `status` (`PASS`, `FAIL`, `INCOMPLETE`, or `NOT RUN`), exact `source_identity` and `contract_sha256`.
- `assessor: {"id": "named-person-or-agent"}`, a substantive `method`, supporting artifact IDs in `artifacts`, and `findings` (possibly empty).
- Each finding has `id`, concrete `observation`, and `disposition` (`OPEN`, `RESOLVED`, or `NOT_APPLICABLE`). A resolved finding references retained resolution artifacts in `evidence`; inapplicability requires a concrete `reason`.

A digest establishes identity, not truth. These records must describe work actually performed. The evaluator validates assertions against raw artifacts; a separate assessor verifies substantive review records. Invented reviewer names, generated PASS notes, or an unchecked declaration of independence are not acceptable evidence.

## Assertions on retained observations

`checks` is a nonempty list of comparisons. The left operand must reference a JSON artifact and an RFC6901-style pointer. The right operand is a literal, another JSON reference, or a hash of an artifact. Supported operations are `eq`, `ge`, `le`, and `contains`. For example:

```json
{"left":{"artifact":"run-report","pointer":"/status"},"op":"eq","right":{"value":"PASS"}}
```

```json
{"left":{"artifact":"run-report","pointer":"/kernel_sha256"},"op":"eq","right":{"sha256":"tested-kernel"}}
```

Comparisons run when evidence is finalized; a producer's PASS string alone does not replace the individual case or budget observations. Count equality is type-sensitive. Duplicate JSON keys and nonfinite values are rejected. Retain raw serial, QMP, case/cut inventories and source-bound workload files alongside summary reports.

## Execution record

An execution has `kind: "execution"`, `exit_code: 0`, `completed: true`, `truncated: false`, `environment` (`reference-linux` or `native`), `binary_kind` (`release`, `instrumented` or `host`), `substitutions` (an explicit string list), command-array `invocation`, timezone-aware `started_utc` and `completed_utc`, and artifact assertions in `checks`.

`identities` references artifacts for `toolchain`, `configuration`, `environment` and `workload`; machine executions also reference `kernel`, `firmware` and `image`. The toolchain JSON names Rust1.99.1, target `riscv64imac-unknown-none-elf`, QEMU11.1.3 and OpenSBI1.7. Retain full tool/package hashes and environment limits in these artifacts. A machine execution declares `boundaries: {"cpu":"real-qemu","syscall":"actual-ecall","storage":"real-virtio"}`; storage is required for storage cases. A memory fake cannot qualify this boundary. Required platform and corrupt-mount refusal cases stop before U-mode: only `AC-01.boot-refusals` and `AC-16.*` may instead declare `syscall: "not-reached-boot-refusal"`. Such a record must retain `boundary_observations.boot_refusal: {"artifact": "observation-id", "pointer": "/refusal"}` resolving to an object with literal `refused: true`, `user_entry: false`, and `persistent_image_unchanged: true`, supported by its actual diagnostic/launch/image checks. This is an observed image-preservation claim, not an invented count of storage requests. All other machine cases still require actual ecalls.

`bindings` links record identities to original reports. It maps `source_identity`, and for machine runs `kernel`, `firmware`, `image`, to `{ "artifact": "original-report", "pointer": "/field" }`. Those fields must equal the record's source or the actual referenced binary/image digest. The binding report must be among supporting artifacts. Do not relabel an old run as a new source; use an applicability record.

`cases` is an array with unique catalog `id`, `status: "PASS"`, concrete `inputs`, `public_result`, `authoritative_state`, `forbidden_effects`, `completion_window`, `cleanup`, `limitations`, and nonempty `checks` against retained artifacts. One execution may establish many named boundaries, but each needs its observation and mapping to the actual workload. Do not map an entire family to a single generic PASS without assessing its individual branches and effects. Host-only records cannot qualify syscall/machine cases.

Reference build execution can list `build_checks`: `locked-rust-tests`, `full-pytest`, `rustfmt`, `clippy-host`, `clippy-rv64`, `clippy-instrumented`, `release-build`, `static-elf`. Each must have the actual invocation/log/exit observation. Required normal release shell, peer-isolation and persistent-reboot journeys must also have release-binary execution evidence; instrumented runs alone cannot satisfy them.

## Mandatory budget profiles

An execution's optional `budgets` object uses the following names. Every entry identifies `report` and artifact `checks`. Measurement reports must bind the same source/kernel/firmware/image as their execution record, name the exact run/boot IDs and retain `serial_sha256`, which is checked against the raw capture. An older report without that association cannot silently acquire the claim from an unrelated serial file. Budgets qualify only on the declared reference Linux environment and must accompany their corresponding named cases in the same qualified execution record.

- `fairness4`, `fairness8`, `wakeup`, `context`, `masking`, `reclaim`: include `serial`, `run_id`, and `boot_id`. The evaluator reruns the independent benchmark parser against the complete trusted raw serial. This enforces fixed warm-up/window/peer counts,10,000 samples/cycles where specified, calibration, thresholds, ordering and loss. Configuration must identify `icount: "shift=0,align=off,sleep=off"`; masking must declare `profile: "debug"`.
- `histories`: the actual history report must contain at least100 PASS histories, each at least100 operations and20 cuts, with distinct seeds.
- `exhaustive`: actual report `profile` must be `exhaustive-small`, `workload` must be `all`, every unique recovery case must pass, and report outcome/boot totals must match an independent `inventory` artifact. That inventory supplies `expected_outcomes`, `expected_unique_boots`, nonempty `input_artifacts`, all `mutation_classes` (`create`, `write`, `append`, `truncate`, `rename`, `rename-replace`, `unlink`), all required `subspaces`, and equal positive `declared_cuts`/`completed_cuts`. Required subspaces are `submission`, `completion`, `flush`, `all-lost`, `all-persisted`, `256-per-block`, `all-combinations-at-most12`, `commit-sector-both`, `descriptor-payload-reorder`. Retain the executable independent enumeration method and its inputs; a handwritten count is not enumeration evidence.
- `recovery`: the actual report has PASS `cases`, each at least3 interruptions; the budget lists `phases` including `replay-write`, `replay-flush`, `clear-write`, `clear-flush`. Source-case/cut inventories and checks must establish that every reachable committed replay boundary was exercised.
- `largest-recovery`: actual report has64MiB `image_bytes`,16 `redo_count`, `boot_to_ready_host_seconds` at most180, and positive `block_read_bytes_before_ready`.
- `negative-controls`: a normalized report contains all nine catalog `controls`. Each identifies `name`, `status`, `baseline`, `restored` (allPASS), `outcome: "intended-assertion"`, equal nonempty `expected_assertion` and `observed_assertion`, at least3 supporting `artifacts`, and `checks` against baseline, mutant and restored raw observations. Compilation errors, unrelated faults, harness errors and timeouts cannot be relabeled as intended assertions. Normalization must retain the underlying report/source/patch/serial identities and independent mapping.

## Reviews and their verification

A `review` record names one `gate`, its catalog `obligations`, `reviewed_authors`, and an `independence_method`. The assessor must be distinct from the authors of the assessed scope. Each obligation has an `observations` entry with `obligation`, substantive `method`, concrete `finding`, `disposition: "PASS"`, supporting `artifacts` and executable artifact `checks`. An empty findings list does not dispense with the per-obligation observations.

A separate `verification` record names the reviewed record's `target` ID, has `assessment_performed: true`, a substantive `independence_method`, and artifact `checks`. Its assessor must differ from the review assessor. It documents that the cited assessment and source/evidence inspection actually occurred; it is not an assume-reviewed switch. Verification also applies to reconstruction, applicability and resolution records. Review/verification methods must explain actual scope and limits, including partial independence when appropriate.

## Reconstruction

A `reconstruction` record references the exact current `archive` and `manifest`, declares `environment: "reference-linux"`, `fresh_extraction: true`, `original_tree_unavailable: true`, and `prior_build_outputs_unavailable: true`, and supplies a substantive `independence_method`, at least3 supporting artifacts and `checks`. Its `binaries` array contains `name`, `first` and `rebuilt` artifact IDs for firmware, kernel and every delivered user program. Distinct retained files must have identical bytes. Build logs, image/package identities, extraction paths and proof of isolation accompany the record and its independent verification. An unexplained difference remains non-passing; qualify a deliberate substitution before creating a new candidate.

## Reuse, failures and repairs

An `applicability` record targets one old `execution`, references `previous_archive` and `previous_manifest`, and identifies the exact complete sorted `changed_paths` computed from old/current manifests. Both archives are validated. It lists `unaffected_cases`, exact `unchanged_inputs` (`{"path":"..."}`), a substantive `independence_method`, per-scope `impact_analysis` and `checks`. Optional `unaffected_build_checks` names already executed build checks whose applicability was separately assessed; case applicability alone cannot carry old build results. A separately verified assessment must explain why the changed code/configuration does not affect those cases. Hash equality alone cannot justify a semantic change. This route reuses only named actual cases from the old execution and cannot add coverage.

Keep failed/incomplete records. A verified `resolution` references `failed_record` and qualified `passing_record`, a concrete `repair` description, supporting artifacts and `checks`. The passing execution must cover every named failed case. Open findings and unresolved runs remain non-passing. Recording evidence outside the source keeps its candidate identity stable.

`unit-fixture` records are accepted only by the internal test API, which always returns `qualified_delivery: false` and cannot return overallPASS. The command-line evaluator never enables this mode. Synthetic fixtures test rejection/aggregation logic and are not execution evidence for this kernel.

Reference environment identities use observed fields `system: "Linux"`, `distribution: "ubuntu"`, `version_id: "24.04"`, `base_image_digest` (`sha256:...`), numeric Python patch `python: "3.12.x"`, `pytest: "8.4.2"`, `package_inventory_sha256`, and `packages` mapping the exact `gcc-13-riscv64-linux-gnu`, `binutils-riscv64-linux-gnu`, and `gdb-multiarch` revisions. The execution's `identities.packages` points to the retained tab-separated dpkg inventory; its digest and those revisions must agree, and the complete inventory must match `containers/debian-packages-arm64.lock` in the validated candidate archive. The base digest must equal the pinned Ubuntu24.04 FROM line in that archive’s `containers/Dockerfile`. Fresh collection reads os-release, platform, versions and dpkg inside the actual runner. A reference label cannot override Darwin observations. Benchmark budgets additionally require instrumented binary identity and `host.system: "Linux"` in their bound launch report.
