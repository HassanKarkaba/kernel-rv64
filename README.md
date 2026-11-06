# KERNEL-RV64

A small Rust operating system for one RISC-V hart on QEMU `virt`. It boots through OpenSBI, runs an immutable user-mode shell in an Sv39 address space, schedules isolated programs, transfers bytes through bounded pipes, and stores files on a fully journaled VirtIO block device.

The implementation includes the complete ABI, isolated processes, bounded IPC, a coalescing kernel heap, and a sector-journaled filesystem. Verification covers real QEMU journeys, invalid user memory, resource boundaries, device failures, corruption refusal, crash/replay histories and measured scheduling. Each run records its exact source/tool/binary identities. Qualification results and remaining obligations are in `implementation-report.txt`, supplied alongside the archive and external `evidence/` bundle; a passing subset is never presented as complete G-01–G-08 acceptance.

## Build environment

Pinned inputs are Rust 1.99.1 (edition 2024), QEMU 11.1.3, OpenSBI v1.7, Ubuntu 24.04, Python 3.12 and pytest 8.4.2. `toolchain.lock` records resolved sources, hashes, the native tool identities and qualification limits. Cargo has no registry dependencies. `requirements.lock` pins Python packages with hashes.

The reference reconstruction recipe copies source into an unprivileged Linux container. It uses TCG, no published ports, and no privileged devices. The recipe has been reconstructed on Linux arm64. Resolved package revisions and observed tool identities are retained in `containers/debian-packages-arm64.lock` and `containers/reference-environment.json`; runtime evidence remains external to this source archive. Fields recording initial qualification in `toolchain.lock` describe lock creation, not current test results.

```sh
docker compose build kernel-dev
docker compose run --rm kernel-dev bash
```

Inside that shell, the repository and firmware are already built. For a persistent interactive development image, omit `--rm` or bind an explicit host `var/` directory; do not put valuable images in a disposable container layer. `/evidence` is a separate named volume. No source bind mount is required for reconstruction.

Native convenience builds need the exact Rust compiler and RV64 target, QEMU, Python, the selected OpenSBI source, GNU RISC-V cross tools, and make. Set `OPENSBI_SOURCE` and `CROSS_COMPILE`; `FW_CC` and `FW_LD` permit explicit firmware tool selection. On the tested macOS host the embedded GNU linker lacked PIE support, so the recorded firmware build used GNU GCC with Rust's bundled LLD. Native and reference Linux firmware/tool binaries have distinct identities and separate runtime evidence.

```sh
./scripts/build.sh
# If an independently built and identified firmware already exists:
./scripts/build.sh --kernel-only
```

`--kernel-only` still builds the user programs, embeds the immutable `init` ELF, builds the kernel, and checks ELF protection. It does not claim firmware reconstruction. Set `CARGO_TARGET_DIR` to an explicit writable build directory if desired. Neither build mode modifies a disk image.

## Create and run

Commands resolve source-relative paths from the repository root. Paths are passed as argument arrays, with no shell interpolation inside the Python runner.

```sh
mkdir -p var
./scripts/mkfs.sh --image var/dev.img
./scripts/run.sh --image var/dev.img --firmware build/fw_dynamic.bin
```

`mkfs` creates exactly 64 MiB and imports `/demo3`, `/compute`, `/writer`, `/fault`, `/producer`, and `/consumer` from rebuilt ELFs. It refuses an existing path. The runner requires modern VirtIO MMIO, writeback with honored flushes, PLIC, one hart and 256 MiB; it records binary hashes, command, image identity, DTB and serial output. `READY` occurs only after recovery, complete metadata validation, and successful init loading. A mount failure starts the restricted `status`, `help`, `shutdown` console.

The launcher and QEMU share an inherited exclusive inode lock for the VM lifetime. QEMU opens the validated file descriptor, so replacing its pathname cannot redirect the VM. SIGTERM stops the owned guest and records an incomplete run; if the launcher is forcibly killed, the guest retains the lock until it exits. QEMU's separate file-lock mechanism is disabled to avoid conflicting lock namespaces on macOS. All supplied image tools honor the launcher lock; use these commands rather than starting an unmanaged VM against a shared image. Symlinked image paths and wrong-sized files are rejected. Images remain in place after every normal or failed run.

Try these shell commands:

```text
help
ls
ps
run /demo3
run /producer | /consumer
write /hello "persistent text"
cat /hello
mv /hello /saved
shutdown
```

Restart the same image and `cat /saved`. The `write` builtin closes a temporary file before atomic replacement by rename; it writes no automatic newline. Quoted or escaped pipes are literal arguments. `run` supports one pipeline. Ctrl-C is an ordinary input byte, not a signal. A failed second pipeline spawn leaves the first child tracked for later reaping and reports its PID.

Pipe writes up to 512 bytes are atomic; larger writes may return a positive prefix. Readers see EOF only after the last writer closes and buffered bytes drain. Writers without readers get EPIPE. Successful regular-file mutations are synchronous through journal retirement. An EIO or lost reply can have an uncertain persistent effect; restart and inspect the recovered content instead of automatically retrying an append. The filesystem is deliberately shared by all processes, with no per-file confidentiality boundary.

## Inspection and isolated verification

```sh
./scripts/fsck.sh --image var/dev.img
./scripts/image-export.sh --image var/dev.img --output var/export-new
./scripts/test.sh --suite host --output /absolute/new/host-evidence
./scripts/smoke.sh --output /absolute/new/smoke-evidence
./scripts/guest-test.sh --output /absolute/new/guest-evidence
./scripts/trace-test.sh --output /absolute/new/trace-evidence
./scripts/device-test.sh --output /absolute/new/completion-evidence
./scripts/crash-test.sh --profile selected --output /absolute/new/crash-evidence
./scripts/bench.sh --kind all --seed 1 --output /absolute/new/bench-evidence
./scripts/acceptance.sh --output /absolute/new/acceptance-evidence
```

The verification commands accept explicit `--qemu`, `--firmware`, `--kernel` or program-directory arguments where relevant; use `--help` for the exact interface. Output directories must be new and external to the source candidate. Tests create their own images and preserve failure artifacts. `fsck` is read-only and validates an authoritative journal before evaluating a replay overlay; it never repairs an input. Export validates first and creates a new directory without overwriting files.

`smoke` tests the release shell and reboot journey through actual QEMU and QMP. `guest-test` embeds a separate immutable test init and uses a declared instrumented kernel. Ordinary console output in that build is escaped as `UOUT`; only init may emit raw `KTEST` framing. The host checks case/run/boot identity, ordered phases, one terminal result, guest shutdown and the independent disk oracle. Release has no privileged test syscall.

`crash-test` uses a Unix-socket NBD sector-persistence backend, captures real guest writes/flushes and acknowledgments, materializes explicit permitted sector outcomes, and boots the kernel to recover each image. Process termination alone is not the crash model. `--profile exhaustive-small` enumerates the specified bounded subspaces; it does not prove all disk histories. A `--max-boots` cap produces INCOMPLETE when it truncates the matrix. Retained trace and case reports identify every tested cut. The full seeded-history/repeated-recovery budgets and mutation controls are distinct obligations.

`bench --kind all` measures four/eight-worker fairness, 10,000 wakeups with seven compute peers, 10,000 context transitions plus counter-read calibration, debug interrupt-mask intervals, and 10,000 ownership reclamation cycles. Guest virtual time and host elapsed time are separate. Its raw records are checked by independent host calculations.

`trace-test` records bounded enqueue/dispatch/block/wake/user-return/exit, device submission/completion, flush and journal-phase events. Its checker rejects duplicate READY ownership, unmatched wakeups/completions, lost trace records and missing durable phases. Trace controls and completion fault selectors exist only in instrumented builds and only immutable init can invoke them. `device-test` substitutes observed status/used-ring values after real requests; it explicitly does not simulate a physically malicious DMA device. `tools/driver_fault_test.py` separately injects real NBD backend errors and delays.

`acceptance` executes host/static checks and every available real-boundary family, including the full crash/history budgets. It returns nonzero while any required family fails or qualifying review/reconstruction evidence is missing. It can take tens of minutes and retains several GiB of sparse images. It never promotes a subset to complete release acceptance.

[Acceptance record format and finalization](docs/acceptance.md) defines the versioned artifact, execution, review, reconstruction and scoped applicability records. Package the source first, then bind the actual observations and independent assessments to that candidate. The finalizer validates all eight gates without rerunning unchanged, identity-matched expensive campaigns:

```sh
./scripts/acceptance.sh --catalog --output /absolute/new/coverage-catalog
./scripts/acceptance.sh --finalize /absolute/bundle/qualification.json --output /absolute/new/final-gates
# Execute available families and then evaluate the same evidence format:
./scripts/acceptance.sh --evidence-index /absolute/bundle/qualification.json --output /absolute/new/full-run
```

A missing or stale record, skipped case, incomplete budget, wrong negative-control outcome, unresolved finding, or unverified review cannot produce a passing delivery. Synthetic evaluator fixtures always remain test-only. `--suite host` keeps its narrow host-check meaning.

Focused completion regressions are `tools/readonly_test.py`, `tools/abi_matrix_test.py`, `tools/interleave_test.py`, `tools/observation_test.py`, `tools/uart_test.py`, `tools/storage_capacity_test.py`, `tools/corruption_matrix_test.py`, `tools/shutdown_test.py` and `tools/host_isolation_test.py`. Read-only tests reach sequence exhaustion with valid fixtures and reproduce the original open-admission defect in an isolated source copy. Trusted record emission has a total guest-time deadline and sticky failure; parsers reject unterminated or duplicate-key records. Controlled interleaving hooks are instrumented-only and keep protected registration windows closed. The UART and trace overflow tests inspect their exact loss counters. Shutdown cases hold real requests across admission closure, observe a waiting caller recheck the flag, drain an active transaction, and identify the global watchdog deadline separately from host elapsed time.

Additional reproducible families are `tools/platform_test.py`, `tools/loader_test.py`, `tools/supervisor_fault_test.py`, `tools/capacity_test.py`, `tools/corruption_test.py`, `tools/history_test.py`, `tools/recovery_test.py`, `tools/largest_recovery_test.py`, `tools/kernel_mutations.py` and `tools/journal_guest_mutations.py`. Use each command's `--help` for its retained-input requirements. Mutation tools copy source into isolated evidence directories, modify only those copies, require the expected assertion to fail, and rerun the unmodified candidate.

Debug only an explicitly separate image:

```sh
./scripts/mkfs.sh --image var/debug.img
./scripts/debug.sh --image var/debug.img --firmware build/fw_dynamic.bin
```

The runner starts paused and records a local Unix GDB socket. Use a RISC-V-capable GDB and the kernel ELF's symbols. Kernel panics and supervisor faults are fatal; user faults terminate only the offending process. Synchronous supervisor faults switch to the boot/emergency stack before touching a potentially invalid process stack. Only instrumented builds emit the extra fault-PC/CSR diagnostic.

Destructive reset is a separate, explicit command and is never called by build/tests:

```sh
./scripts/reset.sh --image var/dev.img --destroy-existing
```

## Source map and maintenance

| Responsibility | Source |
| --- | --- |
| Entry, SBI, CSR boundaries, traps and context switch | `kernel/src/arch/` |
| Sv39 mappings, frame ownership, copy validation and guarded stacks | `kernel/src/memory/` |
| Process execution, round-robin scheduling, sleep, exit and reaping | `kernel/src/process.rs` |
| ABI dispatch, descriptor/open-description ownership, FS serialization | `kernel/src/syscall.rs` |
| UART rings, PLIC and modern VirtIO split queue | `kernel/src/drivers/` |
| Bounded diagnostics, event traces and measurement hooks | `kernel/src/diagnostics.rs`, `kernel/src/trace.rs`, `kernel/src/metrics.rs`, `kernel/src/interleave.rs` |
| Fallible first-fit/coalescing arena with owned allocation lifetimes | `crates/heap/` |
| Numeric syscall assignments and byte-encoded records | `crates/abi/` |
| Reusable ELF, extent, process, FIFO, pipe and shell algorithms | `crates/core-model/` |
| Bounded DTB decoding and device completion validation | `crates/platform/` |
| Disk codecs, CRC32C, metadata scan and redo protocol | `crates/disk-format/` |
| Flat namespace, bounded file operations and mount state | `crates/filesystem/` |
| no_std user ABI wrappers, init, demos and hostile checks | `user/runtime/`, `user/programs/` |
| Independent Python oracle, image tools and NBD model | `tools/`, `tests/` |

The filesystem mutex is acquired before open-description state. The loader snapshot mutex is acquired before the filesystem mutex; no path acquires them in reverse. Scheduler and pipe critical sections never acquire a sleepable lock. Device interrupts only acknowledge hardware; the scheduler rechecks completion and wake predicates. Syscalls retain their private stack/scratch while blocked. No Rust borrow into a shared owner may survive a scheduling point unless an explicit sleepable owner keeps it exclusive.

When reviewing unsafe code, verify physical range provenance, alignment, aliasing, lifetimes, interrupt discipline, translation fences, direct-map executable aliases, and DMA ownership through validated completion or confirmed reset. Inspect rejection paths before checking success. Tests for invalid output buffers must observe that pipe bytes, zombies, offsets and descriptor slots remain unchanged.

Add a syscall only at a reserved number and update the runtime and independent boundary tests. Existing numbers/layouts and resource limits require a deliberate ABI version change. Disk format changes require a new format version and an offline conversion contract; mount never guesses an upgrade. Tool updates require new hashes, reconstruction, and affected boundary tests. Regenerate synthetic images from source rather than committing generated disks. Reproduce one crash case from its recorded source/binary identity, seed, cut, persistence choice and original image; do not reuse a failure result for a changed binary.

The code archive excludes build products, disk images, caches and evidence. The input specifications and detailed requirement/evidence report are external to this repository.

## Exact source archive

Create a deterministic source-only ZIP and its file/hash/mode manifest outside the repository:

```sh
python3 tools/package.py --archive /absolute/new/kernel-rv64.zip --manifest /absolute/new/kernel-rv64.manifest.json
python3 tools/package.py --archive /absolute/new/kernel-rv64.zip --manifest /absolute/new/kernel-rv64.manifest.json --extract /absolute/new/reconstruction
```

Extraction verifies archive/member digests, path safety, regular-file types, modes, sizes, duplicate entries and the reconstructed source identity before any build. Both output paths must be new. Rebuild in the extracted tree using the same pinned toolchain and `scripts/build.sh`; its path remapping permits comparison across independent directories. Keep the manifest with the externally reviewed archive hash. Downloaded tool sources/binaries and test evidence remain outside the source ZIP. See `NOTICE` for external dependency licensing.
