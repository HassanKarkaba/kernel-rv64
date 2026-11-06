#!/usr/bin/env python3
"""Detect four real regressions in isolated, compiled QEMU kernel candidates.

The accepted implementation is never edited. Baseline and restored candidates
must pass the same immutable supervisor. Detection requires exactly the expected
failed assertion and clean guest shutdown. Build failure and timeout never pass.
"""
import argparse
import difflib
import json
import os
from pathlib import Path
import shutil
import sys
import uuid
import fsck
import mkfs
from accept import source_identity
from doctor import probe, sha256
from guest_test import build
from protocol import trusted_records
from smoke import Guest

NAMES = ["copyout-before-consume", "writable-executable", "translation-invalidation", "waiter-registration"]
IGNORE = shutil.ignore_patterns(".git", "target", "build", "var", ".venv", "__pycache__", ".pytest_cache")


def once(text, before, after):
    if text.count(before) != 1:
        raise ValueError("mutation anchor is not unique in the current source")
    return text.replace(before, after, 1)


def remove_function_fences(text, name, expected):
    start = text.index("fn " + name + "(")
    opening = text.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    body = text[start:end]
    if body.count("arch::translation_fence();") != expected:
        raise ValueError("unexpected translation-fence topology in " + name)
    return text[:start] + body.replace("arch::translation_fence();", "/* Deliberate isolated mutation: no invalidation before reuse. */") + text[end:]


def mutate(candidate, name):
    path = candidate / ("kernel/src/syscall.rs" if name in (NAMES[0], NAMES[3]) else "kernel/src/memory/mod.rs")
    old = path.read_text()
    if name == NAMES[0]:
        new = once(old, "    memory::validate(root, pointer, length, !write)?;", "    // Deliberate isolated mutation: consume before discovering copyout failure.")
    elif name == NAMES[1]:
        new = once(old, "| if writable { W | D } else { 0 };", "| if writable || executable { W | D } else { 0 };")
    elif name == NAMES[2]:
        new = old
        for function, count in [("unmap", 1), ("release_frame", 1), ("prune", 2)]:
            new = remove_function_fences(new, function, count)
    elif name == NAMES[3]:
        new = once(old, "                process::block(reason);\n                arch::restore(on);", "                // Deliberately admit the producer between the failed predicate\n                // and publishing BLOCKED, exposing the lost-wakeup window.\n                arch::restore(on);\n                process::yield_now();\n                let on = arch::disable();\n                process::block(reason);\n                arch::restore(on);")
    else:
        raise ValueError(name)
    path.write_text(new)
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), fromfile=str(path.relative_to(candidate)), tofile=str(path.relative_to(candidate))))


def analyze(serial, run_id, boot_id, expected_failure):
    records = trusted_records(serial)
    if len(records) != 6:
        raise ValueError("supervisor must emit all six trusted records")
    for sequence, record in enumerate(records, 1):
        expected = dict(schema=1, run_id=run_id, boot_id=boot_id, case_id="kernel-mutations", sequence=sequence)
        if any(record.get(k) != v for k, v in expected.items()):
            raise ValueError("trusted identity or sequence mismatch")
    if records[0].get("event") != "start" or records[-1].get("event") != "result":
        raise ValueError("invalid start or terminal phase")
    failed = []
    for name, record in zip(NAMES, records[1:-1]):
        if record.get("event") != "assertion" or record.get("assertion") != name or record.get("result") not in ("PASS", "FAIL") or record.get("error") != 0:
            raise ValueError("missing, reordered or infrastructure-failed assertion")
        if record["result"] == "FAIL":
            failed.append(name)
    expected = [] if expected_failure is None else [expected_failure]
    if failed != expected:
        raise ValueError(f"expected failed assertions {expected}, observed {failed}")
    if records[-1].get("result") != ("FAIL" if expected_failure else "PASS"):
        raise ValueError("terminal status disagrees with assertions")
    return records


def run_candidate(args, candidate, output, name, expected_failure):
    output.mkdir()
    run_id, boot_id = uuid.uuid4().hex, uuid.uuid4().hex
    report = dict(candidate=name, status="INCOMPLETE", run_id=run_id, boot_id=boot_id,
                  expected_failed_assertion=expected_failure, source_identity=source_identity(candidate))
    guest = None
    try:
        env = os.environ.copy()
        env.update(KERNEL_TEST_RUN_ID=run_id, KERNEL_TEST_BOOT_ID=boot_id, SOURCE_DATE_EPOCH="1793923200",
                   CARGO_HOME=str(output / "cargo-home"), CARGO_TARGET_DIR=str(output / "user-target"))
        user_command = [args.cargo, "build", "--locked", "--release", "-p", "user-programs", "--target", "riscv64imac-unknown-none-elf"]
        build("build-user", user_command, candidate, output, env)
        programs = output / "user-target/riscv64imac-unknown-none-elf/release"
        env.update(CARGO_TARGET_DIR=str(output / "kernel-target"), KERNEL_INIT_ELF=str(programs / "mutation-init"))
        kernel_command = [args.cargo, "build", "--locked", "--release", "-p", "kernel", "--features", "instrumented", "--target", "riscv64imac-unknown-none-elf"]
        build("build-kernel", kernel_command, candidate, output, env)
        kernel = output / "kernel-target/riscv64imac-unknown-none-elf/release/kernel"
        names = ["fault-probe", "race-reader", "race-writer"]
        report["build"] = dict(commands=[user_command, kernel_command], kernel_sha256=sha256(kernel),
                               init_sha256=sha256(programs / "mutation-init"), firmware_sha256=sha256(args.firmware),
                               fixtures={fixture: sha256(programs / fixture) for fixture in names})
        image = output / "candidate.img"
        mkfs.create(image, uuid.UUID(run_id).bytes, [("/" + fixture, programs / fixture) for fixture in names])
        before = sha256(image)
        guest = Guest(args.qemu, kernel, args.firmware, image, output / "boot", start_paused=True, icount=True)
        guest.expect(rb"(?:^|\n)READY\r?\n")
        guest.wait_for_shutdown(60)
        report["records"] = analyze(bytes(guest.data), run_id, boot_id, expected_failure)
        guest = None
        checked = fsck.inspect(image)
        if checked["needs_replay"] or sha256(image) != before:
            raise ValueError("negative-control read-only fixture changed persistent storage")
        (output / "fsck.json").write_text(json.dumps(checked, indent=2) + "\n")
        if source_identity(candidate) != report["source_identity"]:
            raise ValueError("isolated candidate changed during execution")
        report.update(status="PASS", compiled_mutation_detected=expected_failure is not None,
                      actual_failed_assertion=expected_failure, clean_guest_shutdown=True)
    except Exception as error:
        report.update(status="FAIL", reason=str(error))
    finally:
        if guest:
            guest.close()
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(name + ": " + report["status"] + (": " + report["reason"] if "reason" in report else ""), flush=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--qemu", default="qemu-system-riscv64")
    parser.add_argument("--firmware", type=Path, default=Path("build/fw_dynamic.bin"))
    parser.add_argument("--cargo", default="cargo")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if output.is_relative_to(root):
        parser.error("mutated sources and evidence must be outside the accepted source tree")
    output.mkdir(parents=True, exist_ok=False)
    report = dict(schema=1, status="INCOMPLETE", scope="Compiled isolated kernel mutations under real QEMU RV64 execution",
                  limitations=["Deliberately widened waiter gap proves the registration oracle; it is not a probability estimate for unforced races.",
                               "TLB negative control exercises stale user translation after free; hardware-specific TLB replacement policies are outside the emulated target."], results=[])
    try:
        report["accepted_source_before"] = source_identity(root)
        qemu = probe("qemu-system-riscv64", args.qemu)
        report["qemu"] = qemu
        if qemu["status"] != "MATCH":
            raise ValueError("QEMU 11.1.3 required")
        args.qemu = qemu["path"]
        args.firmware = args.firmware.resolve(strict=True)
        snapshot = output / "snapshot"
        shutil.copytree(root, snapshot, ignore=IGNORE)
        report["snapshot_identity"] = source_identity(snapshot)
        for name in ["baseline", *NAMES, "restored"]:
            candidate = output / (name + "-source")
            shutil.copytree(snapshot, candidate, ignore=IGNORE)
            if name in NAMES:
                (output / (name + ".patch")).write_text(mutate(candidate, name))
            result = run_candidate(args, candidate, output / name, name, name if name in NAMES else None)
            report["results"].append(result)
            if name == "baseline" and result["status"] != "PASS":
                raise RuntimeError("unmodified baseline did not pass; mutations not attempted")
        report["accepted_source_after"] = source_identity(root)
        report["accepted_source_unchanged"] = report["accepted_source_after"] == report["accepted_source_before"]
        report["status"] = "PASS" if all(r["status"] == "PASS" for r in report["results"]) else "FAIL"
    except Exception as error:
        report.update(status="FAIL", reason=str(error))
    (output / "mutation-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "report": str(output / "mutation-report.json")}), flush=True)
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
