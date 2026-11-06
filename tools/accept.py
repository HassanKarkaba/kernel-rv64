#!/usr/bin/env python3
"""Run available checks and preserve a fail-closed external release-gate report."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from doctor import inspect

GATES = {
    "G-01": "Build, formatting, clippy, static ELF checks and exact dependency identity",
    "G-02": "Real QEMU boot, shell journeys and readiness failures",
    "G-03": "Complete ABI, hostile processes, isolation and ownership reclamation",
    "G-04": "Scheduling, IPC interleavings and mandatory raw measurements",
    "G-05": "Real VirtIO durability, crash histories, replay and independent oracle",
    "G-06": "Corruption, device reset failures and negative controls",
    "G-07": "Independent exact-candidate reconstruction",
    "G-08": "Exact archive review and complete requirement accounting",
}


def source_identity(root):
    """Hash canonical file names and bytes, excluding generated and local state."""
    ignore = {".git", "target", "build", "var", ".venv", "__pycache__", ".pytest_cache", ".DS_Store", "__MACOSX"}
    h = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(p in ignore for p in relative.parts) or not path.is_file():
            continue
        if path.is_symlink():
            raise ValueError(f"source symlink is unsupported: {relative}")
        name = relative.as_posix().encode()
        data = path.read_bytes()
        h.update(len(name).to_bytes(8, "big") + name + len(data).to_bytes(8, "big") + data)
    return h.hexdigest()


def execute(label, command, root, output, environment, timeout=600):
    started = time.monotonic()
    result = {"check": label, "command": command, "status": "INCOMPLETE"}
    with (output / (label + ".log")).open("xb") as log:
        try:
            p = subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT,
                               env=environment, timeout=timeout)
            result.update(status="PASS" if p.returncode == 0 else "FAIL", exit_code=p.returncode)
        except (OSError, subprocess.TimeoutExpired) as error:
            log.write(str(error).encode())
            result["reason"] = str(error)
    result["elapsed_host_seconds"] = time.monotonic() - started
    print(label + ": " + result["status"], flush=True)
    return result



def combined_status(unchanged, checks, qualification):
    """An earlier qualified report never overrides a fresh failed/incomplete run."""
    if not unchanged or any(c.get("status") == "FAIL" for c in checks):
        return "FAIL"
    if not checks or any(c.get("status") != "PASS" for c in checks):
        return "INCOMPLETE"
    return qualification["status"]

def main():
    p = argparse.ArgumentParser(description=__doc__, epilog="Exit 0 only for all checks in --suite host, or all eight release gates in --suite all.")
    p.add_argument("--output", required=True, type=Path, help="New directory outside the candidate tree")
    p.add_argument("--suite", choices=["host", "all"], default="all")
    p.add_argument("--qemu", default="qemu-system-riscv64")
    p.add_argument("--firmware", type=Path, default=Path("build/fw_dynamic.bin"))
    p.add_argument("--timeout", type=int, default=14400, help="Per real-boundary family watchdog, seconds")
    p.add_argument("--evidence-index", type=Path, help="Versioned external qualification index, evaluated after --suite all")
    p.add_argument("--finalize", type=Path, help="Evaluate identity-matched evidence without rerunning campaigns")
    p.add_argument("--catalog", action="store_true", help="Write the mandatory named-case/review inventory; does not run or qualify tests")
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if output.is_relative_to(root):
        p.error("evidence must be outside the candidate tree")
    if sum((bool(args.finalize), args.catalog, bool(args.evidence_index))) > 1:
        p.error("--finalize, --catalog and --evidence-index are mutually exclusive")
    if args.suite == "host" and (args.finalize or args.evidence_index):
        p.error("host-only checks cannot finalize release acceptance")
    if args.finalize or args.catalog:
        try:
            output.mkdir(parents=True, exist_ok=False)
            if args.catalog:
                from qualification_policy import catalog
                result = {"schema": 1, "status": "NOT RUN", "scope": "Mandatory obligation inventory only", "catalog": catalog()}
            else:
                from qualification import evaluate
                result = evaluate(args.finalize, root)
            with (output / "index.json").open("x") as stream:
                json.dump(result, stream, indent=2)
                stream.write("\n")
            print(f"Evidence: {output / 'index.json'}")
            return 0 if args.catalog or result["status"] == "PASS" else 2
        except (OSError, ValueError, KeyError) as error:
            p.exit(2, f"accept: {error}\n")
    report = None
    created = False
    try:
        output.mkdir(parents=True, exist_ok=False)
        created = True
        baseline = source_identity(root)
        env = os.environ.copy()
        env.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONDONTWRITEBYTECODE="1")
        env.setdefault("CARGO_HOME", str(output / "cargo-home"))
        env["CARGO_TARGET_DIR"] = str(output / "target")
        report = {"schema": 1, "created_utc": datetime.now(timezone.utc).isoformat(),
                  "source_identity": baseline, "identity_scope": "sorted relative names and bytes, length framed; excludes generated directories and local cache metadata",
                  "tools": inspect(args.qemu), "suite": args.suite, "checks": [],
                  "gates": {key: {"status": "NOT RUN", "obligation": value} for key, value in GATES.items()}}
        checks = [("host-rust", ["cargo", "test", "--locked"]),
                  ("host-python", [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"])]
        for label, command in checks:
            report["checks"].append(execute(label, command, root, output, env))
        if args.suite == "all":
            firmware = args.firmware.resolve(strict=True)
            target = output / "target/riscv64imac-unknown-none-elf/release"
            build_checks = [
                ("format", ["cargo", "fmt", "--all", "--check"]),
                ("clippy-host", ["cargo", "clippy", "--locked", "--all-targets", "--", "-D", "warnings"]),
                ("build-release", ["bash", "scripts/build.sh", "--kernel-only"]),
            ]
            for label, command in build_checks:
                report["checks"].append(execute(label, command, root, output, env))
            env["KERNEL_INIT_ELF"] = str(target / "init")
            report["checks"].append(execute("clippy-rv64", ["cargo", "clippy", "--locked", "--release", "-p", "kernel", "-p", "user-programs", "--target", "riscv64imac-unknown-none-elf", "--", "-D", "warnings"], root, output, env))
            common = ["--qemu", args.qemu, "--firmware", str(firmware)]
            release = common + ["--kernel", str(target / "kernel")]
            families = [
                ("smoke", "smoke.py", release + ["--program-dir", str(target)]),
                ("platform-refusal", "platform_test.py", release),
                ("guest", "guest_test.py", common),
                ("loader", "loader_test.py", common),
                ("supervisor-faults", "supervisor_fault_test.py", common),
                ("boundary-trace", "trace_test.py", common),
                ("measurements", "bench.py", common + ["--kind", "all"]),
                ("crash", "crash_test.py", release + ["--profile", "exhaustive-small", "--workload", "all", "--program-dir", str(target)]),
                ("recovery", "recovery_test.py", release + ["--source-run", str(output / "crash")]),
                ("histories", "history_test.py", release + ["--fswork", str(target / "fswork")]),
                ("largest-recovery", "largest_recovery_test.py", release),
                ("backend-faults", "driver_fault_test.py", release + ["--program", str(target / "fsfailure")]),
                ("completion-faults", "device_test.py", common),
                ("corruption", "corruption_test.py", release + ["--source-run", str(output / "crash")]),
                ("journal-controls", "journal_mutations.py", []),
                ("journal-guest-controls", "journal_guest_mutations.py", common + ["--init", str(target / "init"), "--fswork", str(target / "fswork")]),
            ]
            if (root / "tools/kernel_mutations.py").is_file():
                families.append(("kernel-controls", "kernel_mutations.py", common))
            if (root / "tools/capacity_test.py").is_file():
                families.append(("capacity", "capacity_test.py", common))
            if (root / "tools/interleave_test.py").is_file():
                families.append(("interleavings", "interleave_test.py", common))
            if (root / "tools/readonly_test.py").is_file():
                families.append(("readonly-boundary", "readonly_test.py", common))
            if (root / "tools/abi_matrix_test.py").is_file():
                families.append(("abi-matrix", "abi_matrix_test.py", common))
            if (root / "tools/storage_capacity_test.py").is_file():
                families.append(("storage-capacity", "storage_capacity_test.py", common))
            if (root / "tools/host_isolation_test.py").is_file():
                families.append(("host-isolation", "host_isolation_test.py", release))
            if (root / "tools/corruption_matrix_test.py").is_file():
                families.append(("corruption-matrix", "corruption_matrix_test.py", release))
            if (root / "tools/shutdown_test.py").is_file():
                families.append(("shutdown-drain", "shutdown_test.py", common))
            if (root / "tools/observation_test.py").is_file():
                families.append(("timer-trace-observations", "observation_test.py", common))
            if (root / "tools/uart_test.py").is_file():
                families.append(("uart-transport", "uart_test.py", common))
            for label, script, options in families:
                command = [sys.executable, "tools/" + script, "--output", str(output / label)] + options
                report["checks"].append(execute(label, command, root, output, env, args.timeout))
        unchanged = source_identity(root) == baseline
        report["source_unchanged"] = unchanged
        passed = unchanged and all(c["status"] == "PASS" for c in report["checks"])
        if args.suite == "all":
            by_name = {check["check"]: check["status"] for check in report["checks"]}
            gate_checks = {
                "G-01": ["host-rust", "host-python", "format", "clippy-host", "build-release", "clippy-rv64"],
                "G-02": ["smoke", "platform-refusal", "corruption"],
                "G-03": ["guest", "loader", "capacity", "measurements", "kernel-controls", "supervisor-faults"],
                "G-04": ["measurements", "guest", "boundary-trace", "kernel-controls"],
                "G-05": ["crash", "recovery", "histories", "largest-recovery"],
                "G-06": ["corruption", "backend-faults", "completion-faults", "journal-controls", "journal-guest-controls", "kernel-controls"],
            }
            # Family PASS is narrower than a full specification gate. Preserve
            # explicit review obligations instead of inferring missing evidence.
            remaining = {
                "G-01": "Reference Linux toolchain/package identity and independent ELF/unsafe review must accompany these checks.",
                "G-02": "Review invalid platform/device boot matrix against AC-01; disk-corruption refusals are covered here.",
                "G-03": "Review complete resource-limit and hostile ABI matrix; bounded guest checks are explicitly scoped.",
                "G-04": "Review forced pipe/wait/I/O interleavings and trace loss against AC-11/19.",
                "G-05": "Review each mutation-class cut inventory and independent oracle against section 7C.",
                "G-06": "Review source-mutant counterexamples and distinguish observed-completion substitutions from actual DMA behavior.",
            }
            for gate, names in gate_checks.items():
                statuses = [by_name.get(name, "NOT RUN") for name in names]
                report["gates"][gate].update(status="FAIL" if "FAIL" in statuses else "INCOMPLETE", checks=names, remaining=remaining[gate])
            report["gates"]["G-07"]["remaining"] = "Independently extract the exact candidate archive and rerun reconstruction/guest checks; bind the archive and source hashes."
            report["gates"]["G-08"]["remaining"] = "Independent archive exclusions, complete requirement ledger and handoff review are external to this runner."
            report["status"] = "FAIL" if not unchanged or any(c["status"] == "FAIL" for c in report["checks"]) else "INCOMPLETE"
            report["reason"] = "Executed available families. Finalization requires versioned execution, review and exact reconstruction records; use --evidence-index or --finalize."
            if args.evidence_index:
                from qualification import evaluate
                qualification = evaluate(args.evidence_index, root)
                report["qualification"] = qualification
                report["gates"] = qualification["gates"]
                report["status"] = combined_status(unchanged, report["checks"], qualification)
                report["reason"] = "All eight gates are evaluated from checked external records; fresh failed or incomplete checks cannot be overridden by older evidence."
        else:
            report["status"] = "PASS" if passed else "FAIL"
            report["scope"] = "Host algorithm and tooling checks only; no guest or release acceptance claim"
        with (output / "index.json").open("x") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        print(f"Evidence: {output / 'index.json'}")
        return 0 if report["status"] == "PASS" else 2
    except (OSError, ValueError) as error:
        if created:
            if report is None:
                report = {"schema": 1, "checks": [], "suite": args.suite}
            report.update(status="INCOMPLETE", reason=str(error))
            index = output / "index.json"
            if not index.exists():
                with index.open("x") as stream:
                    json.dump(report, stream, indent=2)
                    stream.write("\n")
        p.exit(2, f"accept: {error}\n")


if __name__ == "__main__":
    sys.exit(main())
