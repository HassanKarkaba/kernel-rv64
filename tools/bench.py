#!/usr/bin/env python3
"""Measure scheduler fairness, wakeup, switching, masking and reclamation.

Each fixed guest workload is verified independently from its raw trusted records.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import statistics
import sys
import time
import uuid
import fsck
import mkfs
from accept import source_identity
from check_elf import check as check_elf
from doctor import probe, sha256
from guest_test import build
from protocol import trusted_records
from smoke import Guest


def analyze(serial, count, run_id, boot_id):
    records = trusted_records(serial)
    if len(records) < count + 4:
        raise ValueError("missing fairness records")
    for seq, record in enumerate(records, 1):
        expected = dict(schema=1, run_id=run_id, boot_id=boot_id, case_id=f"fairness-{count}", sequence=seq)
        if any(record.get(k) != v for k, v in expected.items()):
            raise ValueError("fairness identity/sequence mismatch")
    if records[0].get("event") != "start" or records[0].get("warmup_ms") != 1000 or records[0].get("sample_ms") != 10000:
        raise ValueError("wrong measurement profile")
    if records[-1].get("event") != "result" or records[-1].get("result") != "PASS":
        raise ValueError("guest reported an unsuccessful benchmark")
    if [r.get("event") for r in records[1:2 + count]] != ["window"] + ["worker"] * count:
        raise ValueError("invalid metadata phase")
    window = records[1]
    start, stop, frequency = (window[k] for k in ("start_ticks", "end_ticks", "frequency"))
    if any(type(x) is not int for x in (start, stop, frequency)) or frequency <= 0 or stop - start != 10 * frequency:
        raise ValueError("measurement window is not exactly ten guest seconds")
    workers = records[2:2 + count]
    pids = [w["pid"] for w in workers]
    if len(set(pids)) != count:
        raise ValueError("duplicate worker identities")
    trace = records[2 + count:-1]
    if not trace or any(r.get("event") != "dispatch" for r in trace):
        raise ValueError("unexpected phase or missing raw dispatch trace")
    by_pid = {pid: [] for pid in pids}
    intervals = {pid: 0 for pid in pids}
    previous = start - 1
    for ordinal, record in enumerate(trace, 1):
        pid, tick = record["pid"], record["ticks"]
        if record["ordinal"] != ordinal or pid not in by_pid or type(tick) is not int or not start <= tick < stop or tick < previous:
            raise ValueError("invalid raw dispatch identity, ordering or timestamp")
        by_pid[pid].append(ordinal)
        previous = tick
        end = trace[ordinal]["ticks"] if ordinal < len(trace) else stop
        intervals[pid] += end - tick
    total = sum(w["user_ticks"] for w in workers)
    if total <= 0 or total > stop - start or window["user_ticks"] != total:
        raise ValueError("invalid accounted user CPU total")
    low, high = (20, 30) if count == 4 else (10, 15)
    summaries = []
    interval_total = sum(intervals.values())
    for worker in workers:
        pid, ticks = worker["pid"], worker["user_ticks"]
        ordinals = by_pid[pid]
        if not ordinals:
            raise ValueError("worker never ran")
        gap = max((b - a - 1 for a, b in zip(ordinals, ordinals[1:])), default=0)
        if len(ordinals) != worker["dispatches"] or ordinals[0] != worker["first_ordinal"] or ordinals[-1] != worker["last_ordinal"] or gap != worker["max_peer_gap"]:
            raise ValueError("worker summary disagrees with independent dispatch trace")
        if max(gap, ordinals[0] - 1, len(trace) - ordinals[-1]) > count - 1:
            raise ValueError("round-robin peer gap threshold failed")
        if type(ticks) is not int or not low * total <= ticks * 100 <= high * total:
            raise ValueError("accounted CPU share threshold failed")
        if not low * interval_total <= intervals[pid] * 100 <= high * interval_total:
            raise ValueError("independent dispatch interval share threshold failed")
        summaries.append(dict(pid=pid, user_ticks=ticks, share_percent=100 * ticks / total,
                              raw_interval_share_percent=100 * intervals[pid] / interval_total,
                              dispatches=len(ordinals), max_peer_gap=gap))
    return {"status": "PASS", "window": window, "dispatch_count": len(trace), "workers": summaries,
            "raw_interval_limit": "Intervals between dispatch timestamps include scheduler overhead; user ticks exclude it"}, records


def quantiles(values):
    values = sorted(values)
    if not values:
        raise ValueError("empty sample set")
    return {"samples": len(values), "median": statistics.median(values),
            "p95": values[(95 * len(values) + 99) // 100 - 1],
            "p99": values[(99 * len(values) + 99) // 100 - 1], "maximum": values[-1],
            "percentile_method": "nearest rank"}


def analyze_extended(serial, kind, run_id, boot_id):
    records = trusted_records(serial)
    if len(records) < 3:
        raise ValueError("missing measurement records")
    for sequence, record in enumerate(records, 1):
        expected = dict(schema=1, run_id=run_id, boot_id=boot_id, case_id=kind, sequence=sequence)
        if any(record.get(k) != v for k, v in expected.items()):
            raise ValueError("measurement identity/sequence mismatch")
    if records[0].get("event") != "start" or records[0].get("kind") != kind:
        raise ValueError("wrong measurement start")
    if records[-1].get("event") != "result" or records[-1].get("result") != "PASS":
        raise ValueError("guest reported unsuccessful measurement")
    body = records[1:-1]
    result = {"status": "PASS", "kind": kind}
    if kind in ("wakeup", "context"):
        config, samples = body[0], body[1:]
        frequency = config.get("frequency")
        if config.get("event") != "configuration" or type(frequency) is not int or frequency <= 0 or config.get("required_samples") != 10000 or len(samples) != 10000:
            raise ValueError("wrong measurement configuration or sample budget")
        result["frequency"] = frequency
        for index, sample in enumerate(samples, 1):
            if sample.get("event") != ("wake-sample" if kind == "wakeup" else "context-sample") or sample.get("sample") != index:
                raise ValueError("sample order, count or phase mismatch")
        if kind == "wakeup":
            if config.get("peers") != 7 or config.get("sleep_ms") != 10:
                raise ValueError("wrong wake workload")
            latency, from_deadline = [], []
            previous_deadline = -1
            for s in samples:
                deadline, wake, user = (s[k] for k in ("deadline_ticks", "wake_ticks", "user_ticks"))
                if any(type(x) is not int for x in (deadline, wake, user)) or not previous_deadline < deadline <= wake <= user:
                    raise ValueError("invalid wake timestamps")
                if s["wake_latency_ticks"] != user - wake or s["deadline_latency_ticks"] != user - deadline:
                    raise ValueError("reported latency disagrees with raw timestamps")
                previous_deadline = deadline
                latency.append(user - wake)
                from_deadline.append(user - deadline)
            summary = quantiles(latency)
            if summary["p99"] * 1000 > frequency * 45 or summary["maximum"] * 1000 > frequency * 100:
                raise ValueError("wake latency acceptance threshold failed")
            result.update(wake_latency_ticks=summary, deadline_latency_ticks=quantiles(from_deadline),
                          wake_p99_ms=summary["p99"] * 1000 / frequency,
                          wake_max_ms=summary["maximum"] * 1000 / frequency)
        else:
            if config.get("calibration") != "consecutive-counter-reads" or config.get("scope") != "process-to-scheduler-to-process":
                raise ValueError("missing context measurement calibration/scope")
            if any(type(s[k]) is not int or s[k] < 0 for s in samples for k in ("ticks", "calibration_ticks")):
                raise ValueError("invalid context counter interval")
            result.update(raw_ticks=quantiles([s["ticks"] for s in samples]),
                          calibration_ticks=quantiles([s["calibration_ticks"] for s in samples]),
                          scope=config["scope"], limit="Emulated counter interval; no hardware latency comparison")
    elif kind == "masking":
        if len(body) != 8 or body[0].get("event") != "masking":
            raise ValueError("invalid interrupt-mask measurement framing")
        measured, buckets = body[0], body[1:]
        frequency, maximum, intervals = (measured[k] for k in ("frequency", "maximum_ticks", "intervals"))
        if any(type(x) is not int for x in (frequency, maximum, intervals)) or frequency <= 0 or maximum < 0 or intervals <= 0:
            raise ValueError("invalid interrupt-mask counts")
        if maximum * 1000 > frequency:
            raise ValueError("debug interrupt-mask interval exceeded one millisecond")
        if not measured.get("location") or measured.get("line", 0) <= 0 or measured["end_ticks"] <= measured["start_ticks"]:
            raise ValueError("missing mask location or measurement window")
        if any(b.get("event") != "mask-bucket" or b.get("bucket") != i or type(b.get("count")) is not int or b["count"] < 0 for i, b in enumerate(buckets)):
            raise ValueError("invalid mask histogram")
        if sum(b["count"] for b in buckets) != intervals:
            raise ValueError("histogram count does not equal observed intervals")
        result.update(measured=measured, maximum_ms=maximum * 1000 / frequency,
                      buckets=buckets, bucket_upper_ns=[1000, 10000, 100000, 1000000, 10000000, 100000000, None], profile="debug")
    elif kind == "reclaim":
        if [r.get("event") for r in body] != ["baseline"] * 12 + ["progress"] * 10 + ["final"] * 12:
            raise ValueError("invalid reclamation phase sequence")
        baseline, progress, final = body[:12], body[12:22], body[22:]
        for i in range(12):
            if baseline[i].get("owner") != i or final[i].get("owner") != i or type(baseline[i].get("count")) is not int or baseline[i]["count"] < 0 or baseline[i]["count"] != final[i].get("count"):
                raise ValueError("ownership census differs from baseline")
        if [r.get("completed_cycles") for r in progress] != list(range(1000, 10001, 1000)):
            raise ValueError("missing reclamation cycles")
        names = ["user_frames", "page_tables", "heap_free_bytes", "published_processes", "descriptors", "extents", "charged_user_pages", "open_descriptions", "file_refs", "pipe_slots", "pipe_readers", "pipe_writers"]
        result.update(completed_cycles=10000, owner_counts={name: baseline[i]["count"] for i, name in enumerate(names)})
    else:
        raise ValueError("unsupported measurement family")
    return result, records


def one_case(args, root, output, count, kind="fairness"):
    output.mkdir()
    run_id, boot_id = uuid.uuid4().hex, uuid.uuid4().hex
    label = f"fairness-{count}" if kind == "fairness" else kind
    profile = "debug" if kind == "masking" else "release"
    profile_args = [] if profile == "debug" else ["--release"]
    report = {"schema": 1, "status": "INCOMPLETE", "run_id": run_id, "boot_id": boot_id, "kind": kind, "profile": profile,
              "processes": count, "seed": args.seed, "source_identity": source_identity(root),
              "icount": "shift=0,align=off,sleep=off", "host_watchdog_seconds": args.timeout,
              "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine(), "logical_cpus": os.cpu_count()},
              "limits": ["Virtual-time emulation measurements; no hardware latency claim", "Each report applies only to its named measurement family", "Counter hooks approximate user entry/exit at the assembly boundary; that small boundary cost is not separately calibrated"]}
    guest = None
    try:
        env = os.environ.copy()
        env.update(KERNEL_TEST_RUN_ID=run_id, KERNEL_TEST_BOOT_ID=boot_id, KERNEL_BENCH_PROCESSES=str(count), KERNEL_BENCH_KIND=kind,
                   CARGO_HOME=str(output / "cargo-home"), CARGO_TARGET_DIR=str(output / "user-target"), SOURCE_DATE_EPOCH="1793923200")
        build("build-user", [args.cargo, "build", "--locked", *profile_args, "-p", "user-programs", "--target", "riscv64imac-unknown-none-elf"], root, output, env)
        programs = output / f"user-target/riscv64imac-unknown-none-elf/{profile}"
        env.update(CARGO_TARGET_DIR=str(output / "kernel-target"), KERNEL_INIT_ELF=str(programs / "bench-init"))
        build("build-kernel", [args.cargo, "build", "--locked", *profile_args, "-p", "kernel", "--features", "instrumented", "--target", "riscv64imac-unknown-none-elf"], root, output, env)
        kernel = output / f"kernel-target/riscv64imac-unknown-none-elf/{profile}/kernel"
        fixtures = {"fairness": ["bench-worker"], "wakeup": ["bench-worker", "bench-sleeper"], "context": ["bench-worker"], "masking": ["mask-worker"], "reclaim": ["reclaim-child"]}[kind]
        report["static_elf"] = {"kernel": check_elf(kernel, kernel=True),
                                **{name: check_elf(programs / name) for name in ["bench-init", *fixtures]}}
        report["identities"] = {"kernel_sha256": sha256(kernel), "init_sha256": sha256(programs / "bench-init"),
                                "workload_sha256": {name: sha256(programs / name) for name in fixtures}, "firmware_sha256": sha256(args.firmware)}
        image = output / "bench.img"
        mkfs.create(image, uuid.UUID(run_id).bytes, [("/" + name, programs / name) for name in fixtures])
        report["initial_image_sha256"] = sha256(image)
        qemu = probe("qemu-system-riscv64", args.qemu)
        report["qemu"] = qemu
        if qemu["status"] != "MATCH":
            raise RuntimeError("QEMU 11.1.3 required")
        print(f"{label}: beginning specified {profile} guest workload", flush=True)
        guest = Guest(qemu["path"], kernel, args.firmware, image, output / "boot", start_paused=True, icount=True)
        guest.expect(rb"(?:^|\n)READY\r?\n")
        started = time.monotonic()
        last_progress = started
        while guest.child.poll() is None:
            guest.pump(0.1)
            now = time.monotonic()
            if now - started >= args.timeout:
                raise TimeoutError("fixed guest workload exceeded its host watchdog")
            if now - last_progress >= 30:
                print(f"{label}: {now - started:.0f} host seconds elapsed", flush=True)
                last_progress = now
        guest.wait_for_shutdown(1)
        report["elapsed_host_seconds"] = time.monotonic() - started
        report["serial_sha256"] = sha256(output / "boot/serial.log")
        report["measurement"], records = (analyze(bytes(guest.data), count, run_id, boot_id) if kind == "fairness" else analyze_extended(bytes(guest.data), kind, run_id, boot_id))
        guest = None
        (output / "raw-records.json").write_text(json.dumps(records, indent=2) + "\n")
        checked = fsck.inspect(image)
        if checked["needs_replay"] or sha256(image) != report["initial_image_sha256"]:
            raise ValueError("compute-only benchmark changed persistent storage")
        (output / "fsck.json").write_text(json.dumps(checked, indent=2) + "\n")
        report["source_unchanged"] = source_identity(root) == report["source_identity"]
        report["status"] = "PASS"
        if not report["source_unchanged"]:
            report["applicability"] = "Recorded binary identities only; candidate changed during measurement"
        print(f"{label}: PASS; raw data retained at {output}", flush=True)
    except Exception as error:
        report.update(status="INCOMPLETE" if isinstance(error, TimeoutError) else "FAIL", reason=str(error))
        print(f"{label}: {report['status']}: {error}", flush=True)
    finally:
        if guest:
            guest.close()
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--seed", type=int, default=1, help="Recorded identity; compute workload itself is deterministic")
    p.add_argument("--processes", choices=["4", "8", "both"], default="both")
    p.add_argument("--kind", choices=["fairness", "wakeup", "context", "masking", "reclaim", "all"], default="fairness")
    p.add_argument("--qemu", default="qemu-system-riscv64")
    p.add_argument("--firmware", type=Path, default=Path("build/fw_dynamic.bin"))
    p.add_argument("--cargo", default="cargo")
    p.add_argument("--timeout", type=float, default=1800)
    args = p.parse_args()
    if not 0 <= args.seed <= 2**64 - 1 or not 60 <= args.timeout <= 3600:
        p.error("seed must be u64; host watchdog must be 60 through 3600 seconds")
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if output.is_relative_to(root):
        p.error("measurement evidence must be outside the candidate tree")
    try:
        output.mkdir(parents=True, exist_ok=False)
        args.firmware = args.firmware.resolve(strict=True)
        counts = [4, 8] if args.processes == "both" else [int(args.processes)]
        kinds = ["fairness", "wakeup", "context", "masking", "reclaim"] if args.kind == "all" else [args.kind]
        reports = []
        for kind in kinds:
            for count in (counts if kind == "fairness" else [4]):
                label = f"fairness-{count}" if kind == "fairness" else kind
                reports.append(one_case(args, root, output / label, count, kind))
        index = {"schema": 1, "created_utc": datetime.now(timezone.utc).isoformat(),
                 "status": "PASS" if all(r["status"] == "PASS" for r in reports) else "INCOMPLETE", "cases": reports}
        (output / "bench.json").write_text(json.dumps(index, indent=2) + "\n")
        return 0 if index["status"] == "PASS" else 2
    except (OSError, ValueError) as error:
        p.exit(2, f"bench: {error}\n")


if __name__ == "__main__":
    sys.exit(main())
