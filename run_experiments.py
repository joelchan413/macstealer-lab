#!/usr/bin/env python3
"""Run or resume a randomized matrix of MacStealer measurement trials."""

from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path

from lab_common import PROFILES, collect_environment, write_json


DEFAULT_CLIENTS = [1, 5, 10, 20, 40]
DEFAULT_PROFILES = list(PROFILES)


def read_result(path: Path):
    """Return a result object, or (None, reason) for a damaged result file."""
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, f"{type(exc).__name__}: {exc}"
    if not isinstance(value, dict):
        return None, f"expected a JSON object, got {type(value).__name__}"
    return value, None


def parse_int_list(value: str) -> list[int]:
    values = [int(item.strip()) for item in value.split(",") if item.strip()]
    if not values or any(item < 1 for item in values):
        raise argparse.ArgumentTypeError("provide comma-separated integers >= 1")
    return values


def parse_str_list(value: str) -> list[str]:
    values = [item.strip() for item in value.split(",") if item.strip()]
    unknown = [item for item in values if item not in PROFILES]
    if not values or unknown:
        raise argparse.ArgumentTypeError(
            "unknown profiles: " + ", ".join(unknown or ["<empty>"])
        )
    return values


def build_plan(clients, profiles, trials, seed):
    plan = []
    for profile in profiles:
        block = []
        for client_count in clients:
            for repetition in range(1, trials + 1):
                trial_id = f"{profile}-n{client_count:03d}-r{repetition:03d}"
                block.append(
                    {
                        "trial_id": trial_id,
                        "profile": profile,
                        "clients": client_count,
                        "repetition": repetition,
                    }
                )
        # Keep expensive AP-profile changes blocked, but randomize client count
        # and repetition inside each block.
        random.Random(f"{seed}:{profile}").shuffle(block)
        plan.extend(block)
    return plan


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--macstealer", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, default=Path("results"))
    parser.add_argument("--resume", type=Path)
    parser.add_argument("--clients", type=parse_int_list, default=DEFAULT_CLIENTS)
    parser.add_argument("--profiles", type=parse_str_list, default=DEFAULT_PROFILES)
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--seed", type=int, default=20261115)
    parser.add_argument("--udp-rate", type=float, default=100.0)
    parser.add_argument("--payload-bytes", type=int, default=1200)
    parser.add_argument("--observation-seconds", type=float, default=10.0)
    parser.add_argument(
        "--trial-timeout",
        type=float,
        default=None,
        help=(
            "Maximum seconds allowed for one trial (new runs default to 300; "
            "on resume, an explicit value overrides the saved manifest)"
        ),
    )
    parser.add_argument("--hwsim-pcap", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--rerun-invalid",
        action="store_true",
        help="Rerun completed trial directories whose result is not valid",
    )
    args = parser.parse_args()

    if os.geteuid() != 0 and not args.dry_run:
        parser.error("run_experiments.py must run as root (use sudo)")
    if args.trials < 1:
        parser.error("--trials must be at least 1")

    lab_dir = Path(__file__).resolve().parent
    single_trial = lab_dir / "single_trial.py"
    macstealer_dir = args.macstealer.resolve()

    if args.resume:
        run_dir = args.resume.resolve()
        manifest_path = run_dir / "manifest.json"
        if not manifest_path.exists():
            parser.error(f"resume manifest does not exist: {manifest_path}")
        manifest = json.loads(manifest_path.read_text())
        if args.trial_timeout is not None:
            manifest["trial_timeout_seconds"] = args.trial_timeout
            write_json(manifest_path, manifest)
        plan = manifest["plan"]
    else:
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        run_dir = (args.output_root / f"macstealer-{stamp}").resolve()
        run_dir.mkdir(parents=True, exist_ok=False)
        plan = build_plan(args.clients, args.profiles, args.trials, args.seed)
        manifest = {
            "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "seed": args.seed,
            "clients": args.clients,
            "profiles": args.profiles,
            "trials_per_cell": args.trials,
            "udp_rate": args.udp_rate,
            "payload_bytes": args.payload_bytes,
            "observation_seconds": args.observation_seconds,
            "trial_timeout_seconds": args.trial_timeout or 300.0,
            "environment": collect_environment(macstealer_dir),
            "plan": plan,
        }
        write_json(run_dir / "manifest.json", manifest)

    print(f"Experiment directory: {run_dir}")
    print(f"Planned trials: {len(plan)}")
    if args.dry_run:
        for item in plan:
            print(item["trial_id"])
        return 0

    completed = 0
    skipped = 0
    invalid = 0
    matrix_log_path = run_dir / "matrix.log"
    with matrix_log_path.open("a", buffering=1) as matrix_log:
        for index, item in enumerate(plan, start=1):
            trial_dir = run_dir / "trials" / item["trial_id"]
            result_path = trial_dir / "result.json"
            if result_path.exists():
                existing, result_error = read_result(result_path)
                if result_error:
                    print(
                        f"[{index}/{len(plan)}] damaged result for "
                        f"{item['trial_id']}: {result_error}; archive and rerun"
                    )
                elif existing.get("valid_trial") or not args.rerun_invalid:
                    skipped += 1
                    print(f"[{index}/{len(plan)}] skip {item['trial_id']}")
                    continue

            if trial_dir.exists():
                archive_stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
                archive_stamp += f"-{time.time_ns()}"
                archive_dir = (
                    run_dir
                    / "invalid-attempts"
                    / f"{item['trial_id']}-{archive_stamp}"
                )
                archive_dir.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(trial_dir), str(archive_dir))

            print(f"[{index}/{len(plan)}] run {item['trial_id']}")
            command = [
                sys.executable,
                str(single_trial),
                "--macstealer",
                str(macstealer_dir),
                "--output",
                str(trial_dir),
                "--trial-id",
                item["trial_id"],
                "--clients",
                str(item["clients"]),
                "--profile",
                item["profile"],
                "--udp-rate",
                str(manifest["udp_rate"]),
                "--payload-bytes",
                str(manifest["payload_bytes"]),
                "--observation-seconds",
                str(manifest["observation_seconds"]),
            ]
            if args.hwsim_pcap:
                command.append("--hwsim-pcap")

            # Best-effort cleanup protects subsequent trials when a prior
            # Mininet process was interrupted.
            subprocess.run(
                ["mn", "-c"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
            started = time.monotonic()
            try:
                process = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=manifest.get("trial_timeout_seconds", 300.0),
                    check=False,
                )
                output_text = process.stdout
                status = process.returncode
            except subprocess.TimeoutExpired as exc:
                output_text = exc.stdout or ""
                if isinstance(output_text, bytes):
                    output_text = output_text.decode("utf-8", errors="replace")
                output_text += "\nMATRIX TIMEOUT\n"
                status = 124
            elapsed = time.monotonic() - started
            matrix_log.write(
                f"\n===== {item['trial_id']} status={status} elapsed={elapsed:.1f}s =====\n"
            )
            matrix_log.write(output_text)
            if output_text and not output_text.endswith("\n"):
                matrix_log.write("\n")

            completed += 1
            if result_path.exists():
                trial_result, result_error = read_result(result_path)
                if result_error:
                    invalid += 1
                    print(f"  damaged result.json: {result_error}")
                else:
                    if not trial_result.get("valid_trial"):
                        invalid += 1
                    print(
                        "  valid={} attack={} tcp={} udp={} failure={}".format(
                            trial_result.get("valid_trial"),
                            trial_result.get("attack_success"),
                            trial_result.get("tcp_success"),
                            trial_result.get("udp_packets_intercepted_unique"),
                            trial_result.get("failure_class"),
                        )
                    )
            else:
                invalid += 1
                print("  no result.json produced; inspect matrix.log")

    summary = {
        "run_directory": str(run_dir),
        "planned": len(plan),
        "executed_this_invocation": completed,
        "skipped": skipped,
        "invalid_this_invocation": invalid,
        "finished_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    write_json(run_dir / "run-summary.json", summary)
    print(json.dumps(summary, indent=2))
    print(
        f"Analyze with: python3 {lab_dir / 'analyze_results.py'} --run {run_dir}"
    )
    return 0 if invalid == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
