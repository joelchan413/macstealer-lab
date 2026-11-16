#!/usr/bin/env python3
"""Aggregate MacStealer trials and create CSV summaries and plots."""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from lab_common import PROFILES, write_json


def wilson_interval(successes: int, total: int, z: float = 1.96):
    if total == 0:
        return None, None
    proportion = successes / total
    denominator = 1 + (z * z / total)
    center = (proportion + (z * z / (2 * total))) / denominator
    margin = (
        z
        * math.sqrt(
            (proportion * (1 - proportion) / total)
            + (z * z / (4 * total * total))
        )
        / denominator
    )
    return max(0.0, center - margin), min(1.0, center + margin)


def median(values):
    clean = [float(value) for value in values if value is not None]
    return statistics.median(clean) if clean else None


def quartiles(values):
    clean = sorted(float(value) for value in values if value is not None)
    if not clean:
        return None, None
    if len(clean) == 1:
        return clean[0], clean[0]
    points = statistics.quantiles(clean, n=4, method="inclusive")
    return points[0], points[2]


def load_trials(run_dir: Path):
    trials = []
    for result_path in sorted((run_dir / "trials").glob("*/result.json")):
        try:
            result = json.loads(result_path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        result["result_path"] = str(result_path)
        trials.append(result)
    return trials


def write_trial_table(path: Path, trials: list[dict[str, Any]]):
    fields = [
        "trial_id",
        "profile",
        "ap_isolate",
        "mfp_mode",
        "wmm_enabled",
        "auth_mode",
        "associated_clients",
        "valid_trial",
        "failure_class",
        "attack_success",
        "tcp_success",
        "reconnect_ms",
        "tcp_first_intercept_ms",
        "udp_first_intercept_ms",
        "udp_packets_sent_window",
        "udp_packets_intercepted_unique",
        "udp_bytes_intercepted",
        "interception_ratio",
        "measurement_exit_status",
        "result_path",
    ]
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(trials)


def summarize(trials: list[dict[str, Any]]):
    grouped = defaultdict(list)
    for trial in trials:
        grouped[(trial.get("profile"), trial.get("associated_clients"))].append(trial)

    summaries = []
    for (profile, clients), group in sorted(
        grouped.items(), key=lambda item: (list(PROFILES).index(item[0][0]), item[0][1])
    ):
        valid = [trial for trial in group if trial.get("valid_trial")]
        successes = [
            trial
            for trial in valid
            if trial.get("attack_success", trial.get("tcp_success"))
        ]
        tcp_successes = [trial for trial in valid if trial.get("tcp_success")]
        success_count = len(successes)
        low, high = wilson_interval(success_count, len(valid))
        all_volumes = [trial.get("udp_bytes_intercepted", 0) or 0 for trial in valid]
        success_volumes = [
            trial.get("udp_bytes_intercepted", 0) or 0 for trial in successes
        ]
        ratios = [trial.get("interception_ratio") for trial in valid]
        reconnects = [trial.get("reconnect_ms") for trial in valid]
        first_times = [trial.get("udp_first_intercept_ms") for trial in valid]
        reconnect_q1, reconnect_q3 = quartiles(reconnects)
        ratio_q1, ratio_q3 = quartiles(ratios)
        summaries.append(
            {
                "profile": profile,
                "associated_clients": clients,
                "attempted_trials": len(group),
                "valid_trials": len(valid),
                "infrastructure_failures": len(group) - len(valid),
                "attack_successes": success_count,
                "strict_tcp_successes": len(tcp_successes),
                "success_rate": success_count / len(valid) if valid else None,
                "success_ci95_low": low,
                "success_ci95_high": high,
                "reconnect_ms_median": median(reconnects),
                "reconnect_ms_q1": reconnect_q1,
                "reconnect_ms_q3": reconnect_q3,
                "udp_first_intercept_ms_median": median(first_times),
                "interception_ratio_median": median(ratios),
                "interception_ratio_q1": ratio_q1,
                "interception_ratio_q3": ratio_q3,
                "udp_bytes_median_unconditional": median(all_volumes),
                "udp_bytes_median_success_only": median(success_volumes),
            }
        )
    return summaries


def write_summary_csv(path: Path, summaries):
    if not summaries:
        path.write_text("")
        return
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summaries[0]))
        writer.writeheader()
        writer.writerows(summaries)


def make_plots(output: Path, trials, summaries):
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        return ["matplotlib is not installed; CSV summaries were still generated"]

    messages = []
    profile_order = [name for name in PROFILES if any(s["profile"] == name for s in summaries)]

    fig, axis = plt.subplots(figsize=(9, 5.5))
    for profile in profile_order:
        rows = sorted(
            [row for row in summaries if row["profile"] == profile],
            key=lambda row: row["associated_clients"],
        )
        rows = [row for row in rows if row["success_rate"] is not None]
        if not rows:
            continue
        x = [row["associated_clients"] for row in rows]
        y = [100 * row["success_rate"] for row in rows]
        lower = [100 * (row["success_rate"] - row["success_ci95_low"]) for row in rows]
        upper = [100 * (row["success_ci95_high"] - row["success_rate"]) for row in rows]
        axis.errorbar(x, y, yerr=[lower, upper], marker="o", capsize=4, label=profile)
    axis.set_xlabel("Associated clients before transition")
    axis.set_ylabel("Attack success: TCP or tagged UDP (%)")
    axis.set_ylim(-2, 102)
    axis.grid(alpha=0.3)
    axis.legend()
    fig.tight_layout()
    fig.savefig(output / "success-rate.png", dpi=180)
    plt.close(fig)

    fig, axis = plt.subplots(figsize=(9, 5.5))
    for profile in profile_order:
        rows = sorted(
            [row for row in summaries if row["profile"] == profile],
            key=lambda row: row["associated_clients"],
        )
        rows = [row for row in rows if row["interception_ratio_median"] is not None]
        if not rows:
            continue
        axis.plot(
            [row["associated_clients"] for row in rows],
            [100 * row["interception_ratio_median"] for row in rows],
            marker="o",
            label=profile,
        )
    axis.set_xlabel("Associated clients before transition")
    axis.set_ylabel("Median UDP interception ratio (%)")
    axis.set_ylim(-2, 102)
    axis.grid(alpha=0.3)
    axis.legend()
    fig.tight_layout()
    fig.savefig(output / "interception-ratio.png", dpi=180)
    plt.close(fig)

    fig, axis = plt.subplots(figsize=(9, 5.5))
    for profile in profile_order:
        rows = sorted(
            [row for row in summaries if row["profile"] == profile],
            key=lambda row: row["associated_clients"],
        )
        rows = [row for row in rows if row["reconnect_ms_median"] is not None]
        if not rows:
            continue
        axis.plot(
            [row["associated_clients"] for row in rows],
            [row["reconnect_ms_median"] for row in rows],
            marker="o",
            label=profile,
        )
    axis.set_xlabel("Associated clients before transition")
    axis.set_ylabel("Median attacker reconnect time (ms)")
    axis.grid(alpha=0.3)
    axis.legend()
    fig.tight_layout()
    fig.savefig(output / "reconnect-latency.png", dpi=180)
    plt.close(fig)

    failure_counts = Counter(
        trial.get("failure_class") or "valid_positive"
        for trial in trials
        if not trial.get("valid_trial") or trial.get("failure_class")
    )
    if failure_counts:
        fig, axis = plt.subplots(figsize=(9, 5.5))
        labels = list(failure_counts)
        axis.bar(labels, [failure_counts[label] for label in labels])
        axis.set_ylabel("Trial count")
        axis.set_title("Failure classifications")
        axis.tick_params(axis="x", rotation=25)
        fig.tight_layout()
        fig.savefig(output / "failure-classes.png", dpi=180)
        plt.close(fig)
    messages.append("generated PNG plots")
    return messages


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    run_dir = args.run.resolve()
    output = (args.output or (run_dir / "analysis")).resolve()
    output.mkdir(parents=True, exist_ok=True)
    trials = load_trials(run_dir)
    if not trials:
        parser.error(f"no trial results found under {run_dir / 'trials'}")

    summaries = summarize(trials)
    write_trial_table(output / "trials.csv", trials)
    write_summary_csv(output / "summary.csv", summaries)
    failures = Counter(
        trial.get("failure_class") or "none" for trial in trials if not trial.get("valid_trial")
    )
    write_json(
        output / "analysis.json",
        {
            "trial_results_found": len(trials),
            "valid_trials": sum(bool(trial.get("valid_trial")) for trial in trials),
            "failure_classes": dict(failures),
            "cells": summaries,
        },
    )
    messages = make_plots(output, trials, summaries)
    print(f"Analyzed {len(trials)} trials into {output}")
    for message in messages:
        print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
