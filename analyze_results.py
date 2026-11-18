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
        "network_mode",
        "vlan_separated",
        "associated_clients",
        "background_direction",
        "background_load_target_mbps",
        "background_load_actual_mbps",
        "background_packets_sent",
        "background_packets_received",
        "background_receive_mbps",
        "background_delivery_ratio",
        "background_processes_stayed_running",
        "background_load_ok",
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
        background_rates = [
            trial.get("background_load_actual_mbps") for trial in valid
        ]
        background_receive_rates = [
            trial.get("background_receive_mbps") for trial in valid
        ]
        reconnect_q1, reconnect_q3 = quartiles(reconnects)
        ratio_q1, ratio_q3 = quartiles(ratios)
        summaries.append(
            {
                "profile": profile,
                "associated_clients": clients,
                "background_direction": next(
                    (
                        trial.get("background_direction")
                        for trial in group
                        if trial.get("background_direction")
                    ),
                    None,
                ),
                "attempted_trials": len(group),
                "valid_trials": len(valid),
                "infrastructure_failures": len(group) - len(valid),
                "attack_successes": success_count,
                "strict_tcp_successes": len(tcp_successes),
                "secure_negatives": sum(
                    trial.get("failure_class") == "secure_negative"
                    for trial in valid
                ),
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
                "background_load_target_mbps": median(
                    trial.get("background_load_target_mbps") for trial in group
                ),
                "background_load_actual_mbps_median": median(background_rates),
                "background_receive_mbps_median": median(
                    background_receive_rates
                ),
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
    profile_order = [
        name for name in PROFILES if any(s["profile"] == name for s in summaries)
    ]
    profile_labels = {
        "baseline_idle": "Baseline\nidle",
        "baseline_load20": "Baseline\n20 Mbit/s",
        "wmm_disabled_load20": "WMM disabled\n20 Mbit/s",
        "vlan_separated": "VLAN\nseparated",
    }
    labels = [
        profile_labels.get(profile, profile.replace("_", " "))
        for profile in profile_order
    ]
    colors = plt.rcParams["axes.prop_cycle"].by_key()["color"]
    client_counts = sorted(
        {row["associated_clients"] for row in summaries}
    )
    single_client_count = len(client_counts) == 1

    def color_for(index):
        return colors[index % len(colors)]

    def profile_trials(profile, field):
        values = []
        for trial in trials:
            if trial.get("profile") != profile or not trial.get("valid_trial"):
                continue
            value = trial.get(field)
            if value is not None:
                values.append(float(value))
        return values

    def jitter(count, width=0.42):
        if count <= 1:
            return [0.0] * count
        return [
            -width / 2 + width * index / (count - 1)
            for index in range(count)
        ]

    def plot_categorical_distribution(filename, field, ylabel, multiplier=1.0, ylim=None):
        fig, axis = plt.subplots(figsize=(9, 5.5))
        for index, profile in enumerate(profile_order):
            values = [
                multiplier * value for value in profile_trials(profile, field)
            ]
            if not values:
                continue
            axis.scatter(
                [index + offset for offset in jitter(len(values))],
                values,
                color=color_for(index),
                alpha=0.55,
                s=28,
                label="Individual trial" if index == 0 else None,
            )
            median_value = statistics.median(values)
            q1, q3 = quartiles(values)
            axis.errorbar(
                index,
                median_value,
                yerr=[[median_value - q1], [q3 - median_value]],
                color=color_for(index),
                marker="D",
                markersize=7,
                capsize=6,
                linewidth=2,
                label="Median and IQR" if index == 0 else None,
            )
            label_below = bool(
                ylim
                and median_value
                > ylim[1] - 0.08 * (ylim[1] - ylim[0])
            )
            axis.annotate(
                f"{median_value:.1f}",
                (index, median_value),
                xytext=(0, -14 if label_below else 10),
                textcoords="offset points",
                ha="center",
                va="top" if label_below else "bottom",
            )
        axis.set_xticks(range(len(profile_order)))
        axis.set_xticklabels(labels)
        axis.set_xlabel("AP profile")
        axis.set_ylabel(ylabel)
        if ylim:
            axis.set_ylim(*ylim)
        axis.grid(axis="y", alpha=0.3)
        axis.legend(loc="best")
        fig.tight_layout()
        fig.savefig(output / filename, dpi=180)
        plt.close(fig)

    if single_client_count:
        rows_by_profile = {
            row["profile"]: row
            for row in summaries
            if row["success_rate"] is not None
        }
        fig, axis = plt.subplots(figsize=(9, 5.5))
        for index, profile in enumerate(profile_order):
            row = rows_by_profile.get(profile)
            if not row:
                continue
            rate = 100 * row["success_rate"]
            axis.scatter(
                index,
                rate,
                color=color_for(index),
                marker="o",
                s=80,
            )
            axis.annotate(
                f"{row['attack_successes']}/{row['valid_trials']}",
                (index, rate),
                xytext=(0, -14 if rate > 90 else 10),
                textcoords="offset points",
                ha="center",
                va="top" if rate > 90 else "bottom",
            )
        axis.set_xticks(range(len(profile_order)))
        axis.set_xticklabels(labels)
        axis.set_xlabel("AP profile")
        axis.set_ylabel("Attack success: TCP or tagged UDP (%)")
        axis.set_ylim(-2, 102)
        axis.grid(axis="y", alpha=0.3)
        fig.tight_layout()
        fig.savefig(output / "success-rate.png", dpi=180)
        plt.close(fig)

        plot_categorical_distribution(
            "interception-ratio.png",
            "interception_ratio",
            "UDP interception ratio (%)",
            multiplier=100,
            ylim=(-2, 102),
        )
        plot_categorical_distribution(
            "reconnect-latency.png",
            "reconnect_ms",
            "Attacker reconnect time (ms)",
        )
    else:
        # Offset series slightly so equal values remain visible in the original
        # multi-client experiment rather than being drawn directly on top of
        # one another.
        offsets = jitter(len(profile_order), width=0.36)
        plot_specs = [
            (
                "success-rate.png",
                "success_rate",
                "Attack success: TCP or tagged UDP (%)",
                100,
                (-2, 102),
            ),
            (
                "interception-ratio.png",
                "interception_ratio_median",
                "Median UDP interception ratio (%)",
                100,
                (-2, 102),
            ),
            (
                "reconnect-latency.png",
                "reconnect_ms_median",
                "Median attacker reconnect time (ms)",
                1,
                None,
            ),
        ]
        for filename, field, ylabel, multiplier, ylim in plot_specs:
            fig, axis = plt.subplots(figsize=(9, 5.5))
            for index, profile in enumerate(profile_order):
                rows = sorted(
                    [
                        row
                        for row in summaries
                        if row["profile"] == profile and row[field] is not None
                    ],
                    key=lambda row: row["associated_clients"],
                )
                if not rows:
                    continue
                x = [row["associated_clients"] + offsets[index] for row in rows]
                y = [multiplier * row[field] for row in rows]
                axis.plot(x, y, marker="o", label=profile.replace("_", " "))
            axis.set_xticks(client_counts)
            axis.set_xlabel("Associated clients before transition")
            axis.set_ylabel(ylabel)
            if ylim:
                axis.set_ylim(*ylim)
            axis.grid(alpha=0.3)
            axis.legend()
            fig.tight_layout()
            fig.savefig(output / filename, dpi=180)
            plt.close(fig)

    loaded_profiles = [
        profile
        for profile in profile_order
        if any(
            trial.get("profile") == profile
            and trial.get("valid_trial")
            and trial.get("background_load_target_mbps", 0) > 0
            and trial.get("background_load_actual_mbps") is not None
            and trial.get("background_receive_mbps") is not None
            for trial in trials
        )
    ]
    throughput_path = output / "background-throughput.png"
    if loaded_profiles:
        fig, axis = plt.subplots(figsize=(8, 5.2))
        positions = list(range(len(loaded_profiles)))
        offered = [
            statistics.median(
                profile_trials(profile, "background_load_actual_mbps")
            )
            for profile in loaded_profiles
        ]
        received = [
            statistics.median(profile_trials(profile, "background_receive_mbps"))
            for profile in loaded_profiles
        ]
        width = 0.34
        axis.bar(
            [position - width / 2 for position in positions],
            offered,
            width,
            label="Offered",
        )
        axis.bar(
            [position + width / 2 for position in positions],
            received,
            width,
            label="Received",
        )
        axis.set_xticks(positions)
        axis.set_xticklabels(
            [
                profile_labels.get(profile, profile.replace("_", " "))
                for profile in loaded_profiles
            ]
        )
        axis.set_xlabel("Loaded AP profile")
        axis.set_ylabel("Background traffic (Mbit/s)")
        axis.grid(axis="y", alpha=0.3)
        axis.legend()
        fig.tight_layout()
        fig.savefig(throughput_path, dpi=180)
        plt.close(fig)
    else:
        throughput_path.unlink(missing_ok=True)

    outcome_counts = {
        "Attack succeeded": [
            sum(
                trial.get("profile") == profile
                and trial.get("valid_trial")
                and bool(trial.get("attack_success"))
                for trial in trials
            )
            for profile in profile_order
        ],
        "Secure negative": [
            sum(
                trial.get("profile") == profile
                and trial.get("valid_trial")
                and not bool(trial.get("attack_success"))
                for trial in trials
            )
            for profile in profile_order
        ],
        "Invalid": [
            sum(
                trial.get("profile") == profile
                and not trial.get("valid_trial")
                for trial in trials
            )
            for profile in profile_order
        ],
    }
    fig, axis = plt.subplots(figsize=(9, 5.5))
    bottoms = [0] * len(profile_order)
    for outcome, counts in outcome_counts.items():
        axis.bar(range(len(profile_order)), counts, bottom=bottoms, label=outcome)
        bottoms = [bottom + count for bottom, count in zip(bottoms, counts)]
    axis.set_xticks(range(len(profile_order)))
    axis.set_xticklabels(labels)
    axis.set_xlabel("AP profile")
    axis.set_ylabel("Trial count")
    axis.set_title("Trial outcomes")
    axis.legend()
    fig.tight_layout()
    fig.savefig(output / "trial-outcomes.png", dpi=180)
    plt.close(fig)

    failure_counts = Counter(
        trial.get("failure_class") or "unclassified"
        for trial in trials
        if not trial.get("valid_trial")
    )
    failure_path = output / "failure-classes.png"
    if failure_counts:
        fig, axis = plt.subplots(figsize=(9, 5.5))
        failure_labels = list(failure_counts)
        axis.bar(failure_labels, [failure_counts[label] for label in failure_labels])
        axis.set_ylabel("Invalid trial count")
        axis.set_title("Infrastructure failure classifications")
        axis.tick_params(axis="x", rotation=25)
        fig.tight_layout()
        fig.savefig(failure_path, dpi=180)
        plt.close(fig)
    else:
        failure_path.unlink(missing_ok=True)

    messages.append("generated non-overlapping categorical PNG plots")
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
