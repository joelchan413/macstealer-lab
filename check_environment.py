#!/usr/bin/env python3
"""Read-only checks for the MacStealer lab prerequisites."""

from __future__ import annotations

import argparse
import importlib.util
import shutil
import subprocess
from pathlib import Path

from lab_common import MACSTEALER_COMMIT


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--macstealer", type=Path, required=True)
    args = parser.parse_args()
    repository = args.macstealer.resolve()
    checks = []

    for binary in ["hostapd", "dnsmasq", "iw", "rfkill", "tcpdump", "mn"]:
        checks.append((f"binary: {binary}", shutil.which(binary) is not None))

    checks.append(
        ("Python module: mn_wifi", importlib.util.find_spec("mn_wifi") is not None)
    )
    for relative in [
        "research/macstealer.py",
        "research/venv/bin/python3",
        "wpa_supplicant/wpa_supplicant",
    ]:
        checks.append((f"file: {repository / relative}", (repository / relative).exists()))

    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repository, text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        commit = "unavailable"
    checks.append((f"MacStealer pinned commit ({commit})", commit == MACSTEALER_COMMIT))

    try:
        subprocess.check_call(
            ["modinfo", "mac80211_hwsim"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        module_ok = True
    except (OSError, subprocess.CalledProcessError):
        module_ok = False
    checks.append(("kernel module: mac80211_hwsim", module_ok))

    for label, passed in checks:
        print(f"[{'PASS' if passed else 'FAIL'}] {label}")
    failures = sum(not passed for _, passed in checks)
    print(f"\n{len(checks) - failures}/{len(checks)} checks passed")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
