#!/usr/bin/env python3
"""Shared constants and helpers for the MacStealer experiment harness."""

from __future__ import annotations

import json
import os
import platform
import subprocess
from pathlib import Path
from typing import Any, Optional


SSID = "macstealer-lab"
VICTIM_PSK = "VictimPass123"
ATTACKER_PSK = "AttackerPass123"
SERVER_IP = "10.77.0.1"
VICTIM_IP = "10.77.0.20"
VLAN_VICTIM_SERVER_IP = "10.77.10.1"
VLAN_VICTIM_IP = "10.77.10.20"
VLAN_ATTACKER_SERVER_IP = "10.77.20.1"
VLAN_ATTACKER_IP = "10.77.20.20"
TCP_PORT = 4444
UDP_PORT = 5555
BACKGROUND_PORT = 6000
MACSTEALER_COMMIT = "83851791bc2657bd9f2f384d6b739956ab2c3ea8"


PROFILES: dict[str, dict[str, Any]] = {
    "baseline": {
        "description": "Multi-PSK, client isolation enabled, MFP disabled, WMM enabled",
        "ap_isolate": 1,
        "ieee80211w": 0,
        "wpa_key_mgmt": "WPA-PSK",
        "wmm_enabled": 1,
        "background_load_mbps": 0.0,
        "network_mode": "same_bss",
    },
    "no_isolation": {
        "description": "Baseline with client isolation disabled (positive control)",
        "ap_isolate": 0,
        "ieee80211w": 0,
        "wpa_key_mgmt": "WPA-PSK",
        "wmm_enabled": 1,
        "background_load_mbps": 0.0,
        "network_mode": "same_bss",
    },
    "mfp_required": {
        "description": "Baseline with Management Frame Protection required",
        "ap_isolate": 1,
        "ieee80211w": 2,
        "wpa_key_mgmt": "WPA-PSK-SHA256",
        "wmm_enabled": 1,
        "background_load_mbps": 0.0,
        "network_mode": "same_bss",
    },
    "wmm_disabled": {
        "description": "Baseline with WMM disabled",
        "ap_isolate": 1,
        "ieee80211w": 0,
        "wpa_key_mgmt": "WPA-PSK",
        "wmm_enabled": 0,
        "background_load_mbps": 0.0,
        "network_mode": "same_bss",
    },
    "baseline_idle": {
        "description": "Baseline client-isolation profile with idle background stations",
        "ap_isolate": 1,
        "ieee80211w": 0,
        "wpa_key_mgmt": "WPA-PSK",
        "wmm_enabled": 1,
        "background_load_mbps": 0.0,
        "network_mode": "same_bss",
    },
    "baseline_load20": {
        "description": "Baseline profile with 20 Mbit/s aggregate uplink background load",
        "ap_isolate": 1,
        "ieee80211w": 0,
        "wpa_key_mgmt": "WPA-PSK",
        "wmm_enabled": 1,
        "background_load_mbps": 20.0,
        "background_direction": "uplink_to_server",
        "network_mode": "same_bss",
    },
    "wmm_disabled_load20": {
        "description": "WMM disabled with 20 Mbit/s aggregate uplink background load",
        "ap_isolate": 1,
        "ieee80211w": 0,
        "wpa_key_mgmt": "WPA-PSK",
        "wmm_enabled": 0,
        "background_load_mbps": 20.0,
        "background_direction": "uplink_to_server",
        "network_mode": "same_bss",
    },
    "vlan_separated": {
        "description": "Victim and attacker credentials placed on isolated BSS forwarding domains",
        "ap_isolate": 1,
        "ieee80211w": 0,
        "wpa_key_mgmt": "WPA-PSK",
        "wmm_enabled": 1,
        "background_load_mbps": 0.0,
        "network_mode": "separate_bss_vlan",
    },
}


STUDY_PROFILES = [
    "baseline_idle",
    "baseline_load20",
    "wmm_disabled_load20",
    "vlan_separated",
]


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def command_output(command: list[str], cwd: Path | None = None) -> str:
    try:
        return subprocess.check_output(
            command, cwd=cwd, stderr=subprocess.STDOUT, text=True, timeout=15
        ).strip()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        output = getattr(exc, "output", "") or ""
        return f"unavailable: {output.strip() or exc}"


def collect_environment(macstealer_dir: Path) -> dict[str, Any]:
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "kernel": platform.release(),
        "euid": os.geteuid(),
        "hostapd_version": command_output(["hostapd", "-v"]),
        "mininet_version": command_output(["mn", "--version"]),
        "iw_version": command_output(["iw", "--version"]),
        "macstealer_commit": command_output(
            ["git", "rev-parse", "HEAD"], cwd=macstealer_dir
        ),
    }


def render_client_config(
    path: Path,
    profile_name: str,
    victim_bssid: Optional[str] = None,
    attacker_bssid: Optional[str] = None,
) -> None:
    profile = PROFILES[profile_name]
    mfp_line = "\tieee80211w=2\n" if profile["ieee80211w"] == 2 else ""
    victim_bssid_line = f"\tbssid={victim_bssid}\n" if victim_bssid else ""
    attacker_bssid_line = f"\tbssid={attacker_bssid}\n" if attacker_bssid else ""
    key_mgmt = profile["wpa_key_mgmt"]
    path.write_text(
        "# Generated by the MacStealer experiment harness.\n"
        "ctrl_interface=wpaspy_ctrl\n\n"
        "network={\n"
        "\tid_str=\"victim\"\n"
        f"\tssid=\"{SSID}\"\n"
        f"\tkey_mgmt={key_mgmt}\n"
        f"\tpsk=\"{VICTIM_PSK}\"\n"
        f"{victim_bssid_line}"
        f"{mfp_line}"
        "}\n\n"
        "network={\n"
        "\tid_str=\"attacker\"\n"
        f"\tssid=\"{SSID}\"\n"
        f"\tkey_mgmt={key_mgmt}\n"
        f"\tpsk=\"{ATTACKER_PSK}\"\n"
        f"{attacker_bssid_line}"
        f"{mfp_line}"
        "}\n"
    )


def render_psk_file(path: Path, identities=("victim", "attacker")) -> None:
    credentials = {
        "victim": VICTIM_PSK,
        "attacker": ATTACKER_PSK,
    }
    path.write_text(
        "".join(
            f"keyid={identity} 00:00:00:00:00:00 {credentials[identity]}\n"
            for identity in identities
        )
    )


def hostapd_config_string(profile_name: str, psk_file: Path) -> str:
    profile = PROFILES[profile_name]
    settings = [
        "wpa=2",
        f"wpa_key_mgmt={profile['wpa_key_mgmt']}",
        "rsn_pairwise=CCMP",
        f"wpa_psk_file={psk_file}",
        f"ap_isolate={profile['ap_isolate']}",
        f"ieee80211w={profile['ieee80211w']}",
        f"wmm_enabled={profile['wmm_enabled']}",
    ]
    return ",".join(settings)


def station_config_string(profile_name: str) -> str:
    profile = PROFILES[profile_name]
    settings = [
        f'ssid="{SSID}"',
        f'psk="{VICTIM_PSK}"',
        f"key_mgmt={profile['wpa_key_mgmt']}",
    ]
    if profile["ieee80211w"] == 2:
        settings.append("ieee80211w=2")
    return ",".join(settings)
