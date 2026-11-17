#!/usr/bin/env python3
"""Run one isolated MacStealer measurement trial in Mininet-WiFi."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import Any

from lab_common import (
    ATTACKER_PSK,
    BACKGROUND_PORT,
    PROFILES,
    SERVER_IP,
    SSID,
    TCP_PORT,
    UDP_PORT,
    VLAN_ATTACKER_IP,
    VLAN_ATTACKER_SERVER_IP,
    VLAN_VICTIM_IP,
    VLAN_VICTIM_SERVER_IP,
    VICTIM_IP,
    VICTIM_PSK,
    collect_environment,
    hostapd_config_string,
    render_client_config,
    render_psk_file,
    write_json,
)


def stop_process(process, timeout: float = 4.0) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=timeout)


def parse_server_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not path.exists():
        return events
    for line in path.read_text().splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("sent"):
            events.append(event)
    return events


def read_json_if_present(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def wait_for_background_links(stations, timeout: float = 35.0) -> tuple[int, list[str]]:
    deadline = time.monotonic() + timeout
    connected: set[str] = set()
    while time.monotonic() < deadline:
        for station in stations:
            output = station.cmd(f"iw dev {station.name}-wlan0 link")
            if "Connected to" in output:
                connected.add(station.name)
        if len(connected) == len(stations):
            break
        time.sleep(0.5)
    missing = sorted(station.name for station in stations if station.name not in connected)
    return len(connected), missing


def wait_for_background_receivers(
    paths: list[Path], timeout: float = 5.0, poll_interval: float = 0.1
) -> list[int]:
    """Wait until every background sink has received at least one datagram."""
    deadline = time.monotonic() + timeout
    counts = [0 for _path in paths]
    while time.monotonic() < deadline:
        counts = [
            int(read_json_if_present(path).get("packets", 0)) for path in paths
        ]
        if counts and all(count > 0 for count in counts):
            break
        time.sleep(poll_interval)
    return counts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--macstealer", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--trial-id", required=True)
    parser.add_argument("--clients", type=int, required=True)
    parser.add_argument("--profile", choices=sorted(PROFILES), required=True)
    parser.add_argument("--udp-rate", type=float, default=100.0)
    parser.add_argument("--payload-bytes", type=int, default=1200)
    parser.add_argument("--observation-seconds", type=float, default=10.0)
    parser.add_argument("--hwsim-pcap", action="store_true")
    parser.add_argument("-d", "--debug", action="count", default=0)
    args = parser.parse_args()

    if os.geteuid() != 0:
        parser.error("single_trial.py must run as root (use sudo)")
    if args.clients < 1:
        parser.error("--clients must be at least 1")

    profile = PROFILES[args.profile]
    background_load_mbps = float(profile.get("background_load_mbps", 0.0))
    background_direction = profile.get("background_direction")
    separated = profile.get("network_mode") == "separate_bss_vlan"
    victim_server_ip = VLAN_VICTIM_SERVER_IP if separated else SERVER_IP
    victim_ip = VLAN_VICTIM_IP if separated else VICTIM_IP
    if background_load_mbps > 0 and args.clients < 2:
        parser.error("loaded profiles require at least two associated clients")

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    macstealer_dir = args.macstealer.resolve()
    research_dir = macstealer_dir / "research"
    lab_dir = Path(__file__).resolve().parent
    measure_script = lab_dir / "macstealer_measure.py"
    traffic_script = lab_dir / "traffic_generator.py"
    background_script = lab_dir / "background_traffic.py"
    client_conf = output / "client.conf"
    psk_file = output / "hostapd.psk"
    attacker_psk_file = output / "hostapd-attacker.psk"
    measurement_json = output / "measurement.json"
    measurement_events = output / "measurement-events.jsonl"
    server_events = output / "server-events.jsonl"
    result_path = output / "result.json"

    if separated:
        render_psk_file(psk_file, identities=("victim",))
        render_psk_file(attacker_psk_file, identities=("attacker",))
    else:
        render_client_config(client_conf, args.profile)
        render_psk_file(psk_file)
    ap_config = hostapd_config_string(args.profile, psk_file)
    attacker_ap_config = (
        hostapd_config_string(args.profile, attacker_psk_file)
        if separated
        else None
    )
    (output / "hostapd-effective-settings.txt").write_text(
        "[victim-bss]\n"
        + ap_config.replace(",", "\n")
        + "\n"
        + (
            "\n[attacker-bss]\n"
            + attacker_ap_config.replace(",", "\n")
            + "\n"
            if attacker_ap_config
            else ""
        )
    )
    write_json(output / "environment.json", collect_environment(macstealer_dir))
    write_json(
        output / "trial-plan.json",
        {
            "trial_id": args.trial_id,
            "profile": args.profile,
            "profile_settings": profile,
            "associated_clients": args.clients,
            "background_clients": args.clients - 1,
            "udp_rate": args.udp_rate,
            "payload_bytes": args.payload_bytes,
            "observation_seconds": args.observation_seconds,
            "background_load_mbps": background_load_mbps,
            "background_direction": background_direction,
            "network_mode": profile.get("network_mode", "same_bss"),
            "victim_server_ip": victim_server_ip,
            "victim_ip": victim_ip,
            "attacker_gateway_ip": (
                VLAN_ATTACKER_SERVER_IP if separated else SERVER_IP
            ),
            "attacker_ip": VLAN_ATTACKER_IP if separated else VICTIM_IP,
        },
    )

    result: dict[str, Any] = {
        "trial_id": args.trial_id,
        "profile": args.profile,
        "profile_settings": profile,
        "ap_isolate": profile["ap_isolate"],
        "mfp_mode": profile["ieee80211w"],
        "wmm_enabled": profile["wmm_enabled"],
        "auth_mode": profile["wpa_key_mgmt"],
        "associated_clients": args.clients,
        "background_clients": args.clients - 1,
        "udp_rate": args.udp_rate,
        "payload_bytes": args.payload_bytes,
        "observation_seconds": args.observation_seconds,
        "background_load_target_mbps": background_load_mbps,
        "background_direction": background_direction,
        "background_load_ok": background_load_mbps == 0,
        "network_mode": profile.get("network_mode", "same_bss"),
        "vlan_separated": separated,
        "victim_server_ip": victim_server_ip,
        "configured_victim_ip": victim_ip,
        "attacker_gateway_ip": (
            VLAN_ATTACKER_SERVER_IP if separated else SERVER_IP
        ),
        "configured_attacker_ip": VLAN_ATTACKER_IP if separated else VICTIM_IP,
        "valid_trial": False,
        "failure_class": "tool_failure",
        "error": None,
        "artifacts": {
            "trial_directory": str(output),
            "server_pcap": str(output / "server.pcap"),
            "attacker_pcap": str(output / "attacker.pcap"),
            "hwsim_pcap": str(output / "hwsim.pcap") if args.hwsim_pcap else None,
            "macstealer_log": str(output / "macstealer.log"),
            "hostapd_log": str(output / "hostapd.log"),
            "hostapd_attacker_log": (
                str(output / "hostapd-attacker.log") if separated else None
            ),
            "traffic_generator_log": str(output / "traffic-generator.log"),
            "background_sender_summaries": [],
            "background_sink_summary": None,
        },
    }

    net = None
    processes: list[Any] = []
    log_handles = []
    exit_code = 1
    try:
        from mininet.log import setLogLevel
        from mn_wifi.net import Mininet_wifi

        setLogLevel("info")
        net = Mininet_wifi()
        ap1 = net.addAccessPoint(
            "ap1",
            ssid=SSID,
            mode="g",
            channel="1",
            encrypt="wpa2",
            passwd=VICTIM_PSK,
            ieee80211w=profile["ieee80211w"],
            client_isolation=bool(profile["ap_isolate"]),
            failMode="standalone",
            datapath="user",
            config=ap_config,
            hostapd_flags=f"-t -f {output / 'hostapd.log'}",
        )
        ap2 = None
        if separated:
            ap2 = net.addAccessPoint(
                "ap2",
                ssid=SSID,
                mode="g",
                channel="1",
                encrypt="wpa2",
                passwd=ATTACKER_PSK,
                ieee80211w=profile["ieee80211w"],
                client_isolation=bool(profile["ap_isolate"]),
                failMode="standalone",
                datapath="user",
                config=attacker_ap_config,
                hostapd_flags=f"-t -f {output / 'hostapd-attacker.log'}",
            )
        lab = net.addStation("lab", wlans=2, ip="0.0.0.0")
        backgrounds = [
            net.addStation(
                f"bg{index:03d}",
                ip="0.0.0.0",
            )
            for index in range(1, args.clients)
        ]
        srv = net.addHost("srv", ip=f"{victim_server_ip}/24")
        attacker_gateway = None
        if separated:
            attacker_gateway = net.addHost(
                "atknet", ip=f"{VLAN_ATTACKER_SERVER_IP}/24"
            )

        net.configureWifiNodes()
        net.addLink(srv, ap1)
        if separated:
            net.addLink(attacker_gateway, ap2)
        net.build()
        ap1.start([])
        if separated:
            ap2.start([])
            victim_bssid = ap1.cmd(
                "cat /sys/class/net/ap1-wlan1/address"
            ).strip()
            attacker_bssid = ap2.cmd(
                "cat /sys/class/net/ap2-wlan1/address"
            ).strip()
            if not victim_bssid or not attacker_bssid or victim_bssid == attacker_bssid:
                raise RuntimeError(
                    "unable to determine two distinct BSSIDs for VLAN profile"
                )
            result["victim_bssid"] = victim_bssid
            result["attacker_bssid"] = attacker_bssid
            render_client_config(
                client_conf,
                args.profile,
                victim_bssid=victim_bssid,
                attacker_bssid=attacker_bssid,
            )
        if not profile["ap_isolate"]:
            # OVS does not normally send a frame back out its ingress wireless
            # port. Hairpin it explicitly so this profile genuinely permits
            # station-to-station delivery instead of being accidentally
            # isolated by the virtual switch.
            wireless_port = ap1.cmd(
                "ovs-vsctl get Interface ap1-wlan1 ofport"
            ).strip()
            ap1.cmd(
                f'ovs-ofctl add-flow ap1 "priority=10,in_port={wireless_port},'
                'actions=output:in_port,normal"'
            )

        # Start background supplicants explicitly instead of relying on
        # Mininet-WiFi's version-dependent automatic association behavior.
        # This also leaves a separate debug log for every background station.
        for station in backgrounds:
            station_conf = output / f"{station.name}.conf"
            station_log = (output / f"{station.name}-wpa.log").open("w")
            log_handles.append(station_log)
            mfp_line = (
                "    ieee80211w=2\n" if profile["ieee80211w"] == 2 else ""
            )
            bssid_line = f"    bssid={victim_bssid}\n" if separated else ""
            station_conf.write_text(
                "network={\n"
                f"    ssid=\"{SSID}\"\n"
                "    scan_ssid=1\n"
                "    proto=RSN\n"
                "    pairwise=CCMP\n"
                f"    key_mgmt={profile['wpa_key_mgmt']}\n"
                f"    psk=\"{VICTIM_PSK}\"\n"
                f"{bssid_line}"
                f"{mfp_line}"
                "}\n"
            )
            supplicant = station.popen(
                [
                    "wpa_supplicant",
                    "-Dnl80211",
                    "-i",
                    f"{station.name}-wlan0",
                    "-c",
                    str(station_conf),
                    "-dd",
                ],
                stdout=station_log,
                stderr=subprocess.STDOUT,
            )
            processes.append(supplicant)

        connected, missing = wait_for_background_links(backgrounds)
        result["background_associated"] = connected
        result["background_missing"] = missing
        if missing:
            raise RuntimeError(f"background stations did not associate: {', '.join(missing)}")

        background_prefix = "10.77.10" if separated else "10.77.0"
        background_ips = []
        background_macs = []
        victim_server_mac = srv.cmd(
            "cat /sys/class/net/srv-eth0/address"
        ).strip()
        if not victim_server_mac:
            raise RuntimeError("could not determine victim server MAC address")
        result["victim_server_mac"] = victim_server_mac
        background_station_neighbors = {}
        for index, station in enumerate(backgrounds, start=1):
            station_ip = f"{background_prefix}.{100 + index}"
            station_interface = f"{station.name}-wlan0"
            station_mac = station.cmd(
                f"cat /sys/class/net/{station_interface}/address"
            ).strip()
            if not station_mac:
                raise RuntimeError(
                    f"could not determine MAC address for {station.name}"
                )
            background_ips.append(station_ip)
            background_macs.append(station_mac)
            station.cmd(
                f"ip address replace {station_ip}/24 dev {station_interface}"
            )
            station.cmd(
                f"ip route replace default via {victim_server_ip} "
                f"dev {station_interface}"
            )
            # Static station addresses are outside dnsmasq's leases. Seed the
            # server's neighbor table so a missed ARP exchange cannot silently
            # turn an offered 20 Mbit/s stream into zero delivered traffic.
            srv.cmd(
                f"ip neigh replace {station_ip} lladdr {station_mac} "
                "nud permanent dev srv-eth0"
            )
            station.cmd(
                f"ip neigh replace {victim_server_ip} lladdr {victim_server_mac} "
                f"nud permanent dev {station_interface}"
            )
            # Emit one station-originated exchange to teach the virtual AP and
            # bridge which wireless port owns this source MAC.
            station.cmd(f"ping -c 1 -W 1 {victim_server_ip}")
            background_station_neighbors[station.name] = station.cmd(
                f"ip neigh show dev {station_interface}"
            ).splitlines()
        result["background_ips"] = background_ips
        result["background_macs"] = background_macs
        result["background_server_neighbors"] = srv.cmd(
            "ip neigh show dev srv-eth0"
        ).splitlines()
        result["background_station_neighbors"] = background_station_neighbors

        victim_mac = lab.cmd("cat /sys/class/net/lab-wlan0/address").strip()
        result["victim_mac"] = victim_mac
        srv.cmd("sysctl -w net.ipv4.tcp_synack_retries=7")

        dnsmasq_log = (output / "dnsmasq.log").open("w")
        http_log = (output / "http.log").open("w")
        log_handles.extend([dnsmasq_log, http_log])
        victim_dhcp_range = (
            "10.77.10.20,10.77.10.99,255.255.255.0,12h"
            if separated
            else "10.77.0.20,10.77.0.99,255.255.255.0,12h"
        )
        dnsmasq = srv.popen(
            [
                "dnsmasq",
                "--no-daemon",
                "--bind-interfaces",
                "--interface=srv-eth0",
                "--port=0",
                "--dhcp-authoritative",
                f"--dhcp-host={victim_mac},{victim_ip}",
                f"--dhcp-range={victim_dhcp_range}",
                f"--dhcp-option=3,{victim_server_ip}",
                f"--dhcp-option=6,{victim_server_ip}",
                "--log-dhcp",
            ],
            stdout=dnsmasq_log,
            stderr=subprocess.STDOUT,
        )
        httpd = srv.popen(
            [
                "python3",
                "-m",
                "http.server",
                str(TCP_PORT),
                "--bind",
                victim_server_ip,
            ],
            stdout=http_log,
            stderr=subprocess.STDOUT,
        )
        processes.extend([dnsmasq, httpd])
        attacker_dnsmasq = None
        if separated:
            attacker_dnsmasq_log = (
                output / "dnsmasq-attacker.log"
            ).open("w")
            log_handles.append(attacker_dnsmasq_log)
            attacker_dnsmasq = attacker_gateway.popen(
                [
                    "dnsmasq",
                    "--no-daemon",
                    "--bind-interfaces",
                    "--interface=atknet-eth0",
                    "--port=0",
                    "--dhcp-authoritative",
                    f"--dhcp-host={victim_mac},{VLAN_ATTACKER_IP}",
                    "--dhcp-range=10.77.20.20,10.77.20.99,255.255.255.0,12h",
                    f"--dhcp-option=3,{VLAN_ATTACKER_SERVER_IP}",
                    f"--dhcp-option=6,{VLAN_ATTACKER_SERVER_IP}",
                    "--log-dhcp",
                ],
                stdout=attacker_dnsmasq_log,
                stderr=subprocess.STDOUT,
            )
            processes.append(attacker_dnsmasq)
        time.sleep(0.5)
        if (
            dnsmasq.poll() is not None
            or httpd.poll() is not None
            or (attacker_dnsmasq is not None and attacker_dnsmasq.poll() is not None)
        ):
            raise RuntimeError("dnsmasq or the local TCP listener exited during startup")

        background_senders = []
        background_sender_paths = []
        background_sinks = []
        background_sink_paths = []
        if background_load_mbps > 0:
            if background_direction != "uplink_to_server":
                raise RuntimeError(
                    f"unsupported background direction: {background_direction}"
                )

            sink_summary = output / "background-server-sink.json"
            sink_log = (output / "background-server-sink.log").open("w")
            log_handles.append(sink_log)
            sink = srv.popen(
                [
                    "python3",
                    str(background_script),
                    "sink",
                    "--bind",
                    victim_server_ip,
                    "--port",
                    str(BACKGROUND_PORT),
                    "--duration",
                    "120",
                    "--output",
                    str(sink_summary),
                ],
                stdout=sink_log,
                stderr=subprocess.STDOUT,
            )
            processes.append(sink)
            background_sinks.append(sink)
            background_sink_paths.append(sink_summary)

            per_station_mbps = background_load_mbps / len(backgrounds)
            for station in backgrounds:
                sender_summary = output / f"{station.name}-background-sender.json"
                sender_log = (
                    output / f"{station.name}-background-sender.log"
                ).open("w")
                log_handles.append(sender_log)
                sender = station.popen(
                    [
                        "python3",
                        str(background_script),
                        "sender",
                        "--target",
                        victim_server_ip,
                        "--port",
                        str(BACKGROUND_PORT),
                        "--aggregate-mbps",
                        str(per_station_mbps),
                        "--payload-bytes",
                        str(args.payload_bytes),
                        "--duration",
                        "120",
                        "--output",
                        str(sender_summary),
                    ],
                    stdout=sender_log,
                    stderr=subprocess.STDOUT,
                )
                processes.append(sender)
                background_senders.append(sender)
                background_sender_paths.append(sender_summary)

            result["artifacts"]["background_sender_summaries"] = [
                str(path) for path in background_sender_paths
            ]
            result["artifacts"]["background_sink_summary"] = str(
                sink_summary
            )
            time.sleep(1.0)
            failed_senders = [
                station.name
                for station, sender in zip(backgrounds, background_senders)
                if sender.poll() is not None
            ]
            if sink.poll() is not None or failed_senders:
                raise RuntimeError(
                    "background traffic process exited during startup; "
                    "failed senders: " + (", ".join(failed_senders) or "none")
                )
            sender_start_counts = [
                int(read_json_if_present(path).get("packets", 0))
                for path in background_sender_paths
            ]
            if not all(count > 0 for count in sender_start_counts):
                failed_senders = [
                    station.name
                    for station, count in zip(backgrounds, sender_start_counts)
                    if count <= 0
                ]
                raise RuntimeError(
                    "background senders produced no packets during startup: "
                    + ", ".join(failed_senders)
                )
            receiver_counts = wait_for_background_receivers(
                background_sink_paths
            )
            result["background_preflight_sender_packets"] = {
                station.name: count
                for station, count in zip(backgrounds, sender_start_counts)
            }
            result["background_preflight_receiver_packets"] = {
                "srv": receiver_counts[0] if receiver_counts else 0
            }
            result["background_preflight_packets_received"] = sum(receiver_counts)
            if not receiver_counts or not all(
                count > 0 for count in receiver_counts
            ):
                result["failure_class"] = "background_load_failure"
                raise RuntimeError(
                    "background server receiver preflight got no packets"
                )

        if shutil.which("tcpdump"):
            server_capture = srv.popen(
                [
                    "tcpdump",
                    "-U",
                    "-s",
                    "0",
                    "-i",
                    "srv-eth0",
                    "-w",
                    str(output / "server.pcap"),
                    "udp port 5555 or tcp port 4444",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            attacker_capture = lab.popen(
                [
                    "tcpdump",
                    "-U",
                    "-s",
                    "0",
                    "-i",
                    "lab-wlan0",
                    "-w",
                    str(output / "attacker.pcap"),
                    "udp port 5555 or tcp port 4444",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            processes.extend([server_capture, attacker_capture])
            if args.hwsim_pcap and Path("/sys/class/net/hwsim0").exists():
                hwsim_capture = subprocess.Popen(
                    [
                        "tcpdump",
                        "-U",
                        "-s",
                        "0",
                        "-i",
                        "hwsim0",
                        "-w",
                        str(output / "hwsim.pcap"),
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                processes.append(hwsim_capture)

        traffic_log = (output / "traffic-generator.log").open("w")
        log_handles.append(traffic_log)
        traffic = srv.popen(
            [
                "python3",
                str(traffic_script),
                "--trial-id",
                args.trial_id,
                "--target",
                victim_ip,
                "--port",
                str(UDP_PORT),
                "--rate",
                str(args.udp_rate),
                "--payload-bytes",
                str(args.payload_bytes),
                "--duration",
                "60",
                "--output",
                str(server_events),
            ],
            stdout=traffic_log,
            stderr=subprocess.STDOUT,
        )
        processes.append(traffic)
        time.sleep(0.25)
        if traffic.poll() is not None:
            traffic_log.flush()
            details = (output / "traffic-generator.log").read_text().strip()
            raise RuntimeError(
                "traffic generator exited during startup with status "
                f"{traffic.returncode}: {details or '<no output>'}"
            )

        macstealer_log = (output / "macstealer.log").open("w")
        log_handles.append(macstealer_log)
        command = [
            str(research_dir / "venv" / "bin" / "python3"),
            str(measure_script),
            "--research-dir",
            str(research_dir),
            "--iface",
            "lab-wlan0",
            "--config",
            str(client_conf),
            "--server",
            f"{victim_server_ip}:{TCP_PORT}",
            "--trial-id",
            args.trial_id,
            "--output",
            str(measurement_json),
            "--events",
            str(measurement_events),
            "--udp-port",
            str(UDP_PORT),
            "--observation-seconds",
            str(args.observation_seconds),
        ]
        if separated:
            command.extend(["--other-bss", "--fresh-attacker-dhcp"])
        if args.debug:
            command.append("-" + ("d" * args.debug))
        measurement = lab.popen(
            command, stdout=macstealer_log, stderr=subprocess.STDOUT
        )
        processes.append(measurement)
        try:
            measurement_status = measurement.wait(timeout=90)
        except subprocess.TimeoutExpired:
            stop_process(measurement)
            measurement_status = 124
            result["error"] = "measurement timed out after 90 seconds"
        result["measurement_exit_status"] = measurement_status

        stop_process(traffic)
        if background_senders:
            background_processes_stayed_running = (
                all(sender.poll() is None for sender in background_senders)
                and all(sink.poll() is None for sink in background_sinks)
            )
            for sender in background_senders:
                stop_process(sender)
            for sink in background_sinks:
                stop_process(sink)
            sender_metrics = [
                read_json_if_present(path) for path in background_sender_paths
            ]
            sink_metrics = [
                read_json_if_present(path) for path in background_sink_paths
            ]
            sender_packets = sum(
                int(item.get("packets", 0)) for item in sender_metrics
            )
            received_packets = sum(
                int(item.get("packets", 0)) for item in sink_metrics
            )
            result["background_packets_sent"] = sender_packets
            result["background_payload_bytes_sent"] = sum(
                int(item.get("payload_bytes", 0)) for item in sender_metrics
            )
            actual_background_mbps = sum(
                float(item.get("achieved_mbps", 0.0))
                for item in sender_metrics
            )
            result["background_load_actual_mbps"] = actual_background_mbps
            result["background_packets_received"] = received_packets
            received_bytes = sum(
                int(item.get("payload_bytes", 0)) for item in sink_metrics
            )
            result["background_payload_bytes_received"] = received_bytes
            sink_elapsed = max(
                (float(item.get("elapsed_seconds", 0.0)) for item in sink_metrics),
                default=0.0,
            )
            result["background_receive_mbps"] = (
                received_bytes * 8 / sink_elapsed / 1_000_000
                if sink_elapsed > 0
                else 0.0
            )
            result["background_delivery_ratio"] = (
                received_packets / sender_packets if sender_packets else None
            )
            result["background_load_ok"] = (
                sender_packets > 0
                and received_packets > 0
                and actual_background_mbps >= background_load_mbps * 0.9
                and background_processes_stayed_running
            )
            result["background_processes_stayed_running"] = (
                background_processes_stayed_running
            )
        else:
            result["background_packets_sent"] = 0
            result["background_payload_bytes_sent"] = 0
            result["background_load_actual_mbps"] = 0.0
            result["background_packets_received"] = 0
            result["background_payload_bytes_received"] = 0
            result["background_receive_mbps"] = 0.0
            result["background_delivery_ratio"] = None
            result["background_processes_stayed_running"] = True
        if not measurement_json.exists():
            raise RuntimeError("measurement process did not produce measurement.json")
        measurement_data = json.loads(measurement_json.read_text())
        result.update(measurement_data)

        sent_events = parse_server_events(server_events)
        ready_ns = measurement_data.get("attacker_ready_ns")
        observation_end_ns = None
        if ready_ns is not None:
            observation_end_ns = ready_ns + int(args.observation_seconds * 1e9)
            window_events = [
                event
                for event in sent_events
                if ready_ns <= event["send_ns"] <= observation_end_ns
            ]
        else:
            window_events = []
        sent_sequences = {event["sequence"] for event in window_events}
        result["udp_packets_sent_window"] = len(sent_sequences)
        result["udp_payload_bytes_sent_window"] = sum(
            event["payload_bytes"] for event in window_events
        )
        intercepted = int(result.get("udp_packets_intercepted_unique", 0))
        result["attack_success"] = bool(result.get("tcp_success") or intercepted > 0)
        result["interception_ratio"] = (
            intercepted / len(sent_sequences) if sent_sequences else None
        )
        result["server_preflight_ok"] = bool(sent_events)

        if not result.get("victim_auth_ok") or not result.get("attacker_auth_ok"):
            result["failure_class"] = "auth_failure"
        elif not result.get("dhcp_ok"):
            result["failure_class"] = "dhcp_failure"
        elif not result.get("background_load_ok"):
            result["failure_class"] = "background_load_failure"
        elif not sent_sequences:
            result["failure_class"] = "server_failure"
        elif measurement_data.get("failure_class"):
            result["failure_class"] = measurement_data["failure_class"]
        else:
            result["valid_trial"] = True
            result["failure_class"] = (
                None
                if result["attack_success"]
                else "secure_negative"
            )
            result["error"] = None
            exit_code = 0

    except BaseException as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        (output / "single-trial-traceback.log").write_text(traceback.format_exc())
    finally:
        for process in reversed(processes):
            try:
                stop_process(process)
            except BaseException:
                pass
        for handle in log_handles:
            try:
                handle.close()
            except BaseException:
                pass
        if net is not None:
            try:
                net.stop()
            except BaseException:
                pass
        result["completed_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        write_json(result_path, result)

    print(json.dumps({
        "trial_id": args.trial_id,
        "valid_trial": result.get("valid_trial"),
        "tcp_success": result.get("tcp_success"),
        "attack_success": result.get("attack_success"),
        "udp_packets_intercepted_unique": result.get("udp_packets_intercepted_unique"),
        "failure_class": result.get("failure_class"),
        "result": str(result_path),
    }, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
