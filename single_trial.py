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
    PROFILES,
    SERVER_IP,
    SSID,
    TCP_PORT,
    UDP_PORT,
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

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    macstealer_dir = args.macstealer.resolve()
    research_dir = macstealer_dir / "research"
    lab_dir = Path(__file__).resolve().parent
    measure_script = lab_dir / "macstealer_measure.py"
    traffic_script = lab_dir / "traffic_generator.py"
    client_conf = output / "client.conf"
    psk_file = output / "hostapd.psk"
    measurement_json = output / "measurement.json"
    measurement_events = output / "measurement-events.jsonl"
    server_events = output / "server-events.jsonl"
    result_path = output / "result.json"

    render_client_config(client_conf, args.profile)
    render_psk_file(psk_file)
    profile = PROFILES[args.profile]
    ap_config = hostapd_config_string(args.profile, psk_file)
    (output / "hostapd-effective-settings.txt").write_text(
        ap_config.replace(",", "\n") + "\n"
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
            "traffic_generator_log": str(output / "traffic-generator.log"),
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
        lab = net.addStation("lab", wlans=2, ip="0.0.0.0")
        backgrounds = [
            net.addStation(
                f"bg{index:03d}",
                ip="0.0.0.0",
            )
            for index in range(1, args.clients)
        ]
        srv = net.addHost("srv", ip=f"{SERVER_IP}/24")

        net.configureWifiNodes()
        net.addLink(srv, ap1)
        net.build()
        ap1.start([])
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
            station_conf.write_text(
                "network={\n"
                f"    ssid=\"{SSID}\"\n"
                "    scan_ssid=1\n"
                "    proto=RSN\n"
                "    pairwise=CCMP\n"
                f"    key_mgmt={profile['wpa_key_mgmt']}\n"
                f"    psk=\"{VICTIM_PSK}\"\n"
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

        victim_mac = lab.cmd("cat /sys/class/net/lab-wlan0/address").strip()
        result["victim_mac"] = victim_mac
        srv.cmd("sysctl -w net.ipv4.tcp_synack_retries=7")

        dnsmasq_log = (output / "dnsmasq.log").open("w")
        http_log = (output / "http.log").open("w")
        log_handles.extend([dnsmasq_log, http_log])
        dnsmasq = srv.popen(
            [
                "dnsmasq",
                "--no-daemon",
                "--bind-interfaces",
                "--interface=srv-eth0",
                "--port=0",
                "--dhcp-authoritative",
                f"--dhcp-host={victim_mac},{VICTIM_IP}",
                "--dhcp-range=10.77.0.20,10.77.0.250,255.255.255.0,12h",
                f"--dhcp-option=3,{SERVER_IP}",
                f"--dhcp-option=6,{SERVER_IP}",
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
                SERVER_IP,
            ],
            stdout=http_log,
            stderr=subprocess.STDOUT,
        )
        processes.extend([dnsmasq, httpd])
        time.sleep(0.5)
        if dnsmasq.poll() is not None or httpd.poll() is not None:
            raise RuntimeError("dnsmasq or the local TCP listener exited during startup")

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
                VICTIM_IP,
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
            f"{SERVER_IP}:{TCP_PORT}",
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
        ] + (["-" + ("d" * args.debug)] if args.debug else [])
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
