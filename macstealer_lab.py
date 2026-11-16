#!/usr/bin/env python3
"""Deterministic Mininet-WiFi lab for the MacStealer PoC.

The topology is:

    lab-wlan0 ----\
                   ap1 ---- srv (10.77.0.1)
    lab-wlan1 ----/

The two lab radios are deliberately placed in the same Mininet namespace so
MacStealer can use one for the CVE test and both for its client-isolation test.
The AP accepts two distinct PSKs on one SSID and has client isolation enabled.
"""

import argparse
import shlex
from pathlib import Path

from mininet.log import info, setLogLevel
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi


SERVER_IP = "10.77.0.1"
SERVER_PORT = 4444


def run_macstealer(lab, research_dir, client_conf, *extra):
    args = [
        "./venv/bin/python3",
        "./macstealer.py",
        "lab-wlan0",
        "--config",
        str(client_conf),
        "--server",
        f"{SERVER_IP}:{SERVER_PORT}",
        *extra,
    ]
    command = "cd {} && {}".format(
        shlex.quote(str(research_dir)),
        " ".join(shlex.quote(arg) for arg in args),
    )
    info("\n*** Running: {}\n".format(" ".join(args)))
    # MacStealer exits with status 1 after both positive and completed tests.
    # Therefore, display and interpret its text instead of the shell status.
    output = lab.cmd(command)
    print(output, end="")
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--macstealer",
        type=Path,
        required=True,
        help="Path to the cloned MacStealer repository",
    )
    parser.add_argument(
        "--run-demo",
        action="store_true",
        help="Run both sanity checks and the positive CVE test automatically",
    )
    parser.add_argument(
        "--recording-sequence",
        action="store_true",
        help="Run the client-isolation control followed by the normal attack",
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Open the Mininet-WiFi CLI after optional automatic tests",
    )
    args = parser.parse_args()
    if args.run_demo and args.recording_sequence:
        parser.error("choose either --run-demo or --recording-sequence")

    lab_dir = Path(__file__).resolve().parent
    psk_file = lab_dir / "hostapd.psk"
    client_conf = lab_dir / "client.conf"
    research_dir = args.macstealer.resolve() / "research"

    required = [
        psk_file,
        client_conf,
        research_dir / "macstealer.py",
        research_dir / "venv" / "bin" / "python3",
        args.macstealer.resolve() / "wpa_supplicant" / "wpa_supplicant",
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise SystemExit("Missing required files:\n  " + "\n  ".join(missing))

    net = Mininet_wifi()
    ap1 = net.addAccessPoint(
        "ap1",
        ssid="macstealer-lab",
        mode="g",
        channel="1",
        client_isolation=True,
        failMode="standalone",
        datapath="user",
        config=(
            "wpa=2,"
            "wpa_key_mgmt=WPA-PSK,"
            "rsn_pairwise=CCMP,"
            f"wpa_psk_file={psk_file}"
        ),
    )
    # MacStealer manages association itself, so do not give this station an
    # encrypt/passwd parameter and do not add an infrastructure wireless link.
    lab = net.addStation("lab", wlans=2, ip="0.0.0.0")
    srv = net.addHost("srv", ip=f"{SERVER_IP}/24")

    info("*** Creating three mac80211_hwsim radios\n")
    net.configureWifiNodes()
    net.addLink(srv, ap1)

    info("*** Starting AP and wired server\n")
    net.build()
    ap1.start([])

    # The PoC intentionally never completes the TCP handshake. A normal Linux
    # listener therefore retransmits SYN/ACK. Seven retries make the timing
    # margin generous even on a slow VM.
    srv.cmd("sysctl -w net.ipv4.tcp_synack_retries=7")
    dnsmasq = srv.popen(
        [
            "dnsmasq",
            "--no-daemon",
            "--bind-interfaces",
            "--interface=srv-eth0",
            "--port=0",
            "--dhcp-authoritative",
            "--dhcp-range=10.77.0.20,10.77.0.50,255.255.255.0,12h",
            f"--dhcp-option=3,{SERVER_IP}",
            f"--dhcp-option=6,{SERVER_IP}",
        ]
    )
    httpd = srv.popen(
        [
            "python3",
            "-m",
            "http.server",
            str(SERVER_PORT),
            "--bind",
            SERVER_IP,
        ]
    )

    try:
        info("*** Lab ready: AP=macstealer-lab, server=10.77.0.1:4444\n")
        if args.run_demo:
            victim_ping = run_macstealer(
                lab, research_dir, client_conf, "--ping"
            )
            attacker_ping = run_macstealer(
                lab, research_dir, client_conf, "--ping", "--flip-id"
            )
            attack = run_macstealer(lab, research_dir, client_conf)

            if "everything looks good" not in victim_ping:
                info("*** WARNING: victim sanity check did not pass\n")
            if "everything looks good" not in attacker_ping:
                info("*** WARNING: attacker sanity check did not pass\n")
            if "This means the network is vulnerable" in attack:
                info("*** POSITIVE DEMO CONFIRMED\n")
            else:
                info("*** Positive result not observed; inspect output above\n")

        if args.recording_sequence:
            info("\n*** RECORDING STEP 1: client-isolation control\n")
            isolation = run_macstealer(
                lab,
                research_dir,
                client_conf,
                "--c2c",
                "lab-wlan1",
            )
            if "appears to be disabled" in isolation:
                info("*** CLIENT ISOLATION CONFIRMED\n")
            else:
                info("*** WARNING: client-isolation control was inconclusive\n")

            info("\n*** RECORDING STEP 2: normal same-BSS attack\n")
            attack = run_macstealer(lab, research_dir, client_conf)
            if "This means the network is vulnerable" in attack:
                info("*** POSITIVE NORMAL ATTACK CONFIRMED\n")
            else:
                info("*** Positive result not observed; inspect output above\n")

        if args.cli:
            info(
                "*** For client isolation: lab <research>/venv/bin/python3 "
                "<research>/macstealer.py lab-wlan0 --config <client.conf> "
                "--c2c lab-wlan1\n"
            )
            CLI(net)
    finally:
        httpd.terminate()
        dnsmasq.terminate()
        httpd.wait()
        dnsmasq.wait()
        net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    main()
