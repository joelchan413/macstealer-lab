#!/usr/bin/env python3
"""Generate or receive measured UDP background traffic for loaded trials."""

from __future__ import annotations

import argparse
import json
import signal
import socket
import time
from pathlib import Path


STOP = False


def request_stop(_signum, _frame):
    global STOP
    STOP = True


def write_snapshot(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def metrics(mode, started_ns, packets, payload_bytes, target_mbps=None, status="running"):
    now_ns = time.monotonic_ns()
    elapsed = max((now_ns - started_ns) / 1e9, 1e-9)
    return {
        "mode": mode,
        "status": status,
        "started_ns": started_ns,
        "updated_ns": now_ns,
        "elapsed_seconds": elapsed,
        "packets": packets,
        "payload_bytes": payload_bytes,
        "achieved_mbps": payload_bytes * 8 / elapsed / 1_000_000,
        "target_mbps": target_mbps,
    }


def run_sender(args) -> int:
    if not args.target:
        raise ValueError("sender requires at least one --target")
    if args.aggregate_mbps <= 0 or args.payload_bytes <= 0:
        raise ValueError("aggregate rate and payload size must be positive")

    packets_per_second = args.aggregate_mbps * 1_000_000 / (args.payload_bytes * 8)
    interval_ns = max(1, int(1_000_000_000 / packets_per_second))
    started_ns = time.monotonic_ns()
    end_ns = started_ns + int(args.duration * 1e9)
    next_ns = started_ns
    next_snapshot_ns = started_ns
    packets = 0
    payload_bytes = 0
    payload = b"B" * args.payload_bytes
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        while not STOP and next_ns < end_ns:
            now_ns = time.monotonic_ns()
            if now_ns < next_ns:
                time.sleep((next_ns - now_ns) / 1e9)
            target = args.target[packets % len(args.target)]
            sock.sendto(payload, (target, args.port))
            packets += 1
            payload_bytes += len(payload)
            next_ns += interval_ns
            if time.monotonic_ns() >= next_snapshot_ns:
                write_snapshot(
                    args.output,
                    metrics(
                        "sender",
                        started_ns,
                        packets,
                        payload_bytes,
                        target_mbps=args.aggregate_mbps,
                    ),
                )
                next_snapshot_ns = time.monotonic_ns() + 500_000_000
    finally:
        sock.close()
        write_snapshot(
            args.output,
            metrics(
                "sender",
                started_ns,
                packets,
                payload_bytes,
                target_mbps=args.aggregate_mbps,
                status="stopped" if STOP else "completed",
            ),
        )
    return 0


def run_sink(args) -> int:
    started_ns = time.monotonic_ns()
    end_ns = started_ns + int(args.duration * 1e9)
    next_snapshot_ns = started_ns
    packets = 0
    payload_bytes = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    sock.settimeout(0.25)

    try:
        while not STOP and time.monotonic_ns() < end_ns:
            try:
                payload, _peer = sock.recvfrom(65535)
            except socket.timeout:
                payload = None
            if payload is not None:
                packets += 1
                payload_bytes += len(payload)
            if time.monotonic_ns() >= next_snapshot_ns:
                write_snapshot(
                    args.output,
                    metrics("sink", started_ns, packets, payload_bytes),
                )
                next_snapshot_ns = time.monotonic_ns() + 500_000_000
    finally:
        sock.close()
        write_snapshot(
            args.output,
            metrics(
                "sink",
                started_ns,
                packets,
                payload_bytes,
                status="stopped" if STOP else "completed",
            ),
        )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)

    sender = subparsers.add_parser("sender")
    sender.add_argument("--target", action="append", required=True)
    sender.add_argument("--port", type=int, default=6000)
    sender.add_argument("--aggregate-mbps", type=float, required=True)
    sender.add_argument("--payload-bytes", type=int, default=1200)
    sender.add_argument("--duration", type=float, default=60.0)
    sender.add_argument("--output", type=Path, required=True)

    sink = subparsers.add_parser("sink")
    sink.add_argument("--bind", default="0.0.0.0")
    sink.add_argument("--port", type=int, default=6000)
    sink.add_argument("--duration", type=float, default=60.0)
    sink.add_argument("--output", type=Path, required=True)

    args = parser.parse_args()
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    if args.mode == "sender":
        return run_sender(args)
    return run_sink(args)


if __name__ == "__main__":
    raise SystemExit(main())
