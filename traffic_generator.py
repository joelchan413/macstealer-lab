#!/usr/bin/env python3
"""Send a sequence-tagged UDP stream and log every successful send."""

from __future__ import annotations

import argparse
import json
import socket
import time
from pathlib import Path


MAGIC = "MSLAB1"


def build_payload(trial_id: str, sequence: int, send_ns: int, size: int) -> bytes:
    header = f"{MAGIC}|{trial_id}|{sequence}|{send_ns}|".encode()
    if len(header) > size:
        raise ValueError("payload size is too small for the measurement header")
    return header + (b"x" * (size - len(header)))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trial-id", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", type=int, default=5555)
    parser.add_argument("--rate", type=float, default=100.0)
    parser.add_argument("--payload-bytes", type=int, default=1200)
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if args.rate <= 0 or args.duration <= 0:
        parser.error("rate and duration must be positive")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    interval_ns = int(1_000_000_000 / args.rate)
    end_ns = time.monotonic_ns() + int(args.duration * 1_000_000_000)
    next_ns = time.monotonic_ns()
    sequence = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    with args.output.open("w", buffering=1) as log:
        while next_ns < end_ns:
            now_ns = time.monotonic_ns()
            if now_ns < next_ns:
                time.sleep((next_ns - now_ns) / 1_000_000_000)
            send_ns = time.monotonic_ns()
            payload = build_payload(
                args.trial_id, sequence, send_ns, args.payload_bytes
            )
            record = {
                "trial_id": args.trial_id,
                "sequence": sequence,
                "send_ns": send_ns,
                "payload_bytes": len(payload),
                "sent": False,
            }
            try:
                sock.sendto(payload, (args.target, args.port))
                record["sent"] = True
            except OSError as exc:
                record["error"] = str(exc)
            log.write(json.dumps(record, sort_keys=True) + "\n")
            sequence += 1
            next_ns += interval_ns

    sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
