"""Packet capture utility for network forensics project.

Usage examples:
  python packet_capture.py --count 300 --output dataset/traffic.csv
  python packet_capture.py --count 200 --timeout 30 --iface eth0
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime
from pathlib import Path
from typing import Any

from scapy.all import ICMP, IP, TCP, UDP, sniff  # type: ignore


CSV_HEADERS = ["Time", "Source IP", "Destination IP", "Protocol", "Packet Size", "Source Port", "Destination Port"]


def detect_protocol(packet: Any) -> str:
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def extract_packet_row(packet: Any) -> list[str | int]:
    if not packet.haslayer(IP):
        return []

    proto = detect_protocol(packet)
    src_port = getattr(packet[TCP], "sport", "") if packet.haslayer(TCP) else getattr(packet[UDP], "sport", "") if packet.haslayer(UDP) else ""
    dst_port = getattr(packet[TCP], "dport", "") if packet.haslayer(TCP) else getattr(packet[UDP], "dport", "") if packet.haslayer(UDP) else ""

    return [
        datetime.fromtimestamp(float(packet.time)).isoformat(timespec="seconds"),
        packet[IP].src,
        packet[IP].dst,
        proto,
        len(packet),
        src_port,
        dst_port,
    ]


def capture_packets(count: int, timeout: int, iface: str | None, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", newline="", encoding="utf-8") as file_obj:
        writer = csv.writer(file_obj)
        writer.writerow(CSV_HEADERS)

        def handle_packet(packet: Any) -> None:
            row = extract_packet_row(packet)
            if row:
                writer.writerow(row)

        sniff(prn=handle_packet, store=False, count=count, timeout=timeout, iface=iface)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Capture network packets and export CSV data.")
    parser.add_argument("--count", type=int, default=300, help="Number of packets to capture")
    parser.add_argument("--timeout", type=int, default=60, help="Max sniff duration in seconds")
    parser.add_argument("--iface", default=None, help="Network interface (optional)")
    parser.add_argument("--output", default="dataset/traffic.csv", help="Output CSV path")

    args = parser.parse_args()
    capture_packets(args.count, args.timeout, args.iface, Path(args.output))
    print(f"Packet capture complete. Saved to: {args.output}")
