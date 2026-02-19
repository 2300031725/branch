"""Data processing and traffic metrics for network forensics."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


EXPECTED_COLUMNS = [
    "Time",
    "Source IP",
    "Destination IP",
    "Protocol",
    "Packet Size",
    "Source Port",
    "Destination Port",
]


def load_and_clean_data(csv_path: Path) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    missing = [col for col in EXPECTED_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError(f"Missing expected columns: {missing}")

    df = df.dropna(subset=["Time", "Source IP", "Destination IP", "Protocol", "Packet Size"]).copy()
    df["Time"] = pd.to_datetime(df["Time"], errors="coerce")
    df = df.dropna(subset=["Time"]).copy()
    df["Packet Size"] = pd.to_numeric(df["Packet Size"], errors="coerce")
    df = df.dropna(subset=["Packet Size"]).copy()
    df["Packet Size"] = df["Packet Size"].astype(int)
    df = df.sort_values("Time")
    return df


def build_metrics(df: pd.DataFrame) -> dict[str, pd.DataFrame | float]:
    packets_per_ip = df.groupby("Source IP").size().reset_index(name="Packets").sort_values("Packets", ascending=False)

    time_series = (
        df.set_index("Time")
        .resample("1s")
        .size()
        .reset_index(name="Packets Per Second")
    )

    avg_packet_size = float(df["Packet Size"].mean()) if not df.empty else 0.0

    protocol_distribution = (
        df["Protocol"].value_counts().reset_index()
        .rename(columns={"index": "Protocol", "Protocol": "Count"})
    )

    return {
        "packets_per_ip": packets_per_ip,
        "time_series": time_series,
        "avg_packet_size": avg_packet_size,
        "protocol_distribution": protocol_distribution,
    }


def export_processed_data(df: pd.DataFrame, output_csv: Path) -> None:
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_csv, index=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Clean and process captured packet CSV.")
    parser.add_argument("--input", default="dataset/traffic.csv", help="Input CSV")
    parser.add_argument("--output", default="dataset/traffic_cleaned.csv", help="Output cleaned CSV")
    args = parser.parse_args()

    cleaned = load_and_clean_data(Path(args.input))
    export_processed_data(cleaned, Path(args.output))
    metrics = build_metrics(cleaned)

    print(f"Rows cleaned: {len(cleaned)}")
    print(f"Unique source IPs: {cleaned['Source IP'].nunique()}")
    print(f"Average packet size: {metrics['avg_packet_size']:.2f}")
