"""Suspicious activity detection module (rule-based + ML anomaly detection)."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest


def rule_based_detection(df: pd.DataFrame, ddos_threshold_per_minute: int = 100, port_scan_threshold: int = 20) -> pd.DataFrame:
    records: list[dict[str, str | int]] = []

    per_minute = (
        df.set_index("Time")
        .groupby("Source IP")
        .resample("1min")
        .size()
        .reset_index(name="Packet Count")
    )
    ddos_hits = per_minute[per_minute["Packet Count"] >= ddos_threshold_per_minute]
    for _, row in ddos_hits.iterrows():
        records.append(
            {
                "IP": row["Source IP"],
                "Attack Type": "Potential DDoS",
                "Timestamp": str(row["Time"]),
                "Details": f"{int(row['Packet Count'])} packets/minute",
            }
        )

    if "Destination Port" in df.columns:
        port_scan = (
            df.set_index("Time")
            .groupby("Source IP")
            .resample("1min")["Destination Port"]
            .nunique()
            .reset_index(name="Unique Destination Ports")
        )
        scan_hits = port_scan[port_scan["Unique Destination Ports"] >= port_scan_threshold]
        for _, row in scan_hits.iterrows():
            records.append(
                {
                    "IP": row["Source IP"],
                    "Attack Type": "Potential Port Scan",
                    "Timestamp": str(row["Time"]),
                    "Details": f"{int(row['Unique Destination Ports'])} ports/minute",
                }
            )

    traffic_per_second = (
        df.set_index("Time")
        .resample("1s")
        .size()
        .reset_index(name="Packets Per Second")
    )
    if not traffic_per_second.empty:
        threshold = traffic_per_second["Packets Per Second"].mean() + 3 * traffic_per_second["Packets Per Second"].std(ddof=0)
        spike_hits = traffic_per_second[traffic_per_second["Packets Per Second"] > threshold]
        for _, row in spike_hits.iterrows():
            records.append(
                {
                    "IP": "MULTIPLE",
                    "Attack Type": "Traffic Spike",
                    "Timestamp": str(row["Time"]),
                    "Details": f"{int(row['Packets Per Second'])} packets/second",
                }
            )

    return pd.DataFrame(records).drop_duplicates()


def ml_anomaly_detection(df: pd.DataFrame, contamination: float = 0.05) -> pd.DataFrame:
    if len(df) < 20:
        return pd.DataFrame(columns=["Time", "Source IP", "Packet Size", "Anomaly Score", "Label"])

    temp = df.copy()
    temp = temp.sort_values("Time")
    temp["Time Delta"] = temp["Time"].diff().dt.total_seconds().fillna(0.0)

    features = temp[["Packet Size", "Time Delta"]].fillna(0.0)
    model = IsolationForest(contamination=contamination, random_state=42)
    model.fit(features)

    temp["Label"] = model.predict(features)
    temp["Anomaly Score"] = model.decision_function(features)

    anomalies = temp[temp["Label"] == -1][["Time", "Source IP", "Packet Size", "Anomaly Score", "Label"]]
    return anomalies


def save_suspicious_activity(suspicious_df: pd.DataFrame, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    suspicious_df.to_csv(output_path, index=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run suspicious activity detection.")
    parser.add_argument("--input", default="dataset/traffic_cleaned.csv", help="Input cleaned CSV")
    parser.add_argument("--output", default="reports/suspicious_activity.csv", help="Output suspicious CSV")
    parser.add_argument("--mode", choices=["rule", "ml"], default="rule", help="Detection mode")
    args = parser.parse_args()

    df = pd.read_csv(args.input)
    df["Time"] = pd.to_datetime(df["Time"], errors="coerce")
    df = df.dropna(subset=["Time"]) 

    suspicious = rule_based_detection(df) if args.mode == "rule" else ml_anomaly_detection(df)
    save_suspicious_activity(suspicious, Path(args.output))

    print(f"Detection mode: {args.mode}")
    print(f"Suspicious records: {len(suspicious)}")
    print(f"Saved to: {args.output}")
