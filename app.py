"""Streamlit dashboard for Visual Security Analytics project."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

from data_processing import build_metrics, load_and_clean_data
from detection import ml_anomaly_detection, rule_based_detection


st.set_page_config(page_title="Visual Security Analytics", layout="wide")
st.title("🔐 Visual Security Analytics for Network Forensics")

DATA_PATH = Path("dataset/traffic.csv")

st.sidebar.header("Configuration")
mode = st.sidebar.selectbox("Detection Mode", ["Rule-Based", "ML (Isolation Forest)"])
uploaded = st.sidebar.file_uploader("Upload traffic CSV", type=["csv"])

if uploaded is not None:
    raw_df = pd.read_csv(uploaded)
    temp_path = Path("dataset/uploaded_traffic.csv")
    temp_path.parent.mkdir(parents=True, exist_ok=True)
    raw_df.to_csv(temp_path, index=False)
    data_file = temp_path
else:
    data_file = DATA_PATH

if not data_file.exists():
    st.warning("No dataset found. Run packet_capture.py first or upload a CSV in the sidebar.")
    st.stop()

try:
    df = load_and_clean_data(data_file)
except Exception as exc:
    st.error(f"Failed to load data: {exc}")
    st.stop()

metrics = build_metrics(df)

if mode == "Rule-Based":
    suspicious_df = rule_based_detection(df)
else:
    anomalies = ml_anomaly_detection(df)
    suspicious_df = anomalies.rename(columns={"Source IP": "IP", "Time": "Timestamp"})
    suspicious_df["Attack Type"] = "ML Anomaly"
    suspicious_df["Details"] = "IsolationForest flagged anomalous packet behavior"
    suspicious_df = suspicious_df[["IP", "Attack Type", "Timestamp", "Details"]]

col1, col2, col3 = st.columns(3)
col1.metric("Total Packets", len(df))
col2.metric("Total Unique IPs", df["Source IP"].nunique())
col3.metric("Suspicious IP Count", suspicious_df["IP"].nunique() if not suspicious_df.empty else 0)

left, right = st.columns(2)
with left:
    st.subheader("Protocol Distribution")
    protocol_df = metrics["protocol_distribution"]
    st.plotly_chart(
        {
            "data": [{"labels": protocol_df["Protocol"], "values": protocol_df["Count"], "type": "pie"}],
            "layout": {"height": 350, "margin": {"l": 10, "r": 10, "t": 30, "b": 10}},
        },
        use_container_width=True,
    )

with right:
    st.subheader("Top 10 Source IPs")
    top_ips = metrics["packets_per_ip"].head(10)
    st.bar_chart(top_ips.set_index("Source IP"))

st.subheader("Traffic Over Time")
st.line_chart(metrics["time_series"].set_index("Time")["Packets Per Second"])

st.subheader("Suspicious Activity Table")
st.dataframe(suspicious_df, use_container_width=True)

report_name = "reports/forensic_report.csv"
if st.button("Download Report"):
    Path("reports").mkdir(exist_ok=True)
    suspicious_df.to_csv(report_name, index=False)

if Path(report_name).exists():
    with open(report_name, "rb") as file_obj:
        st.download_button("Download Latest CSV Report", file_obj, file_name="forensic_report.csv", mime="text/csv")
