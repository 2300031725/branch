# Visual Security Analytics for Network Forensics

This project captures network packets, processes traffic data, detects suspicious behavior, and visualizes forensic insights in a Streamlit dashboard.

## Project Structure

```
Network-Forensics-Project/
├── packet_capture.py
├── data_processing.py
├── detection.py
├── app.py
├── reports/
├── dataset/
└── requirements.txt
```

## Setup

```bash
pip install -r requirements.txt
```

## Phase Workflow

1. **Capture packets**
   ```bash
   python packet_capture.py --count 300 --output dataset/traffic.csv
   ```
2. **Process traffic data**
   ```bash
   python data_processing.py --input dataset/traffic.csv --output dataset/traffic_cleaned.csv
   ```
3. **Run detection module**
   ```bash
   python detection.py --input dataset/traffic_cleaned.csv --output reports/suspicious_activity.csv --mode rule
   ```
4. **Start dashboard**
   ```bash
   streamlit run app.py
   ```

## Dashboard Features

- Traffic overview (total packets, unique IPs, suspicious IP count)
- Protocol distribution chart
- Top 10 source IPs
- Traffic over time
- Suspicious activity table
- Downloadable forensic report (CSV)

## Notes

- Rule-based detections include potential DDoS, port-scan, and traffic spikes.
- ML mode uses Isolation Forest for anomaly detection.
- You can test suspicious detection by simulating scans (e.g., Nmap) or burst traffic.
