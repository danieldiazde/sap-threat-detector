"""
app.py
------
Streamlit real-time dashboard for the SAP AI Security SOC.

Owner: Security Analyst & Visualization Lead

Run: make dashboard
     OR: streamlit run src/dashboard/app.py
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# ─── Page Config ───────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SAP AI Security SOC",
    page_icon="🛡️",
    layout="wide",
)

# ─── Header ────────────────────────────────────────────────────────────────
st.title("🛡️ SAP AI Security — Live SOC Dashboard")
st.markdown("**OBSERVE → ANALYZE → DETECT → RESPOND**")
st.markdown(f"Last updated: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`")

st.divider()

# ─── KPI Metrics ───────────────────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("🔴 Active Threats", "—", help="Anomalies detected in current window")
with col2:
    st.metric("⚡ MTTD (seconds)", "—", help="Mean Time to Detect")
with col3:
    st.metric("📋 Logs Processed", "—", help="Total logs ingested this session")
with col4:
    st.metric("✅ Alerts Sent", "—", help="Webhook alerts fired to SAP")

st.divider()

# ─── Anomaly Timeline ──────────────────────────────────────────────────────
st.subheader("📈 Request Volume & Anomaly Timeline")

# TODO: Replace with live data from the pipeline
st.info("⏳ Waiting for data pipeline to connect. Start the pipeline with `make run`.")

# Placeholder chart — will be replaced with live data
placeholder_df = pd.DataFrame({
    "time":     pd.date_range("2026-04-04 14:00", periods=60, freq="1min"),
    "requests": [100] * 55 + [3500, 3200, 2800, 200, 100],
    "anomaly":  [False] * 55 + [True, True, True, False, False],
})

fig = px.line(
    placeholder_df, x="time", y="requests",
    title="Requests per Minute (sample data)",
    color_discrete_sequence=["#0070f3"],
)

# Highlight anomaly points
anomalies = placeholder_df[placeholder_df["anomaly"]]
fig.add_scatter(
    x=anomalies["time"], y=anomalies["requests"],
    mode="markers", marker=dict(color="red", size=10, symbol="x"),
    name="🚨 Anomaly",
)
st.plotly_chart(fig, use_container_width=True)

st.divider()

# ─── Active Threats Table ──────────────────────────────────────────────────
st.subheader("🚨 Active Threats")
st.info("No active threats detected. Connect the pipeline to see live data.")

# TODO: Replace with live anomaly DataFrame from predict.py
example_threat = pd.DataFrame([{
    "source_ip":     "203.0.113.45",
    "threat_level":  "HIGH",
    "anomaly_score": -0.42,
    "total_requests": 3500,
    "error_rate":    0.87,
    "detected_at":   "2026-04-04 14:49:30",
}])
st.dataframe(example_threat, use_container_width=True)

st.divider()

# ─── Log Feed ──────────────────────────────────────────────────────────────
st.subheader("📄 Recent Log Feed")

# TODO: Replace with live log stream
sample_logs = pd.read_csv("data/samples/sample_logs.csv")
st.dataframe(sample_logs.tail(20), use_container_width=True)
