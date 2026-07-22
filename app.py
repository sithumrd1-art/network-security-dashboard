from pathlib import Path
import base64

import joblib
import pandas as pd
import streamlit as st


st.set_page_config(
    page_title="Network Security Dashboard",
    page_icon="🛡️",
    layout="wide",
)
def set_background(image_path):
    with open(image_path, "rb") as image_file:
        encoded_image = base64.b64encode(
            image_file.read()
        ).decode()

    st.markdown(
        f"""
        <style>
        .stApp {{
            background-image:
                linear-gradient(
                    rgba(7, 17, 31, 0.88),
                    rgba(7, 17, 31, 0.88)
                ),
                url("data:image/jpeg;base64,{encoded_image}");

            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
            background-attachment: fixed;
        }}

        [data-testid="stSidebar"] {{
            background-color: rgba(16, 30, 48, 0.94);
        }}

        [data-testid="stHeader"] {{
            background-color: transparent;
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


set_background("images/background.jpg")

st.markdown(
    """
    <style>
    [data-testid="stMetric"] {
        background: rgba(10, 25, 45, 0.88);
        border: 1px solid rgba(0, 194, 255, 0.45);
        padding: 18px;
        border-radius: 14px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
    }

    [data-testid="stMetricLabel"] {
        color: #B9DDF2;
        font-size: 15px;
    }

    [data-testid="stMetricValue"] {
        color: #FFFFFF;
        font-weight: 700;
    }

    h1, h2, h3 {
        text-shadow: 0 3px 10px rgba(0, 0, 0, 0.8);
    }

    .stDataFrame {
        background: rgba(7, 17, 31, 0.85);
        border-radius: 12px;
        padding: 5px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🛡️ AI-Based Network Security Dashboard")
st.write("Network traffic monitoring and security analysis")

# -----------------------------
# Sidebar - CSV Upload
# -----------------------------
st.sidebar.header("⚙️ Dashboard Controls")

uploaded_file = st.sidebar.file_uploader(
    "Upload Network CSV File",
    type=["csv"],
)

default_file = Path("data/network_logs.csv")

try:
    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        data_source = uploaded_file.name
    else:
        if not default_file.exists():
            st.error("Default network dataset was not found.")
            st.stop()

        df = pd.read_csv(default_file)
        data_source = "network_logs.csv"

except Exception as error:
    st.error(f"CSV file could not be opened: {error}")
    st.stop()

# -----------------------------
# Validate Required Columns
# -----------------------------
required_columns = {
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "bytes",
    "status",
}

missing_columns = required_columns - set(df.columns)

if missing_columns:
    st.error(
        "Missing required columns: "
        + ", ".join(sorted(missing_columns))
    )
    st.stop()

# -----------------------------
# Data Cleaning
# -----------------------------
df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    errors="coerce",
)

df["bytes"] = pd.to_numeric(
    df["bytes"],
    errors="coerce",
)

df["protocol"] = (
    df["protocol"]
    .astype(str)
    .str.strip()
    .str.upper()
)

df["status"] = (
    df["status"]
    .astype(str)
    .str.strip()
    .str.title()
)

df = df.dropna(
    subset=[
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "bytes",
        "status",
    ]
)

# -----------------------------
# Sidebar Filters
# -----------------------------
protocol_options = sorted(df["protocol"].unique())
status_options = sorted(df["status"].unique())

selected_protocols = st.sidebar.multiselect(
    "Select Protocol",
    options=protocol_options,
    default=protocol_options,
)

selected_statuses = st.sidebar.multiselect(
    "Select Traffic Status",
    options=status_options,
    default=status_options,
)

filtered_df = df[
    df["protocol"].isin(selected_protocols)
    & df["status"].isin(selected_statuses)
].copy()

st.sidebar.info(f"Data source: {data_source}")

if filtered_df.empty:
    st.warning("No records match the selected filters.")
    st.stop()

# -----------------------------
# Dashboard Metrics
# -----------------------------
total_records = len(filtered_df)

normal_traffic = len(
    filtered_df[filtered_df["status"] == "Normal"]
)

attack_traffic = len(
    filtered_df[filtered_df["status"] == "Attack"]
)

total_bytes = filtered_df["bytes"].sum()

top_source_ip = filtered_df["source_ip"].mode().iloc[0]

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Total Records", total_records)
col2.metric("Normal Traffic", normal_traffic)
col3.metric("Detected Attacks", attack_traffic)
col4.metric("Total Bytes", f"{total_bytes:,.0f}")
col5.metric("Top Source IP", top_source_ip)

# -----------------------------
# Security Risk Overview
# -----------------------------
attack_rate = (
    attack_traffic / total_records * 100
    if total_records > 0
    else 0
)

st.subheader("🛡️ Security Risk Overview")

risk_col1, risk_col2 = st.columns([1, 3])

with risk_col1:
    st.metric(
        "Attack Rate",
        f"{attack_rate:.1f}%"
    )

with risk_col2:
    if attack_rate >= 40:
        st.error("🔴 High Risk — Immediate investigation is recommended.")
    elif attack_rate >= 20:
        st.warning("🟠 Medium Risk — Suspicious traffic was detected.")
    else:
        st.success("🟢 Low Risk — Network traffic appears mostly safe.")

    st.progress(
        min(attack_rate / 100, 1.0)
    )

# -----------------------------
# Network Records
# -----------------------------
st.subheader("📋 Network Traffic Records")

st.dataframe(
    filtered_df,
    width="stretch",
    hide_index=True,
)

# -----------------------------
# Charts
# -----------------------------
st.divider()
st.subheader("📊 Network Traffic Analysis")

protocol_counts = (
    filtered_df["protocol"]
    .value_counts()
    .rename_axis("Protocol")
    .reset_index(name="Count")
)

status_counts = (
    filtered_df["status"]
    .value_counts()
    .rename_axis("Status")
    .reset_index(name="Count")
)

chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.write("### Protocol Distribution")

    st.bar_chart(
        protocol_counts,
        x="Protocol",
        y="Count",
    )

with chart_col2:
    st.write("### Traffic Status")

    st.bar_chart(
        status_counts,
        x="Status",
        y="Count",
    )

st.write("### Network Traffic Over Time")

traffic_over_time = (
    filtered_df[["timestamp", "bytes"]]
    .sort_values("timestamp")
    .set_index("timestamp")
)

st.line_chart(traffic_over_time)

# -----------------------------
# Attack Records
# -----------------------------
st.divider()
st.subheader("🚨 Detected Attack Records")

attack_records = filtered_df[
    filtered_df["status"] == "Attack"
]

if attack_records.empty:
    st.success("No attack records found in the selected data.")
else:
    st.dataframe(
        attack_records,
        width="stretch",
        hide_index=True,
    )

    # -----------------------------
# Top Threat Sources
# -----------------------------
st.divider()
st.subheader("🎯 Top Threat Sources")

if attack_records.empty:
    st.success("No threat sources were detected.")

else:
    top_attack_ips = (
        attack_records.groupby("source_ip")
        .agg(
            attack_count=("source_ip", "count"),
            total_bytes=("bytes", "sum"),
        )
        .reset_index()
        .sort_values(
            by=["attack_count", "total_bytes"],
            ascending=[False, False],
        )
    )

    threat_col1, threat_col2 = st.columns(2)

    with threat_col1:
        st.write("### Suspicious Source IP Addresses")

        st.dataframe(
            top_attack_ips,
            width="stretch",
            hide_index=True,
        )

    with threat_col2:
        st.write("### Attacks by Source IP")

        st.bar_chart(
            top_attack_ips,
            x="source_ip",
            y="attack_count",
        )

    most_dangerous_ip = top_attack_ips.iloc[0]["source_ip"]
    highest_attack_count = top_attack_ips.iloc[0]["attack_count"]
    highest_attack_bytes = top_attack_ips.iloc[0]["total_bytes"]

    st.error(
        f"⚠️ Highest Threat IP: {most_dangerous_ip} "
        f"— {highest_attack_count} detected attacks "
        f"with {highest_attack_bytes:,.0f} bytes of suspicious traffic"
    )

    # -----------------------------
# Download Reports
# -----------------------------
st.divider()
st.subheader("📥 Download Security Reports")

attack_rate = (
    len(attack_records) / len(filtered_df) * 100
    if len(filtered_df) > 0
    else 0
)

summary_report = f"""
AI-Based Network Security Dashboard Report

Total Records: {len(filtered_df)}
Normal Traffic: {len(filtered_df[filtered_df["status"] == "Normal"])}
Detected Attacks: {len(attack_records)}
Attack Rate: {attack_rate:.2f}%
Total Bytes: {filtered_df["bytes"].sum():,.0f}
Top Source IP: {filtered_df["source_ip"].mode().iloc[0]}
"""

csv_report = filtered_df.to_csv(index=False)

download_col1, download_col2 = st.columns(2)

with download_col1:
    st.download_button(
        label="📊 Download Filtered CSV Report",
        data=csv_report,
        file_name="network_security_report.csv",
        mime="text/csv",
        width="stretch",
    )

with download_col2:
    st.download_button(
        label="📄 Download Summary Report",
        data=summary_report,
        file_name="network_security_summary.txt",
        mime="text/plain",
        width="stretch",
    )
    # -----------------------------
# AI Attack Prediction
# -----------------------------
st.divider()
st.subheader("🤖 AI Network Attack Prediction")

model_file = Path("models/network_attack_model.joblib")


@st.cache_resource
def load_model():
    return joblib.load(model_file)


if not model_file.exists():
    st.warning(
        "AI model was not found. Run 'python model.py' first."
    )
else:
    prediction_model = load_model()

    prediction_col1, prediction_col2, prediction_col3 = st.columns(3)

    with prediction_col1:
        input_protocol = st.selectbox(
            "Network Protocol",
            options=["TCP", "UDP", "ICMP"],
        )

    with prediction_col2:
        input_bytes = st.number_input(
            "Traffic Size in Bytes",
            min_value=0,
            value=1000,
            step=100,
        )

    with prediction_col3:
        input_hour = st.number_input(
            "Traffic Hour",
            min_value=0,
            max_value=23,
            value=12,
            step=1,
        )

    if st.button(
        "Analyze Network Traffic",
        type="primary",
        width="stretch",
    ):
        prediction_data = pd.DataFrame(
            {
                "protocol": [input_protocol],
                "bytes": [input_bytes],
                "hour": [input_hour],
            }
        )

        prediction = prediction_model.predict(
            prediction_data
        )[0]

        probabilities = prediction_model.predict_proba(
            prediction_data
        )[0]

        confidence = max(probabilities) * 100

        if prediction == 1:
            st.error(
                f"🚨 Attack Detected — Confidence: {confidence:.2f}%"
            )

            st.warning(
                "This traffic pattern should be investigated."
            )
        else:
            st.success(
                f"✅ Normal Traffic — Confidence: {confidence:.2f}%"
            )

            st.info(
                "No suspicious network activity was detected."
            )