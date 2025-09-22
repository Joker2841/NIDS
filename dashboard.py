# dashboard.py (Upgraded for Real-time Updates)

import streamlit as st
import pandas as pd
import requests
from datetime import datetime
import streamlit.components.v1 as components

WSL_IP = "172.22.208.236"
API_URL = f"http://{WSL_IP}:5000/api/alerts"

# --- Page Setup ---
st.set_page_config(
    page_title="Real-time NIDS Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# --- WebSocket Component ---
# This HTML/JS component connects to the WebSocket and sends new alerts back to Streamlit
websocket_component = components.declare_component(
    "websocket_component",
    url=f"http://{WSL_IP}:5000" 
)


# --- Functions ---
def fetch_initial_alerts():
    """Fetches the alert history when the dashboard first loads."""
    try:
        response = requests.get(API_URL)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException:
        return []

# --- Main Dashboard UI ---
st.title("🛡️ Real-time Network Intrusion Detection Dashboard")

# Initialize session state to store alerts if it doesn't exist
if 'alerts' not in st.session_state:
    st.session_state.alerts = fetch_initial_alerts()

# Create a placeholder for our metrics and table
placeholder = st.empty()

new_alert_data = websocket_component(key="websocket")

if new_alert_data:
    st.session_state.alerts.append(new_alert_data)

with placeholder.container():
    # --- Metrics ---
    total_alerts = len(st.session_state.alerts)
    unique_attackers = len(set(alert.get('source_ip') for alert in st.session_state.alerts))
    
    kpi1, kpi2 = st.columns(2)
    kpi1.metric(label="Total Alerts 🚨", value=total_alerts)
    kpi2.metric(label="Unique Attacker IPs 👤", value=unique_attackers)

    # --- Data Table ---
    if st.session_state.alerts:
        df = pd.DataFrame(st.session_state.alerts)
        df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s').dt.strftime('%Y-%m-%d %H:%M:%S')
        display_columns = ['timestamp', 'alert_type', 'source_ip', 'destination_ip', 'location', 'summary']
        df_display = df[[col for col in display_columns if col in df]]
        
        st.dataframe(df_display.sort_values(by="timestamp", ascending=False), width='stretch')
    else:
        st.info("No alerts detected yet. Waiting for data...")

st.write("Live connection established. New alerts will appear automatically.")