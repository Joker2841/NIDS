# dashboard.py 

import streamlit as st
import pandas as pd
import requests
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time
from collections import Counter
import streamlit.components.v1 as components

# Configuration
WSL_IP = "172.18.195.55"  # Update this to your WSL IP
API_URL = f"http://{WSL_IP}:5000/api/alerts"

# Page Configuration
st.set_page_config(
    page_title="🛡️ NIDS Real-time Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    .high-severity { border-left-color: #d62728 !important; }
    .medium-severity { border-left-color: #ff7f0e !important; }
    .low-severity { border-left-color: #2ca02c !important; }
    
    .alert-item {
        padding: 0.5rem;
        margin: 0.25rem 0;
        border-radius: 0.25rem;
        border-left: 3px solid;
    }
</style>
""", unsafe_allow_html=True)

# Functions
@st.cache_data(ttl=30)  # Cache for 30 seconds
def fetch_alerts():
    """Fetch alerts from the API with enhanced error handling"""
    try:
        response = requests.get(API_URL, timeout=10)
        response.raise_for_status()
        data = response.json()
        

        if isinstance(data, dict):
            if 'alerts' in data:
                alerts = data['alerts']
            elif 'error' in data:
                st.error(f"API Error: {data['error']}")
                return []
            else:
                st.error("Unexpected API response format")
                return []
        elif isinstance(data, list):
            alerts = data  # Legacy format
        else:
            st.error("Invalid API response type")
            return []
        
        # Validate that alerts are dictionaries
        valid_alerts = []
        for alert in alerts:
            if isinstance(alert, dict):
                valid_alerts.append(alert)
            else:
                st.warning(f"Skipping invalid alert format: {type(alert)}")
        
        return valid_alerts
        
    except requests.exceptions.ConnectionError:
        st.error("❌ Cannot connect to NIDS API. Make sure the API server is running on port 5000.")
        return []
    except requests.exceptions.Timeout:
        st.error("⏱️ API request timed out. The NIDS system might be overloaded.")
        return []
    except requests.exceptions.RequestException as e:
        st.error(f"🌐 Network error: {e}")
        return []
    except ValueError as e:
        st.error(f"📄 Invalid JSON response: {e}")
        return []
    except Exception as e:
        st.error(f"🔥 Unexpected error: {e}")
        return []

def fetch_api_stats():
    """Fetch API statistics if available"""
    try:
        response = requests.get(f"http://{WSL_IP.split(':')[0] if ':' in WSL_IP else WSL_IP}:5000/api/alerts/stats", timeout=5)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return None

def create_severity_chart(alerts):
    """Create pie chart for alert severity distribution"""
    if not alerts:
        fig = go.Figure()
        fig.add_annotation(
            text="No data available",
            xref="paper", yref="paper",
            x=0.5, y=0.5, xanchor='center', yanchor='middle',
            showarrow=False, font_size=16
        )
        fig.update_layout(title="Alert Severity Distribution")
        return fig
    
    severity_counts = Counter([alert.get('severity', 'UNKNOWN') for alert in alerts])
    
    colors = {'HIGH': '#d62728', 'MEDIUM': '#ff7f0e', 'LOW': '#2ca02c', 'UNKNOWN': '#7f7f7f'}
    
    fig = px.pie(
        values=list(severity_counts.values()),
        names=list(severity_counts.keys()),
        title="Alert Severity Distribution",
        color_discrete_map=colors
    )
    fig.update_traces(textposition='inside', textinfo='percent+label')
    fig.update_layout(height=400)
    return fig

def create_attack_types_chart(alerts):
    """Create bar chart for attack types"""
    if not alerts:
        fig = go.Figure()
        fig.add_annotation(
            text="No data available",
            xref="paper", yref="paper",
            x=0.5, y=0.5, xanchor='center', yanchor='middle',
            showarrow=False, font_size=16
        )
        fig.update_layout(title="Attack Types Distribution")
        return fig
    
    attack_counts = Counter([alert.get('alert_type', 'Unknown') for alert in alerts])
    
    # Get top 10 attack types
    top_attacks = dict(attack_counts.most_common(10))
    
    fig = px.bar(
        x=list(top_attacks.keys()),
        y=list(top_attacks.values()),
        title="Attack Types Distribution (Top 10)",
        labels={'x': 'Attack Type', 'y': 'Count'},
        color=list(top_attacks.values()),
        color_continuous_scale='Reds'
    )
    fig.update_layout(xaxis_tickangle=-45, height=400)
    return fig

def create_timeline_chart(alerts):
    """Create timeline chart showing attacks over time"""
    if not alerts:
        fig = go.Figure()
        fig.add_annotation(
            text="No data available",
            xref="paper", yref="paper", 
            x=0.5, y=0.5, xanchor='center', yanchor='middle',
            showarrow=False, font_size=16
        )
        fig.update_layout(title="Attack Timeline (Hourly)")
        return fig
    
    # Convert timestamps to datetime and handle potential errors
    valid_alerts = []
    for alert in alerts:
        try:
            if 'timestamp' in alert and alert['timestamp']:
                timestamp = float(alert['timestamp'])
                alert['datetime'] = datetime.fromtimestamp(timestamp)
                valid_alerts.append(alert)
        except (ValueError, TypeError, OSError):
            continue  # Skip invalid timestamps
    
    if not valid_alerts:
        fig = go.Figure()
        fig.add_annotation(text="No valid timestamp data", showarrow=False)
        fig.update_layout(title="Attack Timeline (Hourly)")
        return fig
    
    df = pd.DataFrame(valid_alerts)
    
    # Group by hour
    df['hour'] = df['datetime'].dt.floor('H')
    hourly_counts = df.groupby(['hour', 'alert_type']).size().reset_index(name='count')
    
    if len(hourly_counts) == 0:
        fig = go.Figure()
        fig.add_annotation(text="No timeline data available", showarrow=False)
        fig.update_layout(title="Attack Timeline (Hourly)")
        return fig
    
    fig = px.bar(
        hourly_counts,
        x='hour',
        y='count',
        color='alert_type',
        title="Attack Timeline (Hourly)",
        labels={'hour': 'Time', 'count': 'Number of Attacks'}
    )
    fig.update_layout(height=400)
    return fig

def create_geolocation_chart(alerts):
    """Create chart showing attack origins"""
    if not alerts:
        fig = go.Figure()
        fig.add_annotation(text="No data available", showarrow=False)
        fig.update_layout(title="Attack Origins by Location")
        return fig
    
    locations = []
    for alert in alerts:
        location = alert.get('location', '')
        if location and location not in ['Private/Internal IP', 'N/A', '']:
            locations.append(location)
    
    if not locations:
        fig = go.Figure()
        fig.add_annotation(text="No geolocation data available", showarrow=False)
        fig.update_layout(title="Attack Origins by Location")
        return fig
    
    location_counts = Counter(locations)
    top_locations = dict(location_counts.most_common(10))
    
    fig = px.bar(
        x=list(top_locations.values()),
        y=list(top_locations.keys()),
        orientation='h',
        title="Attack Origins by Location (Top 10)",
        labels={'x': 'Attack Count', 'y': 'Location'},
        color=list(top_locations.values()),
        color_continuous_scale='Blues'
    )
    fig.update_layout(height=400)
    return fig

def format_alert_severity(severity):
    """Format alert severity with colors"""
    colors = {
        'HIGH': '🔴',
        'MEDIUM': '🟡', 
        'LOW': '🟢'
    }
    return f"{colors.get(severity, '⚪')} {severity}"

def format_timestamp(timestamp):
    """Format timestamp for display"""
    try:
        if isinstance(timestamp, (int, float)):
            dt = datetime.fromtimestamp(float(timestamp))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        return str(timestamp)
    except:
        return "Invalid timestamp"

# Sidebar
st.sidebar.title("🛡️ NIDS Dashboard")
st.sidebar.markdown("---")

# Connection status
try:
    health_response = requests.get(f"http://{WSL_IP.split(':')[0] if ':' in WSL_IP else WSL_IP}:5000/api/health", timeout=3)
    if health_response.status_code == 200:
        st.sidebar.success("🟢 NIDS API Connected")
        health_data = health_response.json()
        st.sidebar.text(f"Queue Size: {health_data.get('queue_size', 'Unknown')}")
    else:
        st.sidebar.error("🔴 API Connection Issues")
except:
    st.sidebar.error("🔴 NIDS API Disconnected")

# Auto-refresh controls
st.sidebar.markdown("### Controls")
auto_refresh = st.sidebar.checkbox("Auto Refresh", value=True)
refresh_interval = st.sidebar.slider("Refresh Interval (seconds)", 5, 60, 10)

# Filters
st.sidebar.markdown("### Filters")
severity_filter = st.sidebar.multiselect(
    "Filter by Severity",
    options=['HIGH', 'MEDIUM', 'LOW'],
    default=['HIGH', 'MEDIUM', 'LOW']
)

time_range = st.sidebar.selectbox(
    "Time Range",
    options=['Last 1 Hour', 'Last 6 Hours', 'Last 24 Hours', 'All Time'],
    index=2
)

# Manual refresh button
if st.sidebar.button("🔄 Refresh Now"):
    st.cache_data.clear()

# Main Dashboard
st.title("🛡️ Real-time Network Intrusion Detection Dashboard")

# Fetch and process data
with st.spinner("Loading alerts..."):
    alerts = fetch_alerts()

# Validate alerts data
if not isinstance(alerts, list):
    st.error("Invalid alerts data received from API")
    alerts = []

# Apply filters
if alerts:
    # Filter by severity
    alerts = [alert for alert in alerts if isinstance(alert, dict) and alert.get('severity') in severity_filter]
    
    # Filter by time range
    if time_range != 'All Time':
        now = datetime.now()
        if time_range == 'Last 1 Hour':
            cutoff = now - timedelta(hours=1)
        elif time_range == 'Last 6 Hours':
            cutoff = now - timedelta(hours=6)
        elif time_range == 'Last 24 Hours':
            cutoff = now - timedelta(hours=24)
        
        filtered_alerts = []
        for alert in alerts:
            try:
                if alert.get('timestamp'):
                    alert_time = datetime.fromtimestamp(float(alert['timestamp']))
                    if alert_time > cutoff:
                        filtered_alerts.append(alert)
            except (ValueError, TypeError, OSError):
                continue  # Skip alerts with invalid timestamps
        alerts = filtered_alerts

# Key Metrics
col1, col2, col3, col4 = st.columns(4)

with col1:
    total_alerts = len(alerts)
    st.metric(
        label="🚨 Total Alerts",
        value=total_alerts,
        delta=f"in {time_range.lower()}"
    )

with col2:
    unique_attackers = len(set(alert.get('source_ip', '') for alert in alerts if alert.get('source_ip')))
    st.metric(
        label="👤 Unique Attackers",
        value=unique_attackers
    )

with col3:
    high_severity = len([a for a in alerts if a.get('severity') == 'HIGH'])
    st.metric(
        label="🔴 High Severity",
        value=high_severity,
        delta="Critical" if high_severity > 0 else None
    )

with col4:
    if alerts:
        try:
            latest_attack = max(alerts, key=lambda x: float(x.get('timestamp', 0)))
            time_since_last = datetime.now() - datetime.fromtimestamp(float(latest_attack.get('timestamp', 0)))
            mins_ago = int(time_since_last.total_seconds() / 60)
            st.metric(
                label="⏰ Last Attack",
                value=f"{mins_ago}m ago" if mins_ago < 60 else f"{int(mins_ago/60)}h ago"
            )
        except:
            st.metric(label="⏰ Last Attack", value="Unknown")
    else:
        st.metric(label="⏰ Last Attack", value="None")

st.markdown("---")

if alerts:
    # Charts Section
    st.subheader("📊 Alert Analytics")
    
    chart_col1, chart_col2 = st.columns(2)
    
    with chart_col1:
        severity_fig = create_severity_chart(alerts)
        st.plotly_chart(severity_fig, use_container_width=True)
        
        attack_types_fig = create_attack_types_chart(alerts)
        st.plotly_chart(attack_types_fig, use_container_width=True)
    
    with chart_col2:
        timeline_fig = create_timeline_chart(alerts)
        st.plotly_chart(timeline_fig, use_container_width=True)
        
        geo_fig = create_geolocation_chart(alerts)
        st.plotly_chart(geo_fig, use_container_width=True)
    
    st.markdown("---")
    
    # Recent Alerts Table
    st.subheader("🚨 Recent Alerts")
    
    # Create DataFrame for better display
    display_data = []
    for alert in sorted(alerts, key=lambda x: float(x.get('timestamp', 0)), reverse=True)[:50]:
        display_data.append({
            'Time': format_timestamp(alert.get('timestamp')),
            'Severity': format_alert_severity(alert.get('severity', 'UNKNOWN')),
            'Attack Type': alert.get('alert_type', 'Unknown'),
            'Source IP': alert.get('source_ip', 'N/A'),
            'Target IP': alert.get('destination_ip', 'N/A'),
            'Location': alert.get('location', 'N/A')[:30] + '...' if len(alert.get('location', '')) > 30 else alert.get('location', 'N/A'),
            'Summary': alert.get('summary', 'N/A')[:50] + '...' if len(alert.get('summary', '')) > 50 else alert.get('summary', 'N/A')
        })
    
    if display_data:
        df_display = pd.DataFrame(display_data)
        st.dataframe(df_display, use_container_width=True, height=400)
    
    # Top Attackers
    st.subheader("🎯 Top Attackers")
    attacker_counts = Counter([
        alert.get('source_ip', 'Unknown') 
        for alert in alerts 
        if alert.get('source_ip') and alert.get('source_ip') not in ['N/A', '']
    ])
    
    if attacker_counts:
        top_attackers = attacker_counts.most_common(10)
        attacker_df = pd.DataFrame(top_attackers, columns=['IP Address', 'Attack Count'])
        st.dataframe(attacker_df, use_container_width=True)

else:
    st.info("🔍 No alerts detected yet. The system is monitoring your network...")
    st.markdown("""
    ### What we're monitoring for:
    - 🔍 **Port Scanning** - Unauthorized reconnaissance
    - 🌊 **SYN Flood Attacks** - DoS attempts
    - 🔄 **ARP Spoofing** - Man-in-the-middle attacks  
    - 📡 **ICMP Floods** - Ping flood attacks
    - 🎯 **LAND Attacks** - Malformed packet attacks
    - 🔍 **DNS Anomalies** - Suspicious DNS activity
    - 🚫 **TCP Scans** - NULL, XMAS, and FIN scans
    """)

# Auto-refresh functionality
if auto_refresh and st.session_state.get('auto_refresh_enabled', True):
    time.sleep(refresh_interval)
    st.rerun()

# Footer
st.markdown("---")
st.markdown(
    f"🛡️ **Network Intrusion Detection System** | "
    f"Built with Python, Scapy, and Streamlit | "
    f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
)