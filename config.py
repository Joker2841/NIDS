# config.py

# --- Network Interface Configuration ---
# Description: Define the network interface for packet capture.
# On Windows with WSL, you can often use "eth0" for the WSL interface.
# To find your interface name on WSL/Linux, run the command: ip addr
# Example: INTERFACE = "eth0" or INTERFACE = "enp0s3"
INTERFACE = "eth0"

# --- Logging Configuration ---
# Description: Define the path for the log file where alerts will be stored.
LOG_FILE = "nids_alerts.log"

# --- Detection Engine Configuration ---
# Description: Parameters for the detection rules.

# Port Scan Detection
# The number of unique ports scanned from a single source IP to trigger an alert.
PORT_SCAN_THRESHOLD = 15
# The time window (in seconds) to track port scan attempts.
PORT_SCAN_WINDOW = 10.0