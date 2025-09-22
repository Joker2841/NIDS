# api.py (Upgraded for WebSockets)

import logging
import os
from queue import Queue
from threading import Thread
from flask import Flask, jsonify
from flask_socketio import SocketIO

# --- Global variables ---
alert_queue = Queue()
alerts_history = []

# Suppress server logs for a cleaner console
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_nids_key!' 
socketio = SocketIO(app, cors_allowed_origins="*")

def _collect_alerts():
    """A worker function that collects alerts and emits them."""
    while True:
        alert = alert_queue.get()
        alerts_history.append(alert)
        socketio.emit('new_alert', alert)

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """API endpoint to get the initial history of alerts."""
    return jsonify(alerts_history)

def run_api_server():
    """Starts the alert collector and the SocketIO server."""
    print("[*] Starting real-time API server...")

    collector_thread = Thread(target=_collect_alerts, daemon=True)
    collector_thread.start()

    socketio.run(app, host='0.0.0.0', port=5000)