# api.py - Enhanced API with better error handling

import logging
import os
import json
from queue import Queue, Empty
from threading import Thread
from flask import Flask, jsonify, request
from flask_socketio import SocketIO
from flask_cors import CORS

# Global variables
alert_queue = Queue()
alerts_history = []
MAX_HISTORY_SIZE = 1000

# Setup logging
logging.getLogger('werkzeug').setLevel(logging.ERROR)
logging.getLogger('socketio').setLevel(logging.ERROR)
logging.getLogger('engineio').setLevel(logging.ERROR)

# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('NIDS_SECRET_KEY', 'nids_secret_key_2024!')
CORS(app)  # Enable CORS for all routes
socketio = SocketIO(app, cors_allowed_origins="*", logger=False, engineio_logger=False)

def _collect_alerts():
    """Enhanced alert collection with error handling"""
    print("[*] Alert collector started")
    
    while True:
        try:
            # Get alert from queue with timeout
            alert = alert_queue.get(timeout=1)
            
            # Add to history with size management
            alerts_history.append(alert)
            if len(alerts_history) > MAX_HISTORY_SIZE:
                alerts_history.pop(0)  # Remove oldest alert
            
            # Emit to all connected clients
            socketio.emit('new_alert', alert)
            
            # Log high severity alerts
            if alert.get('severity') == 'HIGH':
                print(f"[!] HIGH SEVERITY ALERT: {alert.get('alert_type')} from {alert.get('source_ip')}")
                
        except Empty:
            # Timeout occurred, continue loop
            continue
        except Exception as e:
            logging.error(f"Error in alert collector: {e}")
            continue

@app.route('/api/health', methods=['GET'])
def health_check():
    """API health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'alerts_in_history': len(alerts_history),
        'queue_size': alert_queue.qsize()
    })

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get alerts with optional filtering"""
    try:
        # Get query parameters
        limit = request.args.get('limit', type=int, default=100)
        severity = request.args.get('severity', type=str)
        alert_type = request.args.get('type', type=str)
        
        # Filter alerts
        filtered_alerts = alerts_history.copy()
        
        if severity:
            filtered_alerts = [a for a in filtered_alerts if a.get('severity') == severity.upper()]
        
        if alert_type:
            filtered_alerts = [a for a in filtered_alerts if alert_type.lower() in a.get('alert_type', '').lower()]
        
        # Apply limit
        if limit > 0:
            filtered_alerts = filtered_alerts[-limit:]
        
        return jsonify({
            'alerts': filtered_alerts,
            'total_count': len(filtered_alerts),
            'available_filters': {
                'severities': list(set(a.get('severity') for a in alerts_history if a.get('severity'))),
                'alert_types': list(set(a.get('alert_type') for a in alerts_history if a.get('alert_type')))
            }
        })
        
    except Exception as e:
        logging.error(f"Error in get_alerts: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/alerts/stats', methods=['GET'])
def get_alert_stats():
    """Get alert statistics"""
    try:
        if not alerts_history:
            return jsonify({
                'total_alerts': 0,
                'by_severity': {},
                'by_type': {},
                'unique_sources': 0
            })
        
        # Calculate statistics
        severity_counts = {}
        type_counts = {}
        unique_sources = set()
        
        for alert in alerts_history:
            # Severity stats
            severity = alert.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Type stats
            alert_type = alert.get('alert_type', 'Unknown')
            type_counts[alert_type] = type_counts.get(alert_type, 0) + 1
            
            # Unique sources
            source_ip = alert.get('source_ip')
            if source_ip:
                unique_sources.add(source_ip)
        
        return jsonify({
            'total_alerts': len(alerts_history),
            'by_severity': severity_counts,
            'by_type': type_counts,
            'unique_sources': len(unique_sources),
            'top_sources': dict(sorted(
                [(ip, sum(1 for a in alerts_history if a.get('source_ip') == ip)) 
                 for ip in unique_sources], 
                key=lambda x: x[1], reverse=True)[:10]
            )
        })
        
    except Exception as e:
        logging.error(f"Error in get_alert_stats: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/alerts/clear', methods=['POST'])
def clear_alerts():
    """Clear all alerts (for testing purposes)"""
    try:
        global alerts_history
        cleared_count = len(alerts_history)
        alerts_history = []
        
        # Clear the queue as well
        while not alert_queue.empty():
            try:
                alert_queue.get_nowait()
            except Empty:
                break
        
        socketio.emit('alerts_cleared')
        
        return jsonify({
            'message': f'Cleared {cleared_count} alerts',
            'cleared_count': cleared_count
        })
        
    except Exception as e:
        logging.error(f"Error clearing alerts: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print(f"[*] Client connected to WebSocket")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print(f"[*] Client disconnected from WebSocket")

@socketio.on('get_recent_alerts')
def handle_get_recent_alerts(data):
    """Handle request for recent alerts"""
    try:
        count = data.get('count', 10) if data else 10
        recent_alerts = alerts_history[-count:] if len(alerts_history) > count else alerts_history
        socketio.emit('recent_alerts', recent_alerts)
    except Exception as e:
        logging.error(f"Error handling get_recent_alerts: {e}")

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

def run_api_server():
    """Start the API server with enhanced configuration"""
    print("[*] Starting enhanced API server...")
    print("[*] API endpoints available:")
    print("    GET  /api/health        - Health check")
    print("    GET  /api/alerts        - Get alerts (with optional filters)")
    print("    GET  /api/alerts/stats  - Get alert statistics")
    print("    POST /api/alerts/clear  - Clear all alerts")
    
    # Start alert collector thread
    collector_thread = Thread(target=_collect_alerts, daemon=True)
    collector_thread.start()
    
    try:
        # Run with production-ready settings
        socketio.run(
            app, 
            host='0.0.0.0', 
            port=5000, 
            debug=False,
            use_reloader=False,
            log_output=False
        )
    except Exception as e:
        logging.error(f"Error starting API server: {e}")
        raise

if __name__ == '__main__':
    # For testing the API standalone
    run_api_server()