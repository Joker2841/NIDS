# database.py

import sqlite3
import json
import threading
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

class AlertDatabase:
    def __init__(self, db_path="nids.db"):
        self.db_path = db_path
        self.lock = threading.Lock()  # Thread safety
        self.init_database()
        print(f"[*] Database initialized: {db_path}")
    
    def init_database(self):
        """Initialize the database schema"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        alert_type TEXT NOT NULL,
                        source_ip TEXT,
                        destination_ip TEXT,
                        severity TEXT NOT NULL,
                        location TEXT,
                        summary TEXT,
                        extra_data TEXT,
                        acknowledged BOOLEAN DEFAULT FALSE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create indexes for better performance
                conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_alert_type ON alerts(alert_type)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_source_ip ON alerts(source_ip)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity)')
                
                conn.commit()
        except Exception as e:
            print(f"[!] Error initializing database: {e}")
    
    def store_alert(self, alert_data: Dict[Any, Any]):
        """Store a new alert in the database"""
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute('''
                        INSERT INTO alerts 
                        (timestamp, alert_type, source_ip, destination_ip, severity, location, summary, extra_data)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        alert_data.get('timestamp'),
                        alert_data.get('alert_type'),
                        alert_data.get('source_ip', ''),
                        alert_data.get('destination_ip', ''),
                        alert_data.get('severity', 'LOW'),
                        alert_data.get('location', ''),
                        alert_data.get('summary', ''),
                        json.dumps(alert_data.get('extra_data', {})) if alert_data.get('extra_data') else ''
                    ))
                    conn.commit()
        except Exception as e:
            print(f"[!] Error storing alert: {e}")
    
    def get_recent_alerts(self, hours=24, limit=1000) -> List[Dict]:
        """Get recent alerts from the database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cutoff_time = datetime.now() - timedelta(hours=hours)
                
                cursor = conn.execute('''
                    SELECT * FROM alerts 
                    WHERE created_at > ? 
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (cutoff_time, limit))
                
                alerts = []
                for row in cursor.fetchall():
                    alert = dict(row)
                    if alert['extra_data']:
                        try:
                            alert['extra_data'] = json.loads(alert['extra_data'])
                        except json.JSONDecodeError:
                            alert['extra_data'] = {}
                    alerts.append(alert)
                
                return alerts
        except Exception as e:
            print(f"[!] Error retrieving alerts: {e}")
            return []
    
    def get_alert_stats(self) -> Dict[str, Any]:
        """Get alert statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Total alerts
                total_alerts = conn.execute('SELECT COUNT(*) as count FROM alerts').fetchone()['count']
                
                # Alerts by type
                type_stats = conn.execute('''
                    SELECT alert_type, COUNT(*) as count 
                    FROM alerts 
                    GROUP BY alert_type 
                    ORDER BY count DESC
                ''').fetchall()
                
                # Alerts by severity
                severity_stats = conn.execute('''
                    SELECT severity, COUNT(*) as count 
                    FROM alerts 
                    GROUP BY severity 
                    ORDER BY count DESC
                ''').fetchall()
                
                # Top attackers
                top_attackers = conn.execute('''
                    SELECT source_ip, COUNT(*) as count 
                    FROM alerts 
                    WHERE source_ip != '' 
                    GROUP BY source_ip 
                    ORDER BY count DESC 
                    LIMIT 10
                ''').fetchall()
                
                return {
                    'total_alerts': total_alerts,
                    'by_type': [dict(row) for row in type_stats],
                    'by_severity': [dict(row) for row in severity_stats],
                    'top_attackers': [dict(row) for row in top_attackers]
                }
        except Exception as e:
            print(f"[!] Error getting alert stats: {e}")
            return {'total_alerts': 0, 'by_type': [], 'by_severity': [], 'top_attackers': []}
    
    def acknowledge_alert(self, alert_id: int):
        """Mark an alert as acknowledged"""
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute('UPDATE alerts SET acknowledged = TRUE WHERE id = ?', (alert_id,))
                    conn.commit()
        except Exception as e:
            print(f"[!] Error acknowledging alert: {e}")
    
    def cleanup_old_alerts(self, days=30):
        """Remove alerts older than specified days"""
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    cutoff_date = datetime.now() - timedelta(days=days)
                    cursor = conn.execute(
                        'DELETE FROM alerts WHERE created_at < ?', 
                        (cutoff_date,)
                    )
                    deleted_count = cursor.rowcount
                    conn.commit()
                    print(f"[*] Cleaned up {deleted_count} old alerts")
                    return deleted_count
        except Exception as e:
            print(f"[!] Error cleaning up alerts: {e}")
            return 0