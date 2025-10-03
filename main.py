# main.py

import time
import logging
import argparse
import json
import sys
import signal
from queue import Queue
from threading import Thread

from sniffer import PacketSniffer
from detection import DetectionEngine
from api import run_api_server

class JsonFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    def format(self, record):
        log_object = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.name
        }
        if hasattr(record, 'extra_data'):
            log_object.update(record.extra_data)
        return json.dumps(log_object)

class Config:
    """Configuration management class"""
    def __init__(self, interface, log_file):
        self.INTERFACE = self._validate_interface(interface)
        self.LOG_FILE = self._validate_log_file(log_file)
        print(f"[*] Configuration loaded - Interface: {self.INTERFACE}, Log: {self.LOG_FILE}")
    
    def _validate_interface(self, interface):
        """Validate network interface"""
        try:
            import netifaces
            available_interfaces = netifaces.interfaces()
            if interface not in available_interfaces:
                print(f"[!] Interface '{interface}' not found.")
                print(f"[!] Available interfaces: {available_interfaces}")
                # Don't exit here, let the sniffer handle it
        except ImportError:
            print("[!] Warning: netifaces not installed. Cannot validate interface.")
        return interface
    
    def _validate_log_file(self, log_file):
        """Validate log file path"""
        import os
        log_dir = os.path.dirname(os.path.abspath(log_file))
        if not os.access(log_dir, os.W_OK):
            print(f"[!] Warning: Cannot write to log directory: {log_dir}")
        return log_file

class NIDSManager:
    """Main NIDS manager class"""
    def __init__(self, config):
        self.config = config
        self.packet_queue = Queue(maxsize=2000)  # Bounded queue
        self.sniffer = None
        self.detector = None
        self.api_thread = None
        self.is_running = False
        
    def setup_logging(self):
        """Setup logging configuration"""
        # Console logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler()]
        )
        
        # File logging for alerts
        alert_logger = logging.getLogger('nids_alerts')
        try:
            file_handler = logging.FileHandler(self.config.LOG_FILE)
            file_handler.setLevel(logging.WARNING)
            file_handler.setFormatter(JsonFormatter())
            alert_logger.addHandler(file_handler)
            alert_logger.propagate = False
            print(f"[*] Alert logging configured: {self.config.LOG_FILE}")
        except Exception as e:
            print(f"[!] Failed to setup file logging: {e}")
    
    def initialize_components(self):
        """Initialize NIDS components"""
        try:
            self.sniffer = PacketSniffer(self.config, self.packet_queue)
            self.detector = DetectionEngine(self.packet_queue, interface=self.config.INTERFACE)
            print("[*] NIDS components initialized successfully")
            return True
        except Exception as e:
            logging.error(f"Failed to initialize components: {e}")
            return False
    
    def start(self):
        """Start all NIDS components"""
        try:
            logging.info(f"Starting NIDS on interface '{self.config.INTERFACE}'...")
            
            # Start packet sniffer
            if not self.sniffer.start():
                logging.error("Failed to start packet sniffer")
                return False
            
            # Start detection engine
            self.detector.start()
            
            # Start API server
            self.api_thread = Thread(target=run_api_server, daemon=True)
            self.api_thread.start()
            
            self.is_running = True
            logging.info("NIDS and API are running successfully")
            logging.info("Dashboard available at: http://localhost:8501")
            logging.info("API available at: http://localhost:5000")
            logging.info("Press Ctrl+C to stop...")
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to start NIDS: {e}")
            return False
    
    def stop(self):
        """Stop all NIDS components gracefully"""
        logging.info("Stopping NIDS components...")
        
        self.is_running = False
        
        if self.sniffer:
            self.sniffer.stop()
        
        if self.detector:
            self.detector.stop()
        
        # Print final statistics
        if self.sniffer:
            stats = self.sniffer.get_statistics()
            logging.info(f"Final stats - Captured: {stats['packets_captured']}, "
                        f"Dropped: {stats['packets_dropped']}")
        
        logging.info("NIDS shutdown complete")
    
    def run(self):
        """Main run loop"""
        if not self.start():
            return False
        
        try:
            # Monitor system health
            last_stats_time = time.time()
            
            while self.is_running:
                time.sleep(1)
                
                # Print stats every 30 seconds
                if time.time() - last_stats_time > 30:
                    if self.sniffer:
                        stats = self.sniffer.get_statistics()
                        logging.info(f"System stats - Captured: {stats['packets_captured']}, "
                                   f"Queue: {stats['queue_size']}, Dropped: {stats['packets_dropped']}")
                    last_stats_time = time.time()
                    
        except KeyboardInterrupt:
            logging.info("Received shutdown signal")
        except Exception as e:
            logging.error(f"Runtime error: {e}")
        finally:
            self.stop()
        
        return True

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    print(f"\n[*] Received signal {signum}. Initiating graceful shutdown...")
    sys.exit(0)

def check_privileges():
    """Check if running with necessary privileges"""
    import os
    if os.name == 'nt':  # Windows
        # Windows privilege check would go here
        return True
    else:  # Unix/Linux
        if os.geteuid() != 0:
            print("[!] This application requires root privileges for packet capture.")
            print("[!] Please run with: sudo python main.py")
            return False
    return True

def main():
    """Main function to run the NIDS"""
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="🛡️ Real-time Network Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python main.py -i eth0
  sudo python main.py -i wlan0 -l /var/log/nids_alerts.log
  
Dashboard:
  streamlit run dashboard.py
        """
    )
    
    parser.add_argument(
        '-i', '--interface', 
        type=str, 
        required=True,
        help="Network interface to monitor (e.g., eth0, wlan0)"
    )
    
    parser.add_argument(
        '-l', '--logfile', 
        type=str, 
        default='nids_alerts.log',
        help="File to save security alerts (default: nids_alerts.log)"
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Check privileges
    if not check_privileges():
        sys.exit(1)
    
    print("🛡️ " + "="*60)
    print("   NETWORK INTRUSION DETECTION SYSTEM")
    print("   Real-time Monitoring & Threat Detection")
    print("="*64)
    
    try:
        # Create configuration
        config = Config(interface=args.interface, log_file=args.logfile)
        
        # Create and run NIDS
        nids = NIDSManager(config)
        nids.setup_logging()
        
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        if not nids.initialize_components():
            print("[!] Failed to initialize NIDS components")
            sys.exit(1)
        
        success = nids.run()
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\n[*] Shutdown requested by user")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        logging.exception("Fatal error occurred")
        sys.exit(1)

if __name__ == "__main__":
    main()