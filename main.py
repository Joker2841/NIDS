# main.py

import time
import logging
import argparse
import json
from queue import Queue
from threading import Thread

# --- Import our custom modules ---
from sniffer import PacketSniffer
from detection import DetectionEngine
from api import run_api_server
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_object = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage()
        }
        if hasattr(record, 'extra_data'):
            log_object.update(record.extra_data)
        return json.dumps(log_object)

class Config:
    def __init__(self, interface, log_file):
        self.INTERFACE = interface
        self.LOG_FILE = log_file

def setup_logging(log_file):
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
    alert_logger = logging.getLogger('nids_alerts')
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.WARNING)
    file_handler.setFormatter(JsonFormatter())
    alert_logger.addHandler(file_handler)
    alert_logger.propagate = False

def main():
    """The main function to run the NIDS and the API."""
    parser = argparse.ArgumentParser(description="A Python-based Network Intrusion Detection System with a Web API.")
    parser.add_argument('-i', '--interface', type=str, required=True, help="Network interface to sniff on.")
    parser.add_argument('-l', '--logfile', type=str, default='alerts.log', help="File to save security alerts to.")
    args = parser.parse_args()
    
    config = Config(interface=args.interface, log_file=args.logfile)
    setup_logging(config.LOG_FILE)
    logging.info(f"Initializing NIDS on interface '{config.INTERFACE}'...")

    packet_queue = Queue()
    sniffer = PacketSniffer(config, packet_queue)
    detector = DetectionEngine(packet_queue, interface=config.INTERFACE)

    api_thread = Thread(target=run_api_server, daemon=True)

    try:
        sniffer.start()
        detector.start()
        api_thread.start() # Start the API server
        
        logging.info("NIDS and API are running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        logging.info("\nShutdown signal received. Stopping NIDS...")
    finally:
        sniffer.stop()
        detector.stop()
        logging.info("NIDS has been shut down.")

if __name__ == "__main__":
    main()