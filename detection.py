# detection.py

import logging
import time
from queue import Queue
from threading import Thread, Event
from collections import defaultdict, deque
from scapy.all import TCP, IP, ARP

from utils import get_ip_geolocation, get_gateway_info

alert_logger = logging.getLogger('nids_alerts')
alert_logger.setLevel(logging.WARNING)


class DetectionEngine:
    def __init__(self, packet_queue: Queue, interface: str):
        self.packet_queue = packet_queue
        self.is_running = Event()
        self.analysis_thread = None
        self.port_scan_tracker = defaultdict(lambda: deque(maxlen=21))
        self.PORT_SCAN_THRESHOLD = 20
        self.PORT_SCAN_TIME_WINDOW = 10
        self.gateway_ip, _ = get_gateway_info()
        self.arp_table = {}

    def _analyze_packets(self):
        print("[*] Starting detection engine...")
        while not self.is_running.is_set():
            if not self.packet_queue.empty():
                packet = self.packet_queue.get()
                self._rules_engine(packet)

    def _rules_engine(self, packet):
        if packet.haslayer(ARP):
            self._detect_arp_spoofing(packet)
            return
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return
        src_ip = packet[IP].src
        self._detect_port_scan(packet, src_ip)
        tcp_flags = packet[TCP].flags
        FIN, PSH, URG = 0x01, 0x08, 0x20
        if tcp_flags == 0:
            self._trigger_alert("TCP NULL Scan", packet)
        elif tcp_flags & (FIN | PSH | URG) == (FIN | PSH | URG):
            self._trigger_alert("TCP XMAS Scan", packet)

    def _detect_arp_spoofing(self, packet):
        if packet[ARP].op != 2:
            return
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc
        if src_ip == self.gateway_ip:
            if src_ip in self.arp_table and self.arp_table[src_ip] != src_mac:
                extra_details = {
                    "original_mac": self.arp_table[src_ip],
                    "new_mac": src_mac
                }
                self._trigger_alert("ARP Spoofing", packet, extra_data=extra_details)
            else:
                if src_ip not in self.arp_table:
                    print(f"[*] Learning gateway MAC: {self.gateway_ip} -> {src_mac}")
                self.arp_table[src_ip] = src_mac

    def _detect_port_scan(self, packet, src_ip):
        current_time = time.time()
        dest_port = packet[TCP].dport
        self.port_scan_tracker[src_ip].append((current_time, dest_port))
        if len(self.port_scan_tracker[src_ip]) > self.PORT_SCAN_THRESHOLD:
            first_attempt_time, _ = self.port_scan_tracker[src_ip][0]
            if (current_time - first_attempt_time) <= self.PORT_SCAN_TIME_WINDOW:
                scanned_ports = sorted(list({port for _, port in self.port_scan_tracker[src_ip]}))
                extra_details = { "scanned_ports": scanned_ports }
                self._trigger_alert("Port Scan", packet, extra_data=extra_details)
                self.port_scan_tracker.pop(src_ip, None)
    
    def _trigger_alert(self, alert_type: str, packet, extra_data=None):
        """
        Logs a security alert by passing a dictionary of details to the logger.
        """
        # Create a dictionary with the core alert details
        details = {
            "alert_type": alert_type,
            "summary": packet.summary()
        }
        
        # Add IP and Geolocation info if available
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            details['source_ip'] = src_ip
            details['destination_ip'] = packet[IP].dst
            details['location'] = get_ip_geolocation(src_ip)
        
        # Add MAC info for ARP packets
        if packet.haslayer(ARP):
            details['source_mac'] = packet[ARP].hwsrc

        # Merge any extra data from the specific rule (like scanned ports)
        if extra_data:
            details.update(extra_data)
        
        # Log the message, passing the dictionary in the 'extra' parameter.
        # Our custom JsonFormatter will know how to handle this.
        alert_logger.warning(f"{alert_type} Detected", extra={'extra_data': details})

    def start(self):
        if self.analysis_thread and self.analysis_thread.is_alive():
            print("[!] Detection engine is already running.")
            return
        self.is_running.clear()
        self.analysis_thread = Thread(target=self._analyze_packets, daemon=True)
        self.analysis_thread.start()
    def stop(self):
        print("[*] Stopping detection engine...")
        self.is_running.set()
        if self.analysis_thread and self.analysis_thread.is_alive():
            self.analysis_thread.join(timeout=2)
        print("[*] Detection engine stopped.")


# # --- Testing Block ---
# if __name__ == '__main__':
#     # This test demonstrates how the engine detects a malicious packet.
#     from scapy.all import IP, Ether
#     import time
    
#     print("--- Running Detection Engine Module Test ---")

#     # 1. Set up the logger to print alerts to the console for this test
#     handler = logging.StreamHandler()
#     formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#     handler.setFormatter(formatter)
#     alert_logger.addHandler(handler)

#     test_queue = Queue()
#     engine = DetectionEngine(test_queue)
#     engine.start()
    
#     # 2. Create a fake NULL scan packet and put it in the queue
#     print("[*] Simulating a TCP NULL Scan packet...")
#     null_scan_packet = Ether() / IP(src="10.0.0.99", dst="10.0.0.1") / TCP(flags=0)
#     test_queue.put(null_scan_packet)
    
#     # 3. Create a normal packet that should NOT trigger an alert
#     print("[*] Simulating a normal TCP SYN packet...")
#     normal_packet = Ether() / IP(src="10.0.0.50", dst="10.0.0.1") / TCP(flags="S")
#     test_queue.put(normal_packet)
    
#     try:
#         # Wait a moment to ensure the engine processes the packet
#         time.sleep(2)
#     finally:
#         engine.stop()
#         print("\n--- Detection Engine Module Test Finished ---")
#         print("An 'ALERT' message for the NULL Scan should have appeared above.")