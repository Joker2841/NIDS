# detection.py

import logging
import time
from queue import Queue
from threading import Thread, Event
from collections import defaultdict, deque
from scapy.all import TCP, IP, ARP, ICMP, DNS

from utils import get_ip_geolocation, get_gateway_info
from api import alert_queue
from database import AlertDatabase

alert_logger = logging.getLogger('nids_alerts')
alert_logger.setLevel(logging.WARNING)


class DetectionEngine:
    def __init__(self, packet_queue: Queue, interface: str):
        self.packet_queue = packet_queue
        self.is_running = Event()
        self.analysis_thread = None
        self.db = AlertDatabase()
        
        # --- Port Scan State ---
        self.port_scan_tracker = defaultdict(lambda: deque(maxlen=21))
        self.PORT_SCAN_THRESHOLD = 20
        self.PORT_SCAN_TIME_WINDOW = 10
        
        # --- SYN Flood State ---
        self.syn_flood_tracker = defaultdict(list)
        self.SYN_FLOOD_THRESHOLD = 50
        self.SYN_FLOOD_TIME_WINDOW = 5
        
        # --- ICMP Flood State ---
        self.icmp_tracker = defaultdict(list)
        self.ICMP_FLOOD_THRESHOLD = 50
        self.ICMP_FLOOD_TIME_WINDOW = 5
        
        # --- ARP Spoofing State ---
        self.gateway_ip, _ = get_gateway_info()
        self.arp_table = {}
        
        # --- DNS Tracking ---
        self.dns_tracker = defaultdict(list)
        
        print(f"[*] Detection engine initialized for interface: {interface}")

    def _analyze_packets(self):
        print("[*] Starting detection engine...")
        while not self.is_running.is_set():
            try:
                if not self.packet_queue.empty():
                    packet = self.packet_queue.get()
                    self._rules_engine(packet)
                else:
                    time.sleep(0.01)  # Small sleep to prevent CPU spinning
            except Exception as e:
                print(f"[!] Error in packet analysis: {e}")
                continue

    def _rules_engine(self, packet):
        """Main rules engine that processes each packet"""
        try:
            # ARP-based attacks
            if packet.haslayer(ARP):
                self._detect_arp_spoofing(packet)
                return
            
            # ICMP-based attacks
            if packet.haslayer(ICMP):
                self._detect_icmp_flood(packet)
                self._detect_land_attack(packet)
                return
            
            # DNS-based attacks
            if packet.haslayer(DNS):
                self._detect_suspicious_dns(packet)
                if not packet.haslayer(TCP):  # Don't double-process DNS over TCP
                    return
            
            # TCP-based attacks
            if not packet.haslayer(TCP) or not packet.haslayer(IP):
                return
            
            src_ip = packet[IP].src
            tcp_flags = packet[TCP].flags
            
            self._detect_syn_flood(packet, src_ip, tcp_flags)
            self._detect_port_scan(packet, src_ip)
            self._detect_land_attack(packet)
            
            # TCP scan detection
            FIN, PSH, URG = 0x01, 0x08, 0x20
            if tcp_flags == 0:
                self._trigger_alert("TCP NULL Scan", packet)
            elif tcp_flags & (FIN | PSH | URG) == (FIN | PSH | URG):
                self._trigger_alert("TCP XMAS Scan", packet)
            elif tcp_flags == FIN:
                self._trigger_alert("TCP FIN Scan", packet)
                
        except Exception as e:
            print(f"[!] Error in rules engine: {e}")

    def _detect_syn_flood(self, packet, src_ip, flags):
        """Detect SYN flood attacks"""
        try:
            SYN = 0x02
            if flags != SYN:
                return

            current_time = time.time()
            
            # Clean old entries
            self.syn_flood_tracker[src_ip] = [t for t in self.syn_flood_tracker[src_ip] 
                                            if current_time - t < self.SYN_FLOOD_TIME_WINDOW]
            
            # Add current timestamp
            self.syn_flood_tracker[src_ip].append(current_time)
            
            # Check threshold
            if len(self.syn_flood_tracker[src_ip]) > self.SYN_FLOOD_THRESHOLD:
                extra_details = {"syn_packet_count": len(self.syn_flood_tracker[src_ip])}
                self._trigger_alert("SYN Flood Attack", packet, extra_data=extra_details)
                self.syn_flood_tracker.pop(src_ip, None)
        except Exception as e:
            print(f"[!] Error in SYN flood detection: {e}")

    def _detect_icmp_flood(self, packet):
        """Detect ICMP flood attacks"""
        try:
            if not packet.haslayer(ICMP) or not packet.haslayer(IP):
                return
            
            src_ip = packet[IP].src
            current_time = time.time()
            
            # Clean old entries
            self.icmp_tracker[src_ip] = [t for t in self.icmp_tracker[src_ip] 
                                       if current_time - t < self.ICMP_FLOOD_TIME_WINDOW]
            
            # Add current timestamp
            self.icmp_tracker[src_ip].append(current_time)
            
            # Check threshold
            if len(self.icmp_tracker[src_ip]) > self.ICMP_FLOOD_THRESHOLD:
                extra_details = {"icmp_packet_count": len(self.icmp_tracker[src_ip])}
                self._trigger_alert("ICMP Flood Attack", packet, extra_data=extra_details)
                self.icmp_tracker.pop(src_ip, None)
        except Exception as e:
            print(f"[!] Error in ICMP flood detection: {e}")

    def _detect_land_attack(self, packet):
        """Detect LAND attack (source IP == destination IP)"""
        try:
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                if src_ip == dst_ip and src_ip != "127.0.0.1":  # Exclude localhost
                    extra_details = {"target_ip": src_ip}
                    self._trigger_alert("LAND Attack", packet, extra_data=extra_details)
        except Exception as e:
            print(f"[!] Error in LAND attack detection: {e}")

    def _detect_suspicious_dns(self, packet):
        """Detect suspicious DNS queries"""
        try:
            if not packet.haslayer(DNS) or packet[DNS].qr != 0:  # Only DNS queries
                return
            
            if packet[DNS].qd is None:
                return
                
            query_name = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
            
            # Detect long domain names (potential DNS tunneling)
            if len(query_name) > 100:
                extra_data = {"query_name": query_name[:50] + "...", "query_length": len(query_name)}
                self._trigger_alert("Suspicious DNS Query", packet, extra_data)
            
            # Detect high-frequency DNS queries from same source
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                current_time = time.time()
                
                # Clean old entries
                self.dns_tracker[src_ip] = [t for t in self.dns_tracker[src_ip] 
                                          if current_time - t < 60]  # 1 minute window
                
                self.dns_tracker[src_ip].append(current_time)
                
                if len(self.dns_tracker[src_ip]) > 100:  # 100 queries per minute
                    extra_data = {"query_count": len(self.dns_tracker[src_ip])}
                    self._trigger_alert("DNS Query Flood", packet, extra_data)
                    self.dns_tracker.pop(src_ip, None)
                    
        except Exception as e:
            print(f"[!] Error in DNS detection: {e}")

    def _detect_arp_spoofing(self, packet):
        """Detect ARP spoofing attacks"""
        try:
            if packet[ARP].op != 2:  # Only ARP replies
                return
                
            src_ip, src_mac = packet[ARP].psrc, packet[ARP].hwsrc
            
            if src_ip == self.gateway_ip:
                if src_ip in self.arp_table and self.arp_table[src_ip] != src_mac:
                    extra_details = {"original_mac": self.arp_table[src_ip], "new_mac": src_mac}
                    self._trigger_alert("ARP Spoofing", packet, extra_data=extra_details)
                else:
                    if src_ip not in self.arp_table: 
                        print(f"[*] Learning gateway MAC: {self.gateway_ip} -> {src_mac}")
                    self.arp_table[src_ip] = src_mac
        except Exception as e:
            print(f"[!] Error in ARP spoofing detection: {e}")

    def _detect_port_scan(self, packet, src_ip):
        """Detect port scanning attacks"""
        try:
            current_time = time.time()
            dest_port = packet[TCP].dport
            
            self.port_scan_tracker[src_ip].append((current_time, dest_port))
            
            if len(self.port_scan_tracker[src_ip]) > self.PORT_SCAN_THRESHOLD:
                first_attempt_time, _ = self.port_scan_tracker[src_ip][0]
                if (current_time - first_attempt_time) <= self.PORT_SCAN_TIME_WINDOW:
                    scanned_ports = sorted(list({port for _, port in self.port_scan_tracker[src_ip]}))
                    extra_details = {"scanned_ports": scanned_ports, "total_attempts": len(self.port_scan_tracker[src_ip])}
                    self._trigger_alert("Port Scan", packet, extra_data=extra_details)
                    self.port_scan_tracker.pop(src_ip, None)
        except Exception as e:
            print(f"[!] Error in port scan detection: {e}")

    def _get_severity(self, alert_type):
        """Get alert severity level"""
        severity_map = {
            "SYN Flood Attack": "HIGH",
            "ARP Spoofing": "HIGH", 
            "ICMP Flood Attack": "HIGH",
            "LAND Attack": "HIGH",
            "DNS Query Flood": "HIGH",
            "Port Scan": "MEDIUM",
            "TCP NULL Scan": "MEDIUM",
            "TCP XMAS Scan": "MEDIUM",
            "TCP FIN Scan": "MEDIUM",
            "Suspicious DNS Query": "LOW"
        }
        return severity_map.get(alert_type, "LOW")

    def _trigger_alert(self, alert_type: str, packet, extra_data=None):
        """Trigger a security alert"""
        try:
            details = {
                "alert_type": alert_type, 
                "timestamp": time.time(), 
                "summary": packet.summary(),
                "severity": self._get_severity(alert_type)
            }
            
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                details['source_ip'] = src_ip
                details['destination_ip'] = packet[IP].dst
                details['location'] = get_ip_geolocation(src_ip)
                
            if packet.haslayer(ARP):
                details['source_mac'] = packet[ARP].hwsrc
                
            if extra_data: 
                details.update(extra_data)
            
            # Log the alert
            alert_logger.warning(f"{alert_type} Detected", extra={'extra_data': details})
            
            # Store in database
            self.db.store_alert(details)
            
            # Add to API queue for real-time updates
            alert_queue.put(details)
            
        except Exception as e:
            print(f"[!] Error triggering alert: {e}")

    def start(self):
        """Start the detection engine"""
        if self.analysis_thread and self.analysis_thread.is_alive(): 
            return
        self.is_running.clear()
        self.analysis_thread = Thread(target=self._analyze_packets, daemon=True)
        self.analysis_thread.start()
        
    def stop(self):
        """Stop the detection engine"""
        print("[*] Stopping detection engine...")
        self.is_running.set()
        if self.analysis_thread and self.analysis_thread.is_alive(): 
            self.analysis_thread.join(timeout=2)
        print("[*] Detection engine stopped.")