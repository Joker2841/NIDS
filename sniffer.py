# sniffer.py

import threading
import time
from queue import Queue
import logging

from scapy.all import sniff, Scapy_Exception

class PacketSniffer:
    """
    Enhanced packet sniffer with BPF filtering and better error handling.
    """
    def __init__(self, config, packet_queue: Queue):
        self.config = config
        self.packet_queue = packet_queue
        self.is_running = threading.Event()
        self.sniffer_thread = None
        self.logger = logging.getLogger(__name__)
        
        # Statistics
        self.packets_captured = 0
        self.packets_dropped = 0
        
        print(f"[*] Packet sniffer initialized for interface: {config.INTERFACE}")

    def _sniff_packets(self):
        """Enhanced sniffing function with BPF filters and error handling"""
        print(f"[*] Starting packet sniffing on interface '{self.config.INTERFACE}'...")
        
        # BPF filter to capture only relevant packets
        packet_filter = "tcp or arp or icmp or (udp and port 53)"  # Include DNS
        
        retry_count = 0
        max_retries = 3
        
        while not self.is_running.is_set() and retry_count < max_retries:
            try:
                sniff(
                    iface=self.config.INTERFACE,
                    filter=packet_filter,
                    prn=self._process_packet,
                    store=0,
                    timeout=1,
                    stop_filter=lambda p: self.is_running.is_set()
                )
                retry_count = 0  # Reset retry count on successful sniffing
                
            except Scapy_Exception as e:
                retry_count += 1
                self.logger.error(f"Scapy error on interface {self.config.INTERFACE}: {e}")
                if retry_count < max_retries:
                    print(f"[!] Retrying in 5 seconds... (attempt {retry_count}/{max_retries})")
                    time.sleep(5)
                else:
                    print(f"[!] Max retries reached. Stopping sniffer.")
                    break
                    
            except PermissionError:
                print("[!] Permission denied. Please run with sudo/administrator privileges.")
                break
                
            except Exception as e:
                retry_count += 1
                self.logger.error(f"Unexpected error during sniffing: {e}")
                if retry_count < max_retries:
                    print(f"[!] Unexpected error. Retrying in 5 seconds... (attempt {retry_count}/{max_retries})")
                    time.sleep(5)
                else:
                    print(f"[!] Max retries reached. Stopping sniffer.")
                    break

    def _process_packet(self, packet):
        """Process captured packet with error handling and queue management"""
        try:
            self.packets_captured += 1
            
            # Prevent memory issues by limiting queue size
            if self.packet_queue.qsize() < 1000:
                self.packet_queue.put(packet)
            else:
                self.packets_dropped += 1
                if self.packets_dropped % 100 == 0:  # Log every 100 dropped packets
                    print(f"[!] Warning: Dropped {self.packets_dropped} packets due to queue overflow")
                    
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")

    def get_statistics(self):
        """Get sniffer statistics"""
        return {
            'packets_captured': self.packets_captured,
            'packets_dropped': self.packets_dropped,
            'queue_size': self.packet_queue.qsize()
        }

    def start(self):
        """Start the packet sniffing thread with validation"""
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            print("[!] Sniffer is already running.")
            return False

        # Validate interface before starting
        try:
            import netifaces
            if self.config.INTERFACE not in netifaces.interfaces():
                available_interfaces = netifaces.interfaces()
                print(f"[!] Interface '{self.config.INTERFACE}' not found.")
                print(f"[!] Available interfaces: {available_interfaces}")
                return False
        except ImportError:
            print("[!] Warning: netifaces not installed. Cannot validate interface.")

        self.is_running.clear()
        self.sniffer_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.sniffer_thread.start()
        return True

    def stop(self):
        """Stop the packet sniffing thread"""
        print("[*] Stopping packet sniffing...")
        self.is_running.set()
        
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=5)
            
        # Print final statistics
        stats = self.get_statistics()
        print(f"[*] Packet sniffing stopped. Captured: {stats['packets_captured']}, Dropped: {stats['packets_dropped']}")


# --- Testing Block ---
if __name__ == '__main__':
    import sys
    import os
    
    # Mock config for testing
    class MockConfig:
        INTERFACE = "eth0"  # Change this to your interface
    
    print("--- Running Enhanced Sniffer Module Test ---")
    print("Please ensure you're running this script with sudo.")
    
    if os.geteuid() != 0:
        print("[!] This script requires root privileges. Please run with sudo.")
        sys.exit(1)
    
    test_queue = Queue()
    config = MockConfig()
    
    sniffer = PacketSniffer(config, test_queue)
    
    if not sniffer.start():
        print("[!] Failed to start sniffer.")
        sys.exit(1)
    
    print("\n[*] Sniffer started. Capturing packets for 10 seconds...")
    
    try:
        start_time = time.time()
        while time.time() - start_time < 10:
            if not test_queue.empty():
                packet = test_queue.get()
                print(f"  -> Captured: {packet.summary()}")
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n[!] User interrupted the test.")
    finally:
        sniffer.stop()
        stats = sniffer.get_statistics()
        print(f"\n--- Test Results ---")
        print(f"Packets captured: {stats['packets_captured']}")
        print(f"Packets dropped: {stats['packets_dropped']}")
        print("--- Enhanced Sniffer Module Test Finished ---")