# sniffer.py

import threading
import time
from queue import Queue

from scapy.all import sniff, Scapy_Exception

class PacketSniffer:
    """
    A class to sniff network packets in a separate thread.

    Attributes:
        config (object): The configuration object with settings like INTERFACE.
        packet_queue (Queue): A thread-safe queue to store captured packets.
        is_running (bool): A flag to control the sniffing loop.
        sniffer_thread (threading.Thread): The thread that runs the packet sniffing.
    """
    def __init__(self, config, packet_queue: Queue):
        """
        Initializes the PacketSniffer.

        Args:
            config (object): A configuration object containing NIDS settings.
            packet_queue (Queue): The queue where captured packets will be placed.
        """
        self.config = config
        self.packet_queue = packet_queue
        self.is_running = threading.Event()
        self.sniffer_thread = None

    def _sniff_packets(self):
        """
        The core sniffing function, intended to be run in a separate thread.
        Uses Scapy's sniff function to capture packets and put them in the queue.
        """
        print(f"[*] Starting packet sniffing on interface '{self.config.INTERFACE}'...")
        while not self.is_running.is_set():
            try:
                # The 'prn' argument specifies a function to be called for each packet sniffed.
                # The 'store=0' argument tells Scapy not to store the packets in memory.
                # The 'stop_filter' is a more efficient way to stop sniffing.
                sniff(
                    iface=self.config.INTERFACE,
                    prn=lambda packet: self.packet_queue.put(packet),
                    store=0,
                    stop_filter=lambda p: self.is_running.is_set()
                )
            except Scapy_Exception as e:
                # This handles cases where the interface might not be ready or available.
                print(f"[!] Scapy error on interface {self.config.INTERFACE}: {e}")
                print("[!] Retrying in 5 seconds...")
                time.sleep(5)
            except Exception as e:
                print(f"[!] An unexpected error occurred during sniffing: {e}")
                self.stop()


    def start(self):
        """Starts the packet sniffing thread."""
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            print("[!] Sniffer is already running.")
            return

        self.is_running.clear()  # Clear the event flag before starting
        self.sniffer_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.sniffer_thread.start()

    def stop(self):
        """Stops the packet sniffing thread."""
        print("[*] Stopping packet sniffing...")
        self.is_running.set()
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            # Wait for the thread to finish its current packet processing
            self.sniffer_thread.join(timeout=2)
        print("[*] Packet sniffing stopped.")


# --- Testing Block ---
if __name__ == '__main__':
    # This is a simple test to ensure the sniffer module works as expected.
    # It demonstrates how to start the sniffer and retrieve packets from the queue.

    # Mock config object for testing purposes
    class MockConfig:
        INTERFACE = "eth0" # Change this to your WSL interface name if different

    print("--- Running Sniffer Module Test ---")
    
    # 1. Find your WSL interface name by running 'ip addr' in the WSL terminal.
    #    It's often 'eth0' or 'eth1'.
    print("Please ensure you're running this script with sudo.")
    print(f"Using interface: {MockConfig.INTERFACE}. If this is wrong, edit the script.")
    
    test_queue = Queue()
    config = MockConfig()
    
    sniffer = PacketSniffer(config, test_queue)
    sniffer.start()
    
    print("\n[*] Sniffer started. Capturing first 5 packets for this test...")
    
    try:
        packets_captured = 0
        while packets_captured < 5:
            if not test_queue.empty():
                packet = test_queue.get()
                print(f"  -> Captured Packet: {packet.summary()}")
                packets_captured += 1
            else:
                time.sleep(0.1) # Wait a bit for packets to arrive
    except KeyboardInterrupt:
        print("\n[!] User interrupted the test.")
    finally:
        sniffer.stop()
        print("\n--- Sniffer Module Test Finished ---")