import time
import random
import threading
from scapy.all import IP, TCP, ARP, ICMP, Ether, send, sr1
import argparse

class NIDSDemo:
    """Generate various network attacks for NIDS testing"""
    
    def __init__(self, target_ip="192.168.1.1", source_ip="192.168.1.100"):
        self.target_ip = target_ip
        self.source_ip = source_ip
        self.is_running = False
        
        print(f"[*] NIDS Demo initialized")
        print(f"    Target IP: {target_ip}")
        print(f"    Source IP: {source_ip}")
    
    def simulate_port_scan(self, num_ports=25):
        """Simulate a port scanning attack"""
        print(f"[*] Simulating port scan - {num_ports} ports")
        
        ports = random.sample(range(1, 65535), num_ports)
        for port in ports:
            try:
                packet = IP(src=self.source_ip, dst=self.target_ip) / TCP(dport=port, flags="S")
                send(packet, verbose=0, timeout=0.1)
                time.sleep(0.1)
            except Exception as e:
                print(f"[!] Error sending packet to port {port}: {e}")
        
        print(f"[✓] Port scan simulation complete")
    
    def simulate_syn_flood(self, num_packets=60, duration=3):
        """Simulate SYN flood attack"""
        print(f"[*] Simulating SYN flood - {num_packets} packets over {duration}s")
        
        packet_interval = duration / num_packets
        
        for i in range(num_packets):
            try:
                # Randomize source port
                sport = random.randint(1024, 65535)
                packet = IP(src=self.source_ip, dst=self.target_ip) / TCP(sport=sport, dport=80, flags="S")
                send(packet, verbose=0, timeout=0.1)
                time.sleep(packet_interval)
            except Exception as e:
                print(f"[!] Error in SYN flood: {e}")
                break
        
        print(f"[✓] SYN flood simulation complete")
    
    def simulate_icmp_flood(self, num_packets=60, duration=3):
        """Simulate ICMP flood attack"""
        print(f"[*] Simulating ICMP flood - {num_packets} packets over {duration}s")
        
        packet_interval = duration / num_packets
        
        for i in range(num_packets):
            try:
                packet = IP(src=self.source_ip, dst=self.target_ip) / ICMP()
                send(packet, verbose=0, timeout=0.1)
                time.sleep(packet_interval)
            except Exception as e:
                print(f"[!] Error in ICMP flood: {e}")
                break
        
        print(f"[✓] ICMP flood simulation complete")
    
    def simulate_null_scan(self, num_ports=10):
        """Simulate TCP NULL scan"""
        print(f"[*] Simulating TCP NULL scan - {num_ports} ports")
        
        ports = random.sample(range(20, 1024), num_ports)
        for port in ports:
            try:
                # NULL scan has no TCP flags set
                packet = IP(src=self.source_ip, dst=self.target_ip) / TCP(dport=port, flags=0)
                send(packet, verbose=0, timeout=0.1)
                time.sleep(0.2)
            except Exception as e:
                print(f"[!] Error in NULL scan: {e}")
        
        print(f"[✓] NULL scan simulation complete")
    
    def simulate_xmas_scan(self, num_ports=10):
        """Simulate TCP XMAS scan"""
        print(f"[*] Simulating TCP XMAS scan - {num_ports} ports")
        
        ports = random.sample(range(20, 1024), num_ports)
        for port in ports:
            try:
                # XMAS scan has FIN, PSH, URG flags set
                packet = IP(src=self.source_ip, dst=self.target_ip) / TCP(dport=port, flags="FPU")
                send(packet, verbose=0, timeout=0.1)
                time.sleep(0.2)
            except Exception as e:
                print(f"[!] Error in XMAS scan: {e}")
        
        print(f"[✓] XMAS scan simulation complete")
    
    def simulate_land_attack(self):
        """Simulate LAND attack (src IP = dst IP)"""
        print(f"[*] Simulating LAND attack")
        
        try:
            # LAND attack: source and destination are the same
            packet = IP(src=self.target_ip, dst=self.target_ip) / TCP(sport=80, dport=80, flags="S")
            send(packet, verbose=0, timeout=0.1)
            print(f"[✓] LAND attack simulation complete")
        except Exception as e:
            print(f"[!] Error in LAND attack: {e}")
    
    def simulate_dns_tunneling(self, num_queries=5):
        """Simulate suspicious DNS queries"""
        print(f"[*] Simulating suspicious DNS queries - {num_queries} queries")
        
        # Generate long domain names that might indicate DNS tunneling
        for i in range(num_queries):
            try:
                # Create a very long subdomain
                long_subdomain = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=120))
                domain = f"{long_subdomain}.suspicious-domain.com"
                
                # Note: This is a simplified simulation
                # In real scenarios, you'd send actual DNS queries
                print(f"    -> Simulating DNS query for: {domain[:50]}...")
                time.sleep(0.5)
            except Exception as e:
                print(f"[!] Error in DNS simulation: {e}")
        
        print(f"[✓] Suspicious DNS queries simulation complete")
    
    def run_comprehensive_test(self):
        """Run a comprehensive test of all attack types"""
        print("\n" + "="*60)
        print("   NIDS COMPREHENSIVE ATTACK SIMULATION")
        print("="*60)
        
        attacks = [
            ("Port Scan", lambda: self.simulate_port_scan(25)),
            ("SYN Flood", lambda: self.simulate_syn_flood(60, 3)),
            ("ICMP Flood", lambda: self.simulate_icmp_flood(60, 3)),
            ("TCP NULL Scan", lambda: self.simulate_null_scan(10)),
            ("TCP XMAS Scan", lambda: self.simulate_xmas_scan(10)),
            ("LAND Attack", self.simulate_land_attack),
            ("DNS Tunneling", lambda: self.simulate_dns_tunneling(5))
        ]
        
        for attack_name, attack_func in attacks:
            print(f"\n--- {attack_name} ---")
            try:
                attack_func()
                print(f"[✓] {attack_name} completed successfully")
            except Exception as e:
                print(f"[!] {attack_name} failed: {e}")
            
            # Wait between attacks
            time.sleep(2)
        
        print(f"\n{'='*60}")
        print("   SIMULATION COMPLETE")
        print(f"{'='*60}")
        print(f"[*] Check your NIDS dashboard for detected attacks!")
        print(f"[*] Dashboard: http://localhost:8501")
        print(f"[*] API: http://localhost:5000/api/alerts")
    
    def run_continuous_attacks(self, duration_minutes=5):
        """Run continuous attacks for testing over time"""
        print(f"[*] Starting continuous attack simulation for {duration_minutes} minutes...")
        
        self.is_running = True
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        
        attack_functions = [
            lambda: self.simulate_port_scan(random.randint(15, 30)),
            lambda: self.simulate_syn_flood(random.randint(30, 70), 2),
            lambda: self.simulate_icmp_flood(random.randint(30, 70), 2),
            lambda: self.simulate_null_scan(random.randint(5, 15)),
            self.simulate_land_attack
        ]
        
        while time.time() < end_time and self.is_running:
            try:
                # Pick a random attack
                attack = random.choice(attack_functions)
                attack()
                
                # Wait random time between attacks (10-30 seconds)
                wait_time = random.randint(10, 30)
                print(f"[*] Waiting {wait_time} seconds before next attack...")
                time.sleep(wait_time)
                
            except KeyboardInterrupt:
                print("\n[*] Stopping continuous attacks...")
                self.is_running = False
                break
            except Exception as e:
                print(f"[!] Error in continuous attack: {e}")
                time.sleep(5)
        
        print(f"[✓] Continuous attack simulation finished")

def check_requirements():
    """Check if the system has necessary requirements"""
    try:
        import scapy
        print("[✓] Scapy available")
    except ImportError:
        print("[!] Error: Scapy not installed. Run: pip install scapy")
        return False
    
    import os
    if os.name != 'nt' and os.geteuid() != 0:
        print("[!] Error: Root privileges required for packet injection")
        print("    Please run with: sudo python demo.py")
        return False
    
    return True

def get_network_info():
    """Get basic network information"""
    try:
        import netifaces
        
        # Get default gateway
        gateways = netifaces.gateways()
        default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
        if default_gateway:
            gateway_ip = default_gateway[0]
            interface = default_gateway[1]
            
            # Get interface IP
            addrs = netifaces.ifaddresses(interface)
            interface_ip = addrs[netifaces.AF_INET][0]['addr']
            
            return gateway_ip, interface_ip, interface
            
    except ImportError:
        print("[!] Warning: netifaces not available. Using default IPs.")
    except Exception as e:
        print(f"[!] Error getting network info: {e}")
    
    # Return defaults
    return "192.168.1.1", "192.168.1.100", "eth0"

def main():
    """Main demo function"""
    parser = argparse.ArgumentParser(
        description="🛡️ NIDS Attack Simulation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Run comprehensive test
    sudo python demo.py --comprehensive
    
    # Run specific attack
    sudo python demo.py --port-scan --num-ports 50
    
    # Continuous testing
    sudo python demo.py --continuous --duration 10
    
    # Custom targets
    sudo python demo.py --target 10.0.0.1 --source 10.0.0.100 --comprehensive
        """
    )
    
    parser.add_argument('--target', type=str, help='Target IP address')
    parser.add_argument('--source', type=str, help='Source IP address')
    parser.add_argument('--comprehensive', action='store_true', help='Run all attack types')
    parser.add_argument('--continuous', action='store_true', help='Run continuous attacks')
    parser.add_argument('--duration', type=int, default=5, help='Duration for continuous mode (minutes)')
    
    # Individual attack options
    parser.add_argument('--port-scan', action='store_true', help='Run port scan simulation')
    parser.add_argument('--syn-flood', action='store_true', help='Run SYN flood simulation')
    parser.add_argument('--icmp-flood', action='store_true', help='Run ICMP flood simulation')
    parser.add_argument('--null-scan', action='store_true', help='Run NULL scan simulation')
    parser.add_argument('--xmas-scan', action='store_true', help='Run XMAS scan simulation')
    parser.add_argument('--land-attack', action='store_true', help='Run LAND attack simulation')
    parser.add_argument('--dns-tunneling', action='store_true', help='Run DNS tunneling simulation')
    
    # Parameters
    parser.add_argument('--num-ports', type=int, default=25, help='Number of ports to scan')
    parser.add_argument('--num-packets', type=int, default=60, help='Number of packets for flood attacks')
    
    args = parser.parse_args()
    
    print("🛡️ " + "="*50)
    print("   NIDS ATTACK SIMULATION TOOL")
    print("="*54)
    
    # Check requirements
    if not check_requirements():
        return 1
    
    # Get network information
    if args.target and args.source:
        target_ip = args.target
        source_ip = args.source
    else:
        print("[*] Auto-detecting network configuration...")
        target_ip, source_ip, interface = get_network_info()
        print(f"    Detected gateway: {target_ip}")
        print(f"    Using source IP: {source_ip}")
        print(f"    Interface: {interface}")
    
    # Create demo instance
    demo = NIDSDemo(target_ip, source_ip)
    
    # Determine what to run
    if args.comprehensive:
        demo.run_comprehensive_test()
    elif args.continuous:
        demo.run_continuous_attacks(args.duration)
    else:
        # Run individual attacks
        ran_attack = False
        
        if args.port_scan:
            demo.simulate_port_scan(args.num_ports)
            ran_attack = True
        
        if args.syn_flood:
            demo.simulate_syn_flood(args.num_packets)
            ran_attack = True
        
        if args.icmp_flood:
            demo.simulate_icmp_flood(args.num_packets)
            ran_attack = True
        
        if args.null_scan:
            demo.simulate_null_scan(args.num_ports // 2)
            ran_attack = True
        
        if args.xmas_scan:
            demo.simulate_xmas_scan(args.num_ports // 2)
            ran_attack = True
        
        if args.land_attack:
            demo.simulate_land_attack()
            ran_attack = True
        
        if args.dns_tunneling:
            demo.simulate_dns_tunneling()
            ran_attack = True
        
        if not ran_attack:
            print("[!] No attack specified. Use --help for options or --comprehensive for all attacks.")
            return 1
    
    print(f"\n[✓] Demo completed successfully!")
    return 0

if __name__ == '__main__':
    try:
        exit_code = main()
        exit(exit_code)
    except KeyboardInterrupt:
        print("\n[*] Demo interrupted by user")
        exit(0)
    except Exception as e:
        print(f"[!] Demo failed with error: {e}")
        exit(1)