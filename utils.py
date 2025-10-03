# utils.py - Enhanced utilities with caching and error handling

import requests
import json
import subprocess
import re
import threading
import time
from ipaddress import ip_address, AddressValueError
from functools import lru_cache
from typing import Tuple, Optional

# Global cache and locks for thread safety
_ip_cache = {}
_cache_lock = threading.Lock()
_last_cleanup = time.time()
CACHE_TTL = 3600  # 1 hour cache TTL

def cleanup_cache():
    """Clean up expired cache entries"""
    global _last_cleanup
    current_time = time.time()
    
    # Only cleanup every 10 minutes
    if current_time - _last_cleanup < 600:
        return
    
    with _cache_lock:
        expired_keys = []
        for ip, (location, timestamp) in _ip_cache.items():
            if current_time - timestamp > CACHE_TTL:
                expired_keys.append(ip)
        
        for key in expired_keys:
            del _ip_cache[key]
        
        _last_cleanup = current_time
        if expired_keys:
            print(f"[*] Cleaned up {len(expired_keys)} expired cache entries")

@lru_cache(maxsize=1)
def get_gateway_info() -> Tuple[Optional[str], Optional[str]]:
    """
    Enhanced gateway discovery with multiple methods and caching.
    
    Returns:
        Tuple containing (gateway_ip, gateway_mac) or (None, None) if not found.
    """
    try:
        # Method 1: Try 'ip route' command (Linux)
        result = subprocess.run(
            ['ip', 'route'], 
            capture_output=True, 
            text=True, 
            check=True,
            timeout=5
        )
        
        # Look for default gateway
        match = re.search(r'default via (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', result.stdout)
        if match:
            gateway_ip = match.group(1)
            print(f"[*] Found gateway IP: {gateway_ip}")
            return gateway_ip, None
            
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    try:
        # Method 2: Try 'route' command (alternative)
        result = subprocess.run(
            ['route', '-n'], 
            capture_output=True, 
            text=True, 
            check=True,
            timeout=5
        )
        
        lines = result.stdout.split('\n')
        for line in lines:
            if line.startswith('0.0.0.0'):
                parts = line.split()
                if len(parts) > 1:
                    gateway_ip = parts[1]
                    print(f"[*] Found gateway IP via route: {gateway_ip}")
                    return gateway_ip, None
                    
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    print("[!] Could not determine gateway IP address")
    return None, None

def get_ip_geolocation(ip: str) -> str:
    """
    Enhanced IP geolocation with caching, validation, and error handling.
    
    Args:
        ip: IP address to geolocate
        
    Returns:
        Location string or error message
    """
    if not ip:
        return "No IP provided"
    
    # Cleanup old cache entries periodically
    cleanup_cache()
    
    # Check cache first
    with _cache_lock:
        if ip in _ip_cache:
            location, timestamp = _ip_cache[ip]
            if time.time() - timestamp < CACHE_TTL:
                return location
    
    # Validate IP address
    try:
        ip_addr = ip_address(ip)
        
        # Check for private/internal IPs
        if ip_addr.is_private or ip_addr.is_loopback or ip_addr.is_link_local:
            location = "Private/Internal IP"
            with _cache_lock:
                _ip_cache[ip] = (location, time.time())
            return location
            
        # Check for multicast/broadcast
        if ip_addr.is_multicast or ip_addr.is_reserved:
            location = "Reserved/Multicast IP"
            with _cache_lock:
                _ip_cache[ip] = (location, time.time())
            return location
            
    except AddressValueError:
        location = "Invalid IP Address"
        with _cache_lock:
            _ip_cache[ip] = (location, time.time())
        return location
    
    # Try multiple geolocation services
    services = [
        {
            'url': f"https://ipinfo.io/{ip}/json",
            'parser': _parse_ipinfo_response
        },
        {
            'url': f"http://ip-api.com/json/{ip}",
            'parser': _parse_ipapi_response
        }
    ]
    
    for service in services:
        try:
            response = requests.get(
                service['url'], 
                timeout=3,
                headers={'User-Agent': 'NIDS-Tool/1.0'}
            )
            response.raise_for_status()
            
            location = service['parser'](response.json())
            if location and location != "Unknown":
                with _cache_lock:
                    _ip_cache[ip] = (location, time.time())
                return location
                
        except requests.exceptions.RequestException as e:
            continue  # Try next service
        except json.JSONDecodeError:
            continue  # Try next service
        except Exception:
            continue  # Try next service
    
    # If all services fail
    location = "Geolocation unavailable"
    with _cache_lock:
        _ip_cache[ip] = (location, time.time())
    return location

def _parse_ipinfo_response(data: dict) -> str:
    """Parse response from ipinfo.io"""
    try:
        city = data.get('city', 'Unknown')
        region = data.get('region', 'Unknown')
        country = data.get('country', 'Unknown')
        
        if city == 'Unknown' and region == 'Unknown' and country == 'Unknown':
            return "Unknown"
            
        return f"{city}, {region}, {country}"
    except:
        return "Unknown"

def _parse_ipapi_response(data: dict) -> str:
    """Parse response from ip-api.com"""
    try:
        if data.get('status') != 'success':
            return "Unknown"
            
        city = data.get('city', 'Unknown')
        region = data.get('regionName', 'Unknown')  
        country = data.get('country', 'Unknown')
        
        if city == 'Unknown' and region == 'Unknown' and country == 'Unknown':
            return "Unknown"
            
        return f"{city}, {region}, {country}"
    except:
        return "Unknown"

def validate_ip_address(ip: str) -> bool:
    """
    Validate if a string is a valid IP address.
    
    Args:
        ip: String to validate
        
    Returns:
        True if valid IP address, False otherwise
    """
    try:
        ip_address(ip)
        return True
    except AddressValueError:
        return False

def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is private/internal.
    
    Args:
        ip: IP address to check
        
    Returns:
        True if private IP, False otherwise
    """
    try:
        ip_addr = ip_address(ip)
        return ip_addr.is_private or ip_addr.is_loopback or ip_addr.is_link_local
    except AddressValueError:
        return False

def get_cache_stats() -> dict:
    """Get cache statistics for monitoring"""
    with _cache_lock:
        return {
            'cached_entries': len(_ip_cache),
            'cache_ttl': CACHE_TTL,
            'last_cleanup': _last_cleanup
        }

def clear_cache():
    """Clear the geolocation cache"""
    with _cache_lock:
        cleared_count = len(_ip_cache)
        _ip_cache.clear()
        print(f"[*] Cleared {cleared_count} cache entries")
        return cleared_count

# Network utility functions
def get_network_interfaces():
    """Get available network interfaces"""
    try:
        import netifaces
        return netifaces.interfaces()
    except ImportError:
        print("[!] netifaces not installed. Cannot enumerate interfaces.")
        return []

def is_valid_interface(interface: str) -> bool:
    """Check if a network interface is valid and available"""
    try:
        import netifaces
        return interface in netifaces.interfaces()
    except ImportError:
        # Can't validate without netifaces
        return True

# Testing functions
if __name__ == '__main__':
    print("--- Testing Utils Module ---")
    
    # Test gateway discovery
    print("Testing gateway discovery...")
    gw_ip, gw_mac = get_gateway_info()
    print(f"Gateway: {gw_ip}")
    
    # Test geolocation
    test_ips = ["8.8.8.8", "1.1.1.1", "192.168.1.1", "invalid.ip"]
    print("\nTesting geolocation...")
    for ip in test_ips:
        location = get_ip_geolocation(ip)
        print(f"{ip} -> {location}")
    
    # Test cache
    print(f"\nCache stats: {get_cache_stats()}")
    
    print("--- Utils Module Test Complete ---")