# utils.py 

import requests
import json
import subprocess
import re
from ipaddress import ip_address, AddressValueError

_ip_cache = {}

def get_gateway_info() -> tuple[str, str] | tuple[None, None]:
    """
    Finds the default gateway's IP address by running the 'ip route' command.
    This is more reliable in environments like WSL than Scapy's internal methods.

    Returns:
        A tuple containing (gateway_ip, None) or (None, None) if not found.
    """
    try:
        # Run the 'ip route' command and capture its output
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True, check=True)
        
        # Search for the 'default via' line in the output
        match = re.search(r'default via (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', result.stdout)
        
        if match:
            gateway_ip = match.group(1)
            print(f"[*] Found gateway IP: {gateway_ip}")
            return gateway_ip, None
        else:
            print("[!] Could not find 'default via' in routing table.")
            return None, None
            
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[!] Error finding gateway information: {e}")
        return None, None
    except Exception as e:
        print(f"[!] An unexpected error occurred while finding the gateway: {e}")
        return None, None

def get_ip_geolocation(ip: str) -> str:
    if ip in _ip_cache:
        return _ip_cache[ip]
    try:
        ip_addr = ip_address(ip)
        if not ip_addr.is_global:
            return "Private/Internal IP"
    except AddressValueError:
        return "Invalid IP Address"
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        response.raise_for_status()
        data = response.json()
        city, region, country = data.get('city', 'N/A'), data.get('region', 'N/A'), data.get('country', 'N/A')
        location = f"{city}, {region}, {country}"
        _ip_cache[ip] = location
        return location
    except requests.exceptions.RequestException as e:
        error_msg = f"API Error: {e}"
        _ip_cache[ip] = error_msg
        return error_msg
    except json.JSONDecodeError:
        error_msg = "API Error: Invalid JSON response"
        _ip_cache[ip] = error_msg
        return error_msg