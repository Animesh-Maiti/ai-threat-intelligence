import socket
import ipaddress
from urllib.parse import urlparse
from fastapi import HTTPException

# Blacklist loopback, private ranges (RFC 1918), link-local, and AWS/GCP metadata
BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # Cloud metadata IP (169.254.169.254)
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

def validate_target_url(raw_url: str) -> str:
    """
    Validates URL scheme and resolves hostname to ensure it does not target
    internal loopback or private network ranges (SSRF defense).
    """
    parsed = urlparse(raw_url)
    if parsed.scheme not in ["http", "https"]:
        raise HTTPException(status_code=400, detail="Invalid protocol scheme. Only HTTP/HTTPS allowed.")
    
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Missing valid hostname.")

    try:
        resolved_ips = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Could not resolve domain name.")

    for item in resolved_ips:
        ip_addr_str = item[4][0]
        ip_obj = ipaddress.ip_address(ip_addr_str)
        for blocked_net in BLOCKED_IP_NETWORKS:
            if ip_obj in blocked_net:
                raise HTTPException(
                    status_code=403, 
                    detail="Target resolves to a restricted private or internal IP range."
                )

    return raw_url