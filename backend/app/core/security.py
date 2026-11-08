import socket
import ipaddress
from urllib.parse import urlparse
from fastapi import HTTPException

# Blacklisted internal IP ranges (SSRF defense)
BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # Cloud metadata service (AWS/GCP/Azure)
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def validate_target_url(url: str) -> str:
    """
    Validates URL scheme, resolves hostname, and blocks access to internal / SSRF addresses.
    Raises HTTPException(403) only on SSRF attempts.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL format: missing hostname.")

    try:
        resolved_ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(resolved_ip)

        # Enforce SSRF barrier
        for network in BLOCKED_IP_NETWORKS:
            if ip_obj in network:
                raise HTTPException(
                    status_code=403, 
                    detail="Access to internal network or private IP address is forbidden."
                )
    except socket.gaierror:
        # Hostname does not resolve via public DNS (dead/non-existent/sinkholed domain)
        pass

    return url