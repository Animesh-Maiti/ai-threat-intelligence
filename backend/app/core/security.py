import socket
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit
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
    Unreachable public hosts are allowed through for static analysis.
    """
    if not isinstance(url, str):
        raise HTTPException(status_code=400, detail="Invalid URL or domain format")

    cleaned_url = url.strip()
    while cleaned_url and cleaned_url[0] in "@'\"":
        cleaned_url = cleaned_url[1:].lstrip()
    while cleaned_url and cleaned_url[-1] in "/'\"":
        cleaned_url = cleaned_url[:-1].rstrip()

    if not cleaned_url:
        raise HTTPException(status_code=400, detail="Invalid URL or domain format")

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned_url):
        cleaned_url = "https://" + cleaned_url

    try:
        parsed = urlsplit(cleaned_url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid URL or domain format") from exc

    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL or domain format")
    if parsed.username is not None or parsed.password is not None:
        raise HTTPException(status_code=400, detail="Invalid URL or domain format")

    try:
        normalized_hostname = hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid URL or domain format") from exc

    if not normalized_hostname or any(character.isspace() for character in normalized_hostname):
        raise HTTPException(status_code=400, detail="Invalid URL or domain format")

    try:
        ip_obj = ipaddress.ip_address(normalized_hostname)
    except ValueError:
        ip_obj = None

    if ip_obj is not None:
        if any(ip_obj in network for network in BLOCKED_IP_NETWORKS):
            raise HTTPException(
                status_code=403,
                detail="Access to internal network or private IP address is forbidden.",
            )
    else:
        labels = normalized_hostname.split(".")
        if any(
            not label
            or len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        ):
            raise HTTPException(status_code=400, detail="Invalid URL or domain format")

        try:
            try:
                address_results = socket.getaddrinfo(
                    normalized_hostname,
                    None,
                    type=socket.SOCK_STREAM,
                    flags=getattr(socket, "AI_ADDRCONFIG", 0),
                )
            except (socket.gaierror, OSError):
                address_results = socket.getaddrinfo(
                    normalized_hostname, None, type=socket.SOCK_STREAM
                )
            if not address_results:
                address_results = socket.getaddrinfo(
                    normalized_hostname, None, type=socket.SOCK_STREAM
                )
            addresses = {
                ipaddress.ip_address(result[4][0]) for result in address_results
            }
        except (socket.gaierror, OSError):
            addresses = set()

        if any(
            address.version == network.version and address in network
            for address in addresses
            for network in BLOCKED_IP_NETWORKS
        ):
            raise HTTPException(
                status_code=403,
                detail="Access to internal network or private IP address is forbidden.",
            )

    netloc = normalized_hostname
    if ":" in normalized_hostname and not normalized_hostname.startswith("["):
        netloc = f"[{normalized_hostname}]"
    if port is not None:
        netloc = f"{netloc}:{port}"

    return urlunsplit(
        (parsed.scheme.lower(), netloc, parsed.path.rstrip("/"), parsed.query, parsed.fragment)
    )