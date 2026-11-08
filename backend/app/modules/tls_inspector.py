import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, Any, List

# Distrusted or flagged CA identifiers / fingerprints
KNOWN_DISTRUSTED_CAS = [
    "emudhra",
    "wo_sign",
    "wosign",
    "startcom"
]

def inspect_tls_certificate(target_url: str, port: int = 443, timeout: float = 4.0) -> Dict[str, Any]:
    """
    Performs a live TLS handshake to extract certificate validity, SAN identity,
    and inspect Certificate Authority trust chains.
    """
    parsed = urlparse(target_url)
    hostname = parsed.hostname or target_url
    
    report: Dict[str, Any] = {
        "is_valid": False,
        "subject": None,
        "issuer": None,
        "expiry_date": None,
        "san_matches": False,
        "is_untrusted_ca": False,
        "notes": []
    }

    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                report["is_valid"] = True
                
                # Subject details
                subject_dict = dict(x[0] for x in cert.get("subject", ()))
                report["subject"] = subject_dict.get("commonName")
                
                # Issuer details
                issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                issuer_org = issuer_dict.get("organizationName", "") or issuer_dict.get("commonName", "")
                report["issuer"] = issuer_org
                
                # Distrusted CA check (eMudhra-like scenarios)
                for distrusted in KNOWN_DISTRUSTED_CAS:
                    if distrusted in issuer_org.lower():
                        report["is_untrusted_ca"] = True
                        report["notes"].append(f"Flagged Issuer: matches known compromised/distrusted CA list ({issuer_org})")

                # Expiry check
                not_after_str = cert.get("notAfter")
                if not_after_str:
                    expiry_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    report["expiry_date"] = expiry_dt.isoformat()
                    if datetime.utcnow() > expiry_dt:
                        report["is_valid"] = False
                        report["notes"].append("Certificate has expired")

                # SAN (Subject Alternative Names) matching
                san_list = [entry[1] for entry in cert.get("subjectAltName", ())]
                if hostname in san_list or any(hostname.endswith(s.lstrip("*")) for s in san_list if s.startswith("*")):
                    report["san_matches"] = True
                else:
                    report["notes"].append(f"Hostname mismatch: '{hostname}' not listed in SANs")

    except ssl.SSLCertVerificationError as e:
        report["is_valid"] = False
        report["notes"].append(f"SSL Verification Error: {str(e.verify_message)}")
    except socket.timeout:
        report["notes"].append("TLS Handshake timed out")
    except Exception as e:
        report["notes"].append(f"Connection failure: {str(e)}")

    return report