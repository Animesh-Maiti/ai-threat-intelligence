"""URL threat analysis."""

from __future__ import annotations

import codecs
import contextlib
import http.client
import ipaddress
import math
import socket
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import urljoin, urlsplit

_BRAND_NAMES = (
    "paypal",
    "google",
    "microsoft",
    "apple",
    "amazon",
    "netflix",
    "sbi",
    "hdfc",
    "icici",
)

_SUSPICIOUS_KEYWORDS = ("login", "verify", "update", "secure", "account", "signin")
_HOMOGLYPH_MAP = {
    "а": "a",
    "е": "e",
    "ё": "e",
    "і": "i",
    "ј": "j",
    "к": "k",
    "м": "m",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "в": "b",
    "г": "g",
    "д": "d",
    "з": "z",
    "л": "l",
    "н": "n",
    "т": "t",
    "й": "r",
    "ц": "c",
    "ш": "sh",
    "щ": "shch",
    "ъ": "",
    "э": "e",
    "ю": "yu",
    "я": "ya",
    "α": "a",
    "β": "b",
    "γ": "g",
    "δ": "d",
    "ε": "e",
    "η": "n",
    "ι": "i",
    "κ": "k",
    "λ": "l",
    "μ": "m",
    "ν": "v",
    "ο": "o",
    "ρ": "p",
    "σ": "s",
    "τ": "t",
    "υ": "y",
    "φ": "f",
    "χ": "x",
    "ψ": "y",
    "ω": "w",
    "ς": "s",
    "ϕ": "f",
    "ϵ": "e",
    "А": "A",
    "Е": "E",
    "Ё": "E",
    "І": "I",
    "К": "K",
    "М": "M",
    "О": "O",
    "Р": "P",
    "С": "C",
    "У": "Y",
    "Х": "X",
    "В": "B",
    "Г": "G",
    "Д": "D",
    "З": "Z",
    "Л": "L",
    "Н": "H",
    "Т": "T",
    "Й": "R",
    "Ц": "C",
    "Ш": "SH",
    "Щ": "SHCH",
    "Ъ": "",
    "Э": "E",
    "Ю": "YU",
    "Я": "YA",
    "Α": "A",
    "Β": "B",
    "Γ": "G",
    "Δ": "D",
    "Ε": "E",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Λ": "L",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Σ": "S",
    "Τ": "T",
    "Υ": "Y",
    "Φ": "F",
    "Χ": "X",
    "Ψ": "Y",
    "Ω": "W",
}


class NoRedirectHandler(urllib_request.HTTPRedirectHandler):
    """Prevent automatic redirect following for passive audits."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connect to a validated IP while preserving the original hostname for Host headers."""

    def __init__(self, host: str, port: Optional[int] = None, timeout: Optional[float] = None, validated_ip: Optional[str] = None):
        self._validated_ip = validated_ip
        super().__init__(host, port=port, timeout=timeout)

    def connect(self) -> None:
        if not self._validated_ip:
            super().connect()
            return
        self.sock = socket.create_connection((self._validated_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to a validated IP while verifying TLS against the original hostname."""

    def __init__(self, host: str, port: Optional[int] = None, timeout: Optional[float] = None, validated_ip: Optional[str] = None):
        self._validated_ip = validated_ip
        super().__init__(host, port=port, timeout=timeout)

    def connect(self) -> None:
        if not self._validated_ip:
            super().connect()
            return
        self.sock = socket.create_connection((self._validated_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def _resolve_validated_ip(hostname: str) -> Optional[str]:
    """Resolve a hostname and return the first non-blocked IP address."""
    if not hostname:
        return None

    try:
        ip_address = ipaddress.ip_address(hostname)
    except ValueError:
        ip_address = None

    if ip_address is not None:
        return str(ip_address) if not _is_blocked_ip(str(ip_address)) else None

    addresses: List[str] = []
    for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM):
        ip = sockaddr[0]
        if ip and ip not in addresses:
            addresses.append(ip)

    for ip in addresses:
        if not _is_blocked_ip(ip):
            return ip
    return None


def _open_validated_request(url: str, method: str = "HEAD", timeout: float = 3.5, headers: Optional[Dict[str, str]] = None):
    """Open an HTTP request while pinning the actual TCP connection to a validated IP."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("Malformed URL")

    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Malformed URL")

    valid, reason = _validate_destination_url(url)
    if not valid:
        raise ValueError(reason or "Destination validation failed")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid hostname")

    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    validated_ip = _resolve_validated_ip(hostname)
    if not validated_ip:
        raise ValueError(f"Blocked or unresolvable destination: {hostname}")

    request_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36", "Connection": "close"}
    if headers:
        request_headers.update(headers)

    if parsed.scheme.lower() == "https":
        conn = _PinnedHTTPSConnection(hostname, port=port, timeout=timeout, validated_ip=validated_ip)
    else:
        conn = _PinnedHTTPConnection(hostname, port=port, timeout=timeout, validated_ip=validated_ip)

    try:
        request_target = parsed.path or "/"
        if parsed.query:
            request_target = f"{request_target}?{parsed.query}"
        conn.request(method.upper(), request_target, headers=request_headers)
        return conn.getresponse(), conn
    except Exception:
        conn.close()
        raise


def _safe_hostname(raw_domain: str) -> str:
    """Return a normalized hostname without query strings or credentials."""
    if not isinstance(raw_domain, str):
        return ""

    candidate = raw_domain.strip().lower()
    candidate = candidate.rstrip(".")
    if not candidate:
        return ""

    try:
        parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
    except ValueError:
        parsed = None

    if parsed is not None and parsed.hostname:
        candidate = parsed.hostname
    else:
        candidate = candidate.rsplit("@", 1)[-1]
        candidate = candidate.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if candidate.startswith("[") and candidate.endswith("]"):
            candidate = candidate[1:-1]
        if ":" in candidate and candidate.count(":") == 1 and candidate.rsplit(":", 1)[1].isdigit():
            candidate = candidate.rsplit(":", 1)[0]

    return (candidate or "").strip("[]").rstrip(".").lower()


def _decode_idn_label(label: str) -> str:
    """Decode a Punycode label to Unicode when possible."""
    if not label:
        return ""
    text = label.strip().lower()
    if not text:
        return ""
    if text.startswith("xn--"):
        try:
            return codecs.decode(text.encode("ascii"), "idna")
        except (LookupError, TypeError, ValueError, UnicodeError):
            return text
    return text


def _normalize_domain(domain: str) -> str:
    """Normalize a domain name while preserving the hostname and decoding IDNs."""
    hostname = _safe_hostname(domain)
    if not hostname:
        return ""

    labels = []
    for label in hostname.split("."):
        if not label:
            continue
        labels.append(_decode_idn_label(label))
    return ".".join(labels)


def _homoglyph_normalize(value: str) -> str:
    """Translate common homoglyph letters to their Latin counterparts."""
    if not value:
        return ""
    result: List[str] = []
    for char in value:
        result.append(_HOMOGLYPH_MAP.get(char, char))
    return "".join(result)


def _is_blocked_ip(ip_value: str) -> bool:
    """Return True when an IP is within blocked or private network ranges."""
    try:
        ip = ipaddress.ip_address(ip_value)
    except ValueError:
        return True

    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True
    if str(ip) == "169.254.169.254":
        return True
    if ip.version == 6 and ip.is_site_local:
        return True
    return False


def _validate_destination_url(raw_url: str) -> Tuple[bool, Optional[str]]:
    """Validate a URL against SSRF and scheme restrictions before network access.

    Returns (True, hostname) for safe destinations and (False, reason) for blocked or
    malformed destinations. Any resolved IP that falls within loopback, private,
    link-local, reserved, multicast, unspecified, or metadata ranges is rejected.
    """
    if not isinstance(raw_url, str) or not raw_url.strip():
        return False, "Malformed URL"

    try:
        parsed = urlsplit(raw_url)
    except ValueError:
        return False, "Malformed URL"

    if parsed.scheme.lower() not in {"http", "https"}:
        return False, "Unsupported URL scheme"
    if parsed.username is not None or parsed.password is not None:
        return False, "Embedded credentials are not allowed"

    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid hostname"

    hostname = hostname.strip("[]").rstrip(".").lower()
    if not hostname or any(ch.isspace() for ch in hostname):
        return False, "Invalid hostname"

    try:
        ip_address = ipaddress.ip_address(hostname)
    except ValueError:
        ip_address = None
    if ip_address is not None and _is_blocked_ip(str(ip_address)):
        return False, f"Blocked destination {hostname}"

    try:
        ip_addresses = []
        for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM):
            ip = sockaddr[0]
            if ip:
                ip_addresses.append(ip)
    except (socket.gaierror, OSError, ValueError):
        return False, f"DNS resolution failed for {hostname}"

    if not ip_addresses:
        return False, f"No IP addresses resolved for {hostname}"

    for ip in ip_addresses:
        if _is_blocked_ip(ip):
            return False, f"Blocked destination resolved to {ip}"

    return True, hostname


def calculate_entropy(domain: str) -> float:
    """Calculate Shannon entropy for a string of characters."""
    if not isinstance(domain, str):
        return 0.0
    if not domain:
        return 0.0

    counts = Counter(domain)
    length = len(domain)
    if length <= 1:
        return 0.0

    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return float(entropy)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Return the Levenshtein edit distance between two strings."""
    if s1 is None:
        s1 = ""
    if s2 is None:
        s2 = ""

    s1 = str(s1)
    s2 = str(s2)

    if s1 == s2:
        return 0
    if not s1:
        return len(s2)
    if not s2:
        return len(s1)

    if len(s1) < len(s2):
        s1, s2 = s2, s1

    previous_row = list(range(len(s2) + 1))
    for i, left in enumerate(s1, 1):
        current_row = [i]
        for j, right in enumerate(s2, 1):
            insert_cost = current_row[j - 1] + 1
            delete_cost = previous_row[j] + 1
            replace_cost = previous_row[j - 1] + (left != right)
            current_row.append(min(insert_cost, delete_cost, replace_cost))
        previous_row = current_row
    return previous_row[-1]


def check_typosquatting(domain: str) -> Dict[str, Any]:
    """Detect suspicious brand impersonation and homoglyph abuse."""
    original_domain = domain if isinstance(domain, str) else ""
    normalized_domain = _normalize_domain(original_domain)
    hostname = _safe_hostname(original_domain)

    result: Dict[str, Any] = {
        "is_typosquatting": False,
        "is_homoglyph": False,
        "matched_brand": None,
        "levenshtein_distance": 0,
        "original_domain": original_domain,
        "normalized_domain": normalized_domain,
        "flags": [],
    }

    if not hostname:
        result["flags"] = ["malformed_domain"]
        return result

    flags = set()

    if any(label.startswith("xn--") for label in hostname.split(".")):
        flags.add("punycode_label")
    if any(any((char not in "abcdefghijklmnopqrstuvwxyz0123456789-." and char != "") for char in label) for label in hostname.split(".")):
        flags.add("non_ascii_hostname")

    labels = [label for label in normalized_domain.split(".") if label]
    if not labels:
        return result

    best_brand = None
    best_distance = 0

    for brand in _BRAND_NAMES:
        for label in labels:
            if label == brand:
                continue
            candidates = {label, _homoglyph_normalize(label)}
            for candidate in sorted(candidates):
                distance = levenshtein_distance(candidate, brand)
                if distance <= 2:
                    if best_brand is None or distance < best_distance or (distance == best_distance and brand < best_brand):
                        best_brand = brand
                        best_distance = distance
                    flags.add("brand_lookalike")
                    flags.add(f"resemble_{brand}")
                    if candidate != label:
                        flags.add("homoglyph_match")

    if best_brand is not None and best_distance > 0:
        result["is_typosquatting"] = True
        result["matched_brand"] = best_brand
        result["levenshtein_distance"] = best_distance
        result["flags"] = sorted(flags)
        if "homoglyph_match" in flags or "non_ascii_hostname" in flags or any(ch in _HOMOGLYPH_MAP for ch in hostname):
            result["is_homoglyph"] = True
        return result

    if any(ch in _HOMOGLYPH_MAP for ch in hostname):
        result["is_homoglyph"] = True
        flags.add("homoglyph_characters_detected")

    result["flags"] = sorted(flags)
    return result


def analyze_url_structure(url: str) -> Dict[str, Any]:
    """Analyze a URL structure for suspicious patterns without making network requests."""
    result: Dict[str, Any] = {
        "is_homoglyph": False,
        "matched_brand": None,
        "levenshtein_distance": 0,
        "entropy_score": 0.0,
        "redirect_chain": [],
        "suspicious_flags": [],
    }

    if not isinstance(url, str) or not url.strip():
        result["suspicious_flags"] = ["malformed_url"]
        return result

    original_url = url.strip()
    result["redirect_chain"] = [original_url]

    try:
        parsed = urlsplit(original_url)
    except ValueError:
        result["suspicious_flags"].append("malformed_url")
        return result

    scheme = parsed.scheme.lower() if parsed.scheme else ""
    hostname = parsed.hostname or _safe_hostname(original_url)
    if not hostname:
        result["suspicious_flags"].append("malformed_url")
        return result

    if scheme not in {"http", "https"}:
        result["suspicious_flags"].append("unsupported_scheme")

    if parsed.username is not None or parsed.password is not None:
        result["suspicious_flags"].append("embedded_credentials")

    normalized_domain = _normalize_domain(hostname)
    typo_result = check_typosquatting(hostname)

    if typo_result.get("matched_brand"):
        result["matched_brand"] = typo_result["matched_brand"]
        result["levenshtein_distance"] = int(typo_result.get("levenshtein_distance", 0))
        result["is_homoglyph"] = bool(typo_result.get("is_homoglyph"))

    if typed_flags := typo_result.get("flags"):
        for flag in typed_flags:
            if flag not in result["suspicious_flags"]:
                result["suspicious_flags"].append(flag)

    if any(label.startswith("xn--") for label in hostname.split(".")):
        result["suspicious_flags"].append("punycode_label")

    if hostname.count(".") > 3:
        result["suspicious_flags"].append("excessive_subdomains")

    lowered = original_url.lower()
    for keyword in _SUSPICIOUS_KEYWORDS:
        if keyword in lowered:
            result["suspicious_flags"].append(keyword)

    result["entropy_score"] = calculate_entropy(hostname)
    result["suspicious_flags"] = sorted(set(result["suspicious_flags"]))

    result["hostname"] = hostname
    result["normalized_domain"] = normalized_domain
    result["original_url"] = original_url
    result["scheme"] = scheme
    result["is_malformed"] = "malformed_url" in result["suspicious_flags"]
    return result


def trace_redirects(url: str, max_hops: int = 5, timeout: float = 3.5) -> List[str]:
    """Passively trace redirect chains while enforcing SSRF protections.

    A failed validation causes an empty list to be returned so blocked destinations
    are never treated as a successful redirect chain.
    """
    if not isinstance(url, str) or not url.strip():
        return []

    chain = [url.strip()]
    current_url = url.strip()
    seen: set[str] = set()
    hop_limit = min(5, max(0, int(max_hops or 0))) if max_hops is not None else 5
    request_timeout = min(3.5, float(timeout or 3.5))
    if request_timeout <= 0:
        request_timeout = 3.5

    for _ in range(hop_limit):
        if current_url in seen:
            break
        seen.add(current_url)

        valid, _ = _validate_destination_url(current_url)
        if not valid:
            return []

        try:
            response, conn = _open_validated_request(current_url, method="HEAD", timeout=request_timeout)
            try:
                status_code = getattr(response, "status", None) or response.status
                if status_code not in {301, 302, 303, 307, 308}:
                    return chain
                location = response.getheader("Location")
                if not location:
                    return chain
                next_url = urljoin(current_url, location)
                if not next_url:
                    return chain
                valid_next, _ = _validate_destination_url(next_url)
                if not valid_next:
                    return []
                if next_url in seen:
                    chain.append(next_url)
                    break
                current_url = next_url
                chain.append(current_url)
            finally:
                response.close()
                conn.close()
        except (urllib_error.HTTPError, urllib_error.URLError, OSError, ValueError, socket.timeout):
            return chain

    return chain


__all__ = [
    "calculate_entropy",
    "levenshtein_distance",
    "check_typosquatting",
    "analyze_url_structure",
    "trace_redirects",
]
