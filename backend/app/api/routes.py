from app.modules.extended_auditor import (
    check_certificate_transparency,
    audit_server_banner_vulnerabilities,
    inspect_public_metadata_endpoints
)
from app.modules.web3_logger import record_threat_on_chain
import hashlib
import ipaddress
import ssl
import socket
import time
import urllib.error
import urllib.parse
from concurrent.futures import Future, ThreadPoolExecutor, wait
from typing import Dict, Any, List, Optional
import requests
from fastapi import APIRouter

from app.schemas.payloads import (
    URLAnalysisRequest, 
    MessageAnalysisRequest, 
    ThreatAnalysisResponse, 
    RiskClassification
)
from app.core.security import validate_target_url
from app.modules.tls_inspector import inspect_tls_certificate
from app.modules.scam_analyzer import analyze_scam_with_ai, sanitize_message_content
from app.modules.header_auditor import audit_security_headers
from app.modules.url_analyzer import analyze_url_structure, trace_redirects
from app.modules.campaign_correlator import correlate_incident

router = APIRouter()

_PROBE_ERRORS = (
    socket.gaierror,
    urllib.error.URLError,
    requests.RequestException,
    ssl.SSLError,
    OSError,
    TimeoutError,
)
_HIGH_RISK_TLDS = {
    "buzz",
    "click",
    "icu",
    "info",
    "link",
    "live",
    "online",
    "rest",
    "site",
    "support",
    "top",
    "work",
    "xyz",
}
_PROBE_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="threat-probe")
_PROBE_WAIT_SECONDS = 1.8


def resolve_incident_ip(domain: str) -> Optional[str]:
    if not domain:
        return None
    try:
        return str(ipaddress.ip_address(domain))
    except ValueError:
        pass
    try:
        return socket.gethostbyname(domain)
    except (socket.gaierror, OSError):
        return None


def compute_report_hash(target: str, risk: str, summary: str) -> str:
    payload = f"{target}|{risk}|{summary}|{int(time.time())}"
    return hashlib.sha256(payload.encode()).hexdigest()


def _get_probe_result(future: Future, completed: set[Future], fallback: Any) -> Any:
    if future not in completed:
        return fallback
    try:
        return future.result()
    except _PROBE_ERRORS + (ValueError, TypeError, KeyError):
        return fallback


def check_urlhaus_feed(target_url: str) -> Dict[str, Any]:
    """
    Passive threat intelligence check against URLhaus public API.
    """
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    try:
        resp = requests.post(endpoint, data={"url": target_url}, timeout=1.5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "is_listed":
                return {
                    "is_listed": True,
                    "threat": data.get("threat", "Malicious URL"),
                    "tags": data.get("tags", [])
                }
    except (requests.RequestException, ValueError):
        pass
    return {"is_listed": False, "threat": None, "tags": []}


@router.post("/analyze/url", response_model=ThreatAnalysisResponse)
async def analyze_url_endpoint(payload: URLAnalysisRequest):
    # 1. Deterministic SSRF Guard
    target_url = validate_target_url(payload.url)

    parsed_domain = urllib.parse.urlsplit(target_url).hostname or ""

    tls_fallback = {
        "is_valid": False,
        "subject": None,
        "issuer": None,
        "expiry_date": None,
        "san_matches": False,
        "is_untrusted_ca": False,
        "notes": ["Connection unavailable during the scan time limit"],
        "error": "Target host unavailable",
    }
    headers_fallback = {
        "missing_headers": [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
        ],
        "exposed_server": None,
        "exposed_powered_by": None,
        "error": "Request failed",
    }

    probes = {
        "resolved_ip": _PROBE_EXECUTOR.submit(resolve_incident_ip, parsed_domain),
        "tls": _PROBE_EXECUTOR.submit(inspect_tls_certificate, target_url, timeout=1.5),
        "feed": _PROBE_EXECUTOR.submit(check_urlhaus_feed, target_url),
        "redirects": _PROBE_EXECUTOR.submit(
            trace_redirects, target_url, max_hops=1, timeout=1.5
        ),
        "headers": _PROBE_EXECUTOR.submit(
            audit_security_headers, target_url, timeout=1.5
        ),
        "ct": _PROBE_EXECUTOR.submit(
            check_certificate_transparency, parsed_domain, timeout=1.2
        ),
        "metadata": _PROBE_EXECUTOR.submit(
            inspect_public_metadata_endpoints, target_url, timeout=1.0
        ),
    }
    completed_probes, pending_probes = wait(
        probes.values(), timeout=_PROBE_WAIT_SECONDS
    )
    for pending_probe in pending_probes:
        pending_probe.cancel()
    resolved_ip = _get_probe_result(probes["resolved_ip"], completed_probes, None)
    tls_data = _get_probe_result(probes["tls"], completed_probes, tls_fallback)
    feed_data = _get_probe_result(
        probes["feed"], completed_probes, {"is_listed": False, "threat": None, "tags": []}
    )
    redirect_chain = _get_probe_result(probes["redirects"], completed_probes, [target_url])
    headers_audit = _get_probe_result(probes["headers"], completed_probes, headers_fallback)
    ct_audit = _get_probe_result(
        probes["ct"], completed_probes, {"ct_logged": None, "status": "upstream_skipped"}
    )
    metadata_audit = _get_probe_result(
        probes["metadata"],
        completed_probes,
        {
            "security_txt": {"accessible": False, "status_code": None},
            "robots_txt": {"accessible": False, "status_code": None},
        },
    )

    # Passive Structural Heuristics & Typosquatting
    url_analysis = analyze_url_structure(target_url)

    score = 10.0
    indicators: List[str] = []

    # DNS / Reachability check
    tls_notes = " ".join(str(note) for note in tls_data.get("notes", []))
    host_unreachable = (
        resolved_ip is None
        or tls_data.get("error") == "Target host unavailable"
        or "timed out" in tls_notes.lower()
        or "connection failure" in tls_notes.lower()
        or headers_audit.get("error") == "Request failed"
    )
    if host_unreachable:
        score += 45.0
        indicators.append(
            "Target host appears unreachable, inactive, or unresolvable at scan time"
        )
    elif tls_data.get("error") and "Could not resolve" in str(tls_data.get("error")):
        score += 45.0
        indicators.append("Domain does not resolve via public DNS (potentially sinkholed, inactive, or malformed)")

    # Feed hits trigger confirmed malicious classification
    if feed_data.get("is_listed"):
        score = 95.0
        indicators.append(f"Blacklist Match: URLhaus tagged as {feed_data.get('threat')}")

    if not tls_data.get("is_valid") and not (tls_data.get("error") and "resolve" in str(tls_data.get("error"))):
        score += 40.0
        indicators.append("Invalid or unverified SSL/TLS Certificate")
        
    if tls_data.get("is_untrusted_ca"):
        score += 50.0
        indicators.append("Certificate issued by known distrusted/compromised CA (e.g. eMudhra/WoSign)")
        
    if not tls_data.get("san_matches") and tls_data.get("is_valid"):
        score += 25.0
        indicators.append("Hostname mismatch against Subject Alternative Names (SAN)")

    # Heuristic scoring additions
    if url_analysis.get("is_homoglyph"):
        score += 35.0
        indicators.append("Homoglyph / Punycode character obfuscation detected in domain")

    if matched_brand := url_analysis.get("matched_brand"):
        score += 30.0
        indicators.append(f"Typosquatting brand impersonation targeting '{matched_brand}'")

    if url_analysis.get("entropy_score", 0.0) > 4.2:
        score += 15.0
        indicators.append(f"High domain randomness/entropy ({url_analysis.get('entropy_score'):.2f}) indicative of DGA")

    tld = parsed_domain.rsplit(".", 1)[-1].lower() if "." in parsed_domain else ""
    if tld in _HIGH_RISK_TLDS:
        score += 10.0
        indicators.append(f"Uses a high-risk top-level domain (TLD: .{tld})")

    for flag in url_analysis.get("suspicious_flags", []):
        if flag in {"excessive_subdomains", "embedded_credentials"} and flag not in indicators:
            score += 10.0
            indicators.append(f"Suspicious URL pattern: {flag.replace('_', ' ')}")

    # Defensive header check (lack of defensive headers slightly increases risk baseline)
    missing_headers = headers_audit.get("missing_headers", [])
    if len(missing_headers) >= 3:
        score += 5.0
        indicators.append(f"Lacks critical defensive headers: {', '.join(missing_headers[:2])}")

    technical_evidence = {
        "tls": tls_data,
        "threat_intel": feed_data,
        "url_structure": url_analysis,
        "redirect_chain": redirect_chain,
        "security_headers": headers_audit,
    }

    # Certificate Transparency (CT) logging audit
    if ct_audit.get("ct_logged") is False and "error" in ct_audit:
        if "No Certificate Transparency records" in ct_audit["error"]:
            indicators.append("Certificate Transparency anomaly: domain not found in public CT append-only logs.")
            score += 15

    # Known software and version vulnerability check
    server_hdr = headers_audit.get("exposed_server") or ""
    powered_hdr = headers_audit.get("exposed_powered_by") or ""
    cve_indicators = audit_server_banner_vulnerabilities(server_hdr, powered_hdr)
    if cve_indicators:
        indicators.extend(cve_indicators)
        score += 20

    technical_evidence["certificate_transparency"] = ct_audit
    technical_evidence["public_metadata_endpoints"] = metadata_audit
    technical_evidence["security_policy_present"] = metadata_audit.get(
        "security_txt", {}
    ).get("accessible", False)

    # Classify and generate the report after all audit findings have been scored.
    if score >= 85.0:
        risk = RiskClassification.CONFIRMED_MALICIOUS
    elif score >= 50.0:
        risk = RiskClassification.HIGH_RISK
    elif score >= 25.0:
        risk = RiskClassification.SUSPICIOUS
    else:
        risk = RiskClassification.LOW_RISK

    summary = (
        f"Domain certificate status: {'Valid' if tls_data.get('is_valid') else 'Untrusted/Invalid/Unreachable'}. "
        f"Found {len(indicators)} technical security indicator(s)."
    )

    recommended = [
        "Do not enter passwords, OTPs, or financial information on unverified domains.",
        "Check that the address bar matches the official organization domain exactly."
    ]

    report_hash = compute_report_hash(target_url, risk.value, summary)

    tx_hash = record_threat_on_chain(
        report_sha256=report_hash,
        target=target_url,
        risk_level=risk.value,
        confidence_score=round(min(score / 100.0, 1.0), 2)
    )

    campaign_correlation = correlate_incident({
        "target": target_url,
        "target_domain": parsed_domain,
        "brand_targeted": url_analysis.get("matched_brand"),
        "resolved_ip": resolved_ip,
        "indicators": indicators,
    })

    return ThreatAnalysisResponse(
        target=target_url,
        risk_level=risk,
        confidence_score=round(min(score / 100.0, 1.0), 2),
        summary=summary,
        campaign_correlation=campaign_correlation,
        detected_indicators=indicators,
        technical_evidence=technical_evidence,
        recommended_actions=recommended,
        report_sha256=report_hash,
        on_chain_tx=tx_hash
    )

@router.post("/analyze/message", response_model=ThreatAnalysisResponse)
async def analyze_message_endpoint(payload: MessageAnalysisRequest):
    cleaned_content = sanitize_message_content(payload.content)
    ai_result = analyze_scam_with_ai(cleaned_content, payload.context or "SMS/Email")
    
    score = 10.0
    indicators: List[str] = []
    
    if ai_result.get("is_scam"):
        score += 40.0
        indicators.append("Detected manipulative social engineering patterns")
        
    if ai_result.get("urgency_level") == "High":
        score += 25.0
        indicators.append("High urgency and psychological coercion")
        
    red_flags = ai_result.get("red_flags", [])
    if not isinstance(red_flags, list):
        red_flags = [str(red_flags)] if red_flags else []
    for rf in red_flags:
        if rf not in indicators:
            indicators.append(rf)
            
    entities = ai_result.get("extracted_entities", {})
    if not isinstance(entities, dict):
        entities = {}
    extracted_urls = entities.get("extracted_urls", [])
    if not isinstance(extracted_urls, list):
        extracted_urls = []
    if entities.get("extracted_urls"):
        score += 15.0
        indicators.append(f"Contains external link: {', '.join(entities['extracted_urls'])}")

    if score >= 75.0:
        risk = RiskClassification.HIGH_RISK
    elif score >= 25.0:
        risk = RiskClassification.SUSPICIOUS
    else:
        risk = RiskClassification.LOW_RISK

    summary = ai_result.get("explanation", "Scam communication assessment complete.")
    report_hash = compute_report_hash("Raw Message Payload", risk.value, summary)

    # Record report integrity on-chain
    tx_hash = record_threat_on_chain(
        report_sha256=report_hash,
        target="Pasted Message",
        risk_level=risk.value,
        confidence_score=round(min(score / 100.0, 1.0), 2)
    )

    message_domain = None
    if extracted_urls:
        try:
            message_domain = urllib.parse.urlsplit(extracted_urls[0]).hostname
        except ValueError:
            message_domain = None
    brand_targeted = ai_result.get("impersonated_brand")
    campaign_correlation = correlate_incident({
        "target": extracted_urls[0] if extracted_urls else "Pasted Message",
        "target_domain": message_domain,
        "brand_targeted": brand_targeted,
        "resolved_ip": resolve_incident_ip(message_domain or ""),
        "indicators": indicators,
    })

    return ThreatAnalysisResponse(
        target="Pasted Message",
        risk_level=risk,
        confidence_score=round(min(score / 100.0, 1.0), 2),
        summary=summary,
        campaign_correlation=campaign_correlation,
        detected_indicators=indicators,
        technical_evidence=ai_result,
        recommended_actions=[
            "Never share OTPs, passwords, or personal credentials over unverified messages.",
            "Verify sender identity directly through official support channels."
        ],
        report_sha256=report_hash,
        on_chain_tx=tx_hash
    )

from app.modules.web3_logger import verify_threat_on_chain

@router.get("/verify/hash/{report_hash}")
async def verify_report_hash_endpoint(report_hash: str):
    """
    Independent ledger lookup verifying report integrity and transaction receipt.
    """
    verification = verify_threat_on_chain(report_hash)
    return {
        "report_sha256": report_hash,
        "is_verified": verification.get("verified", False),
        "on_chain_tx": verification.get("tx_hash"),
        "audit_data": verification.get("data")
    }