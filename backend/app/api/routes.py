from app.modules.extended_auditor import (
    check_certificate_transparency,
    audit_server_banner_vulnerabilities,
    inspect_public_metadata_endpoints
)
from app.modules.web3_logger import record_threat_on_chain
import hashlib
import time
import urllib.parse
from typing import Dict, Any, List
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
from app.modules.scam_analyzer import analyze_scam_with_ai
from app.modules.header_auditor import audit_security_headers
from app.modules.url_analyzer import analyze_url_structure, trace_redirects

router = APIRouter()

def compute_report_hash(target: str, risk: str, summary: str) -> str:
    payload = f"{target}|{risk}|{summary}|{int(time.time())}"
    return hashlib.sha256(payload.encode()).hexdigest()

def check_urlhaus_feed(target_url: str) -> Dict[str, Any]:
    """
    Passive threat intelligence check against URLhaus public API.
    """
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    try:
        resp = requests.post(endpoint, data={"url": target_url}, timeout=3.0)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "is_listed":
                return {
                    "is_listed": True,
                    "threat": data.get("threat", "Malicious URL"),
                    "tags": data.get("tags", [])
                }
    except Exception:
        pass
    return {"is_listed": False, "threat": None, "tags": []}

@router.post("/analyze/url", response_model=ThreatAnalysisResponse)
async def analyze_url_endpoint(payload: URLAnalysisRequest):
    # 1. Deterministic SSRF Guard
    target_url = validate_target_url(payload.url)
    
    # 2. TLS / Certificate Trust Inspector
    tls_data = inspect_tls_certificate(target_url)
    
    # 3. Live Threat Feed Lookup
    feed_data = check_urlhaus_feed(target_url)
    
    # 4. Passive Structural Heuristics & Typosquatting
    url_analysis = analyze_url_structure(target_url)
    redirect_chain = trace_redirects(target_url, max_hops=3, timeout=3.0)
    
    # 5. Passive Security Header Audit
    headers_audit = audit_security_headers(target_url, timeout=3.0)

    score = 10.0
    indicators: List[str] = []
    
    # DNS / Reachability check
    if tls_data.get("error") and "Could not resolve" in str(tls_data.get("error")):
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
    parsed_domain = urllib.parse.urlparse(target_url).hostname or ""
    ct_audit = check_certificate_transparency(parsed_domain)
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

    # Public metadata policy inspection
    metadata_audit = inspect_public_metadata_endpoints(target_url)
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

    return ThreatAnalysisResponse(
        target=target_url,
        risk_level=risk,
        confidence_score=round(min(score / 100.0, 1.0), 2),
        summary=summary,
        detected_indicators=indicators,
        technical_evidence=technical_evidence,
        recommended_actions=recommended,
        report_sha256=report_hash,
        on_chain_tx=tx_hash
    )

@router.post("/analyze/message", response_model=ThreatAnalysisResponse)
async def analyze_message_endpoint(payload: MessageAnalysisRequest):
    ai_result = analyze_scam_with_ai(payload.content, payload.context or "SMS/Email")
    
    score = 10.0
    indicators: List[str] = []
    
    if ai_result.get("is_scam"):
        score += 40.0
        indicators.append("Detected manipulative social engineering patterns")
        
    if ai_result.get("urgency_level") == "High":
        score += 25.0
        indicators.append("High urgency and psychological coercion")
        
    red_flags = ai_result.get("red_flags", [])
    for rf in red_flags:
        if rf not in indicators:
            indicators.append(rf)
            
    entities = ai_result.get("extracted_entities", {})
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

    return ThreatAnalysisResponse(
        target="Pasted Message",
        risk_level=risk,
        confidence_score=round(min(score / 100.0, 1.0), 2),
        summary=summary,
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