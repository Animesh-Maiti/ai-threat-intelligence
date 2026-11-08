import hashlib
import time
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

router = APIRouter()

def compute_report_hash(target: str, risk: str, summary: str) -> str:
    payload = f"{target}|{risk}|{summary}|{int(time.time())}"
    return hashlib.sha256(payload.encode()).hexdigest()

def check_urlhaus_feed(target_url: str) -> Dict[str, Any]:
    """
    Passive threat intelligence check against URLhaus public API.
    """
    endpoint = "[https://urlhaus-api.abuse.ch/v1/url/](https://urlhaus-api.abuse.ch/v1/url/)"
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
    # 1. SSRF Guard
    target_url = validate_target_url(payload.url)
    
    # 2. TLS / Trust Inspector
    tls_data = inspect_tls_certificate(target_url)
    
    # 3. Live Threat Feed Lookup
    feed_data = check_urlhaus_feed(target_url)
    
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

    # Official 5-tier mapping
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

    return ThreatAnalysisResponse(
        target=target_url,
        risk_level=risk,
        confidence_score=round(min(score / 100.0, 1.0), 2),
        summary=summary,
        detected_indicators=indicators,
        technical_evidence={"tls": tls_data, "threat_intel": feed_data},
        recommended_actions=recommended,
        report_sha256=report_hash,
        on_chain_tx=None
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
        on_chain_tx=None
    )