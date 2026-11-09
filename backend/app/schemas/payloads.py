from pydantic import BaseModel, HttpUrl, Field
from typing import List, Optional, Dict, Any
from enum import Enum

class RiskClassification(str, Enum):
    LOW_RISK = "Low Risk"
    SUSPICIOUS = "Suspicious"
    HIGH_RISK = "High Risk"
    CONFIRMED_MALICIOUS = "Confirmed Malicious"
    INCONCLUSIVE = "Inconclusive"

# --- Request Payloads ---
class URLAnalysisRequest(BaseModel):
    url: str = Field(..., example="https://suspicious-bank-login.com")

class MessageAnalysisRequest(BaseModel):
    content: str = Field(..., example="URGENT: Your bank account is locked. Verify at http://bit.ly/fake")
    context: Optional[str] = Field("SMS/Email", example="SMS")

# --- Component Results ---
class TLSCertReport(BaseModel):
    is_valid: bool
    subject: Optional[str] = None
    issuer: Optional[str] = None
    expiry_date: Optional[str] = None
    san_matches: bool = False
    is_untrusted_ca: bool = False
    notes: List[str] = []

class SecurityHeaderReport(BaseModel):
    missing_headers: List[str] = []
    exposed_server_info: Optional[str] = None
    has_hsts: bool = False
    has_csp: bool = False

# --- Unified Output Payload ---
class ThreatAnalysisResponse(BaseModel):
    target: str
    risk_level: RiskClassification
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    summary: str
    campaign_correlation: Dict[str, Any] = Field(default_factory=dict)
    detected_indicators: List[str] = []
    technical_evidence: Dict[str, Any] = {}
    recommended_actions: List[str] = []
    report_sha256: str
    on_chain_tx: Optional[str] = None