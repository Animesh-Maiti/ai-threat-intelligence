import os
import re
import json
import logging
from typing import Dict, Any, List
import google.generativeai as genai

logger = logging.getLogger(__name__)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
if GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
    except Exception:
        pass

URL_PATTERN = re.compile(
    r"(?<![@\w.-])(?:hxxps?|https?)\s*[:：]\s*//\s*"
    r"(?:(?:[a-z0-9-]+)\s*(?:\.|\[\.\]|\(\.\)|\{\.\})\s*)+"
    r"[a-z]{2,63}(?::\d{1,5})?(?:/[^\s<>\"']*)?"
    r"|(?<![@\w.-])(?:www\s*(?:\.|\[\.\]|\(\.\)|\{\.\})\s*)?"
    r"(?:[a-z0-9-]+\s*(?:\.|\[\.\]|\(\.\)|\{\.\})\s*)+"
    r"[a-z]{2,63}(?::\d{1,5})?(?:/[^\s<>\"']*)?",
    re.IGNORECASE,
)
EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+")
PHONE_PATTERN = r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
UPI_PATTERN = r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}'
_OBFUSCATED_DOT_PATTERN = re.compile(r"\s*(?:\[\.\]|\(\.\)|\{\.\})\s*", re.IGNORECASE)
_OBFUSCATED_AT_PATTERN = re.compile(r"\s*(?:\[at\]|\(at\)|\{at\})\s*", re.IGNORECASE)
_URGENCY_KEYWORDS = (
    "urgent",
    "immediately",
    "suspended",
    "blocked",
    "kyc",
    "otp",
    "deactivated",
    "lottery",
    "cashback",
    "pan",
    "arrest",
    "fine",
    "refund",
)


def sanitize_message_content(content: str) -> str:
    """Normalize line endings and remove invisible controls without flattening pasted text."""
    return content.replace("\x00", "").replace("\u200b", "").replace("\ufeff", "").replace("\r\n", "\n").replace("\r", "\n").strip()


def _normalize_obfuscated_text(text: str) -> str:
    normalized = _OBFUSCATED_AT_PATTERN.sub("@", text)
    normalized = _OBFUSCATED_DOT_PATTERN.sub(".", normalized)
    normalized = re.sub(r"(?i)\bhxxps(?=://)", "https", normalized)
    return re.sub(r"(?i)\bhxxp(?=://)", "http", normalized)

def extract_message_entities(text: str) -> Dict[str, List[str]]:
    normalized_text = _normalize_obfuscated_text(sanitize_message_content(text))
    url_matches = URL_PATTERN.finditer(normalized_text)
    urls = []
    for match in url_matches:
        candidate = match.group(0).strip().rstrip(".,;:!?)]}")
        candidate = re.sub(r"\s+", "", candidate)
        if not candidate.lower().startswith(("http://", "https://")):
            candidate = "https://" + candidate
        if candidate not in urls:
            urls.append(candidate)

    emails = list(dict.fromkeys(EMAIL_PATTERN.findall(normalized_text)))
    phones = list(dict.fromkeys(re.findall(PHONE_PATTERN, normalized_text)))
    raw_upis = re.findall(UPI_PATTERN, normalized_text)
    
    upis = [u for u in raw_upis if u not in emails and any(handle in u for handle in ['@oksbi', '@okhdfcbank', '@paytm', '@ibl', '@ybl', '@axl', '@upi'])]

    return {
        "extracted_urls": urls,
        "extracted_emails": emails,
        "extracted_phones": phones,
        "extracted_upis": list(dict.fromkeys(upis))
    }

def analyze_scam_with_ai(content: str, context: str = "SMS/Email") -> Dict[str, Any]:
    content = sanitize_message_content(content)
    entities = extract_message_entities(content)
    lower_content = _normalize_obfuscated_text(content).lower()
    urgency_matches = [keyword for keyword in _URGENCY_KEYWORDS if re.search(rf"\b{re.escape(keyword)}\b", lower_content)]
    is_urgent = bool(urgency_matches)

    fallback_result = {
        "is_scam": is_urgent or len(entities["extracted_urls"]) > 0 or len(entities["extracted_upis"]) > 0,
        "urgency_level": "High" if len(urgency_matches) >= 2 else ("Medium" if is_urgent else "Low"),
        "impersonated_brand": "Financial / Institutional Entity" if any(term in lower_content for term in ("bank", "sbi", "hdfc", "icici", "account", "pan", "kyc")) else "Unspecified",
        "intent": "Credential harvesting or unauthorized payment transfer",
        "red_flags": [
            "Coercive urgency tactics detected",
            "Direct external action/link provided in unverified message"
        ] if is_urgent else ["External link or communication handle detected"],
        "explanation": "The message demands immediate compliance and includes external interaction links or handles.",
        "extracted_entities": entities
    }

    if not GEMINI_API_KEY:
        return fallback_result

    prompt = f"""
You are a Principal Cybersecurity Analyst.
Analyze the following untrusted {context} message for social engineering, financial fraud, and credential harvesting patterns.

Message Body:
\"\"\"{content}\"\"\"

Respond STRICTLY with a valid JSON object matching this schema with no markdown formatting:
{{
  "is_scam": true,
  "urgency_level": "Low" | "Medium" | "High",
  "impersonated_brand": "brand name or Unknown",
  "intent": "detected attacker goal",
  "red_flags": ["point 1", "point 2"],
  "explanation": "2 sentence clear summary of technical and psychological manipulation observed"
}}
"""
    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt, request_options={"timeout": 10})
        raw_text = response.text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        parsed = json.loads(raw_text)
        if not isinstance(parsed, dict):
            raise ValueError("Gemini response was not a JSON object")
        parsed["extracted_entities"] = entities
        return parsed
    except Exception as exc:
        logger.warning(
            "Gemini message analysis failed; using heuristic fallback (%s)",
            type(exc).__name__,
        )
        return fallback_result