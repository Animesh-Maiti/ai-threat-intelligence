import os
import re
import json
from typing import Dict, Any, List
import google.generativeai as genai

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
if GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
    except Exception:
        pass

URL_PATTERN = r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?'
EMAIL_PATTERN = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
PHONE_PATTERN = r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
UPI_PATTERN = r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}'

def extract_message_entities(text: str) -> Dict[str, List[str]]:
    urls = re.findall(URL_PATTERN, text)
    emails = re.findall(EMAIL_PATTERN, text)
    phones = re.findall(PHONE_PATTERN, text)
    raw_upis = re.findall(UPI_PATTERN, text)
    
    upis = [u for u in raw_upis if u not in emails and any(handle in u for handle in ['@oksbi', '@okhdfcbank', '@paytm', '@ibl', '@ybl', '@axl', '@upi'])]

    return {
        "extracted_urls": list(set(urls)),
        "extracted_emails": list(set(emails)),
        "extracted_phones": list(set(phones)),
        "extracted_upis": list(set(upis))
    }

def analyze_scam_with_ai(content: str, context: str = "SMS/Email") -> Dict[str, Any]:
    entities = extract_message_entities(content)
    lower_content = content.lower()
    
    urgency_keywords = ["urgent", "immediately", "suspended", "blocked", "kyc", "otp", "deactivated", "lottery", "cashback"]
    is_urgent = any(kw in lower_content for kw in urgency_keywords)
    
    fallback_result = {
        "is_scam": is_urgent or len(entities["extracted_urls"]) > 0 or len(entities["extracted_upis"]) > 0,
        "urgency_level": "High" if sum(1 for kw in urgency_keywords if kw in lower_content) >= 2 else ("Medium" if is_urgent else "Low"),
        "impersonated_brand": "Financial / Institutional Entity" if ("bank" in lower_content or "sbi" in lower_content or "account" in lower_content) else "Unspecified",
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
        response = model.generate_content(prompt)
        raw_text = response.text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        parsed = json.loads(raw_text)
        parsed["extracted_entities"] = entities
        return parsed
    except Exception:
        return fallback_result