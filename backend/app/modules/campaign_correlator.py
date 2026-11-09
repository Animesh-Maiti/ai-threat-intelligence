"""Persist and correlate related threat-analysis incidents."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

HISTORY_FILE = Path(__file__).resolve().parents[1] / "data" / "campaign_history.json"
_HISTORY_LOCK = threading.RLock()
_HISTORY_CACHE: Optional[List[Dict[str, Any]]] = None


def ensure_history_directory() -> None:
    os.makedirs(HISTORY_FILE.parent, exist_ok=True)


_KNOWN_BRANDS = (
    "sbi",
    "hdfc",
    "icici",
    "axis",
    "pnb",
    "paytm",
    "google",
    "microsoft",
    "apple",
    "amazon",
    "netflix",
)

_MULTI_LABEL_SUFFIXES = {
    "ac.in",
    "co.in",
    "co.jp",
    "co.nz",
    "co.uk",
    "com.au",
    "com.br",
    "com.cn",
    "com.mx",
    "com.sg",
    "com.tr",
    "co.za",
    "edu.au",
    "gov.uk",
    "net.au",
    "org.uk",
}
_NON_SPECIFIC_BRANDS = {
    "",
    "none",
    "unknown",
    "unspecified",
    "financial / institutional entity",
    "financial institution",
}
_SAFE_RISK_LEVELS = {"low risk", "safe"}
_SUSPICIOUS_INDICATOR_TERMS = (
    "suspicious",
    "malicious",
    "phish",
    "scam",
    "fraud",
    "typosquat",
    "impersonat",
    "social engineering",
    "coercive",
    "high urgency",
    "high-risk top-level domain",
)


def _normalize_domain(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value.strip():
        return None

    raw_domain = value.strip()
    parsed = urlsplit(raw_domain if "://" in raw_domain else f"//{raw_domain}")
    hostname = (parsed.hostname or raw_domain).rstrip(".").lower()
    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return hostname


def _apex_domain(domain: Optional[str]) -> Optional[str]:
    if not domain:
        return None
    try:
        return str(ipaddress.ip_address(domain))
    except ValueError:
        pass

    labels = domain.split(".")
    if len(labels) < 2:
        return None

    suffix = ".".join(labels[-2:])
    label_count = 3 if suffix in _MULTI_LABEL_SUFFIXES and len(labels) >= 3 else 2
    return ".".join(labels[-label_count:])


def _normalize_brand(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    brand = value.strip()
    if brand.casefold() in _NON_SPECIFIC_BRANDS:
        return None
    return brand.casefold()


def _has_suspicious_indicators(indicators: Any) -> bool:
    if not isinstance(indicators, list):
        return False
    return any(
        isinstance(indicator, str)
        and any(term in indicator.casefold() for term in _SUSPICIOUS_INDICATOR_TERMS)
        for indicator in indicators
    )


def _is_safe_unflagged(risk_level: Any, indicators: Any) -> bool:
    return (
        isinstance(risk_level, str)
        and risk_level.strip().casefold() in _SAFE_RISK_LEVELS
        and not _has_suspicious_indicators(indicators)
    )


def _extract_brand(target: str, domain: str, existing_brand: Optional[str]) -> Optional[str]:
    if isinstance(existing_brand, str):
        brand = existing_brand.strip()
        if brand.casefold() not in _NON_SPECIFIC_BRANDS:
            return brand.upper()

    searchable_text = f"{target or ''} {domain or ''}".casefold()
    for known_brand in _KNOWN_BRANDS:
        if known_brand in searchable_text:
            return known_brand.upper()
    return None


def _campaign_id(
    brand: Optional[str],
    apex_domain: Optional[str],
    resolved_ip: Optional[str],
) -> str:
    identity = brand or apex_domain or resolved_ip or "unknown"
    slug = re.sub(r"[^A-Z0-9]+", "-", identity.upper()).strip("-") or "UNKNOWN"
    suffix = "PHISH"
    if not brand:
        digest = hashlib.sha1(identity.encode("utf-8")).hexdigest()[:4].upper()
        suffix = digest
    return f"CAMP-{slug[:24]}-{suffix}-01"


def _load_history() -> List[Dict[str, Any]]:
    global _HISTORY_CACHE
    if _HISTORY_CACHE is None:
        if HISTORY_FILE.exists():
            with HISTORY_FILE.open("r", encoding="utf-8") as history_file:
                records = json.load(history_file)
            if not isinstance(records, list) or not all(isinstance(item, dict) for item in records):
                raise ValueError(f"Campaign history must contain a JSON list of records: {HISTORY_FILE}")
            _HISTORY_CACHE = records
        else:
            _HISTORY_CACHE = []
    return _HISTORY_CACHE


def _save_history(records: List[Dict[str, Any]]) -> None:
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary_file = HISTORY_FILE.with_suffix(f"{HISTORY_FILE.suffix}.tmp")
    try:
        with temporary_file.open("w", encoding="utf-8") as history_file:
            json.dump(records, history_file, ensure_ascii=False, indent=2)
            history_file.write("\n")
        os.replace(temporary_file, HISTORY_FILE)
    finally:
        if temporary_file.exists():
            temporary_file.unlink()


def _matches(
    record: Dict[str, Any],
    brand: Optional[str],
    apex_domain: Optional[str],
    resolved_ip: Optional[str],
) -> bool:
    if _is_safe_unflagged(record.get("risk_level"), record.get("indicators")):
        return False
    record_domain_value = _normalize_domain(record.get("target_domain"))
    record_brand = _normalize_brand(
        _extract_brand(
            record.get("target", ""),
            record_domain_value or "",
            record.get("brand_targeted"),
        )
    )
    record_domain = _apex_domain(record_domain_value)
    record_ip = record.get("resolved_ip")
    return bool(
        (brand and record_brand == brand)
        or (apex_domain and record_domain == apex_domain)
        or (resolved_ip and record_ip == resolved_ip)
    )


def correlate_incident(incident_data: dict) -> dict:
    """Record an incident and return its correlation with prior reports."""
    global _HISTORY_CACHE

    target_domain = _normalize_domain(incident_data.get("target_domain"))
    resolved_brand = _extract_brand(
        incident_data.get("target", ""),
        target_domain or "",
        incident_data.get("brand_targeted"),
    )
    brand = _normalize_brand(resolved_brand)
    resolved_ip = incident_data.get("resolved_ip")
    if not isinstance(resolved_ip, str) or not resolved_ip.strip():
        resolved_ip = None
    else:
        resolved_ip = resolved_ip.strip()

    apex_domain = _apex_domain(target_domain)
    indicators = incident_data.get("indicators", [])
    if not isinstance(indicators, list):
        indicators = []
    risk_level = incident_data.get("risk_level")
    if _is_safe_unflagged(risk_level, indicators):
        return {
            "is_campaign": False,
            "campaign_id": None,
            "related_reports_count": 0,
            "correlated_indicators": [],
            "explanation": "",
        }

    with _HISTORY_LOCK:
        history = _load_history()
        matches = [
            record
            for record in history
            if _matches(record, brand, apex_domain, resolved_ip)
        ]
        related_count = len(matches)
        is_campaign = related_count >= 2

        campaign_id = None
        correlated_indicators: List[str] = []
        explanation = "No prior reports share this incident's brand, apex domain, or resolved IP."
        if is_campaign:
            campaign_id = next(
                (record["campaign_id"] for record in matches if record.get("campaign_id")),
                _campaign_id(brand, apex_domain, resolved_ip),
            )
            group_label = resolved_brand or apex_domain or "this infrastructure"
            distinct_domains = {
                domain
                for domain in (
                    _apex_domain(_normalize_domain(record.get("target_domain")))
                    for record in matches
                )
                if domain
            }
            if len(distinct_domains) > 1:
                indicator = (
                    f"{related_count} related reports target {group_label} across "
                    f"{len(distinct_domains)} distinct domains"
                )
            else:
                indicator = (
                    f"{related_count} related reports share the {group_label} "
                    "brand, domain, or infrastructure"
                )
            correlated_indicators.append(indicator)
            explanation = (
                f"This incident matches {related_count} previous reports. "
                "The shared brand, domain, or infrastructure indicates coordinated activity."
            )

        record = {
            "target": incident_data.get("target"),
            "target_domain": target_domain,
            "brand_targeted": resolved_brand,
            "resolved_ip": resolved_ip,
            "indicators": indicators,
            "risk_level": risk_level,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if campaign_id:
            record["campaign_id"] = campaign_id
        updated_history = history + [record]
        _save_history(updated_history)
        _HISTORY_CACHE = updated_history

    return {
        "is_campaign": is_campaign,
        "campaign_id": campaign_id,
        "related_reports_count": related_count,
        "correlated_indicators": correlated_indicators,
        "explanation": explanation,
    }
