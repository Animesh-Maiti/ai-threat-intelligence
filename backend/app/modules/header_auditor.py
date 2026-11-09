"""HTTP security header auditing."""

from __future__ import annotations

import contextlib
from typing import Any, Dict
from urllib import error as urllib_error
from urllib import request as urllib_request

from app.modules.url_analyzer import _open_validated_request, _validate_destination_url


def audit_security_headers(url: str, timeout: float = 3.5) -> Dict[str, Any]:
    """Perform a passive security-header audit without following redirects.

    HEAD is attempted first, and GET is only used when HEAD is explicitly unsupported.
    """
    result: Dict[str, Any] = {
        "has_hsts": False,
        "has_csp": False,
        "has_xframe": False,
        "missing_headers": [],
        "exposed_server": None,
        "notes": [],
        "has_x_content_type_options": False,
        "exposed_powered_by": None,
        "error": None,
    }

    if not isinstance(url, str) or not url.strip():
        result["error"] = "Malformed URL"
        result["missing_headers"] = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
        ]
        result["notes"] = ["No request was sent because the URL was empty or invalid."]
        return result

    valid, error = _validate_destination_url(url)
    if not valid:
        result["error"] = error or "URL failed SSRF validation"
        result["missing_headers"] = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
        ]
        result["notes"] = ["The destination was rejected by SSRF validation before any request was made."]
        return result

    request_timeout = min(2.5, float(timeout or 2.5))
    if request_timeout <= 0:
        request_timeout = 3.5

    request_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
        "Connection": "close",
    }

    try:
        response, conn = _open_validated_request(url, method="HEAD", timeout=request_timeout, headers=request_headers)
        try:
            status_code = getattr(response, "status", None) or response.status
            result["notes"].append(f"HEAD request completed with HTTP {status_code}.")
            response_headers = {key.lower(): value for key, value in response.headers.items()}
            result["has_hsts"] = bool(response_headers.get("strict-transport-security"))
            result["has_csp"] = bool(response_headers.get("content-security-policy"))
            result["has_xframe"] = bool(response_headers.get("x-frame-options"))
            result["has_x_content_type_options"] = bool(response_headers.get("x-content-type-options"))
            result["exposed_server"] = response_headers.get("server")
            result["exposed_powered_by"] = response_headers.get("x-powered-by")
        finally:
            response.close()
            conn.close()
    except urllib_error.HTTPError as exc:
        if exc.code not in {405, 501}:
            result["error"] = f"HTTP error {exc.code}"
            result["notes"].append("HEAD request failed with a non-retriable HTTP error.")
            return result
        fallback_headers = dict(request_headers)
        fallback_headers["Range"] = "bytes=0-0"
        try:
            response, conn = _open_validated_request(url, method="GET", timeout=request_timeout, headers=fallback_headers)
            try:
                status_code = getattr(response, "status", None) or response.status
                result["notes"].append(f"GET fallback completed with HTTP {status_code}.")
                response_headers = {key.lower(): value for key, value in response.headers.items()}
                result["has_hsts"] = bool(response_headers.get("strict-transport-security"))
                result["has_csp"] = bool(response_headers.get("content-security-policy"))
                result["has_xframe"] = bool(response_headers.get("x-frame-options"))
                result["has_x_content_type_options"] = bool(response_headers.get("x-content-type-options"))
                result["exposed_server"] = response_headers.get("server") or result["exposed_server"]
                result["exposed_powered_by"] = response_headers.get("x-powered-by") or result["exposed_powered_by"]
            finally:
                response.close()
                conn.close()
        except (urllib_error.HTTPError, urllib_error.URLError, OSError, ValueError, TimeoutError):
            result["error"] = f"HEAD unsupported and GET fallback failed with status {getattr(exc, 'code', 'unknown')}"
            result["notes"].append("HEAD was unsupported and the lightweight GET fallback was not available or failed.")
            return result
    except (urllib_error.URLError, OSError, ValueError, TimeoutError):
        result["error"] = "Request failed"
        result["notes"].append("The connection to the target could not be established.")
        return result

    required_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
    ]
    result["missing_headers"] = [
        name for name in required_headers if not (
            (name == "Strict-Transport-Security" and result["has_hsts"]) or
            (name == "Content-Security-Policy" and result["has_csp"]) or
            (name == "X-Frame-Options" and result["has_xframe"]) or
            (name == "X-Content-Type-Options" and result["has_x_content_type_options"])
        )
    ]

    if not result["notes"]:
        result["notes"] = ["Passive HTTP header audit completed without incident."]
    if result["exposed_server"] or result["exposed_powered_by"]:
        result["notes"].append("Technology disclosure is visible in response headers; the presence alone is not a vulnerability.")

    return result


__all__ = ["audit_security_headers"]
