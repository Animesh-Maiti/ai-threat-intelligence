from app.modules.url_analyzer import analyze_url_structure, check_typosquatting, calculate_entropy
from app.modules.header_auditor import audit_security_headers

print("--- 1. Testing Benign Target (GitHub) ---")
gh_url = analyze_url_structure("https://github.com")
gh_headers = audit_security_headers("https://github.com")
print(f"Entropy: {gh_url.get('entropy_score')}")
print(f"HSTS: {gh_headers.get('has_hsts')} | CSP: {gh_headers.get('has_csp')}")

print("\n--- 2. Testing Typosquatting / Homoglyph ---")
typo_res = check_typosquatting("https://paypaI-security.com")
print(f"Typosquatting Flagged: {typo_res.get('is_typosquatting')} | Matched Brand: {typo_res.get('matched_brand')}")

print("\n--- 3. Testing SSRF Rejection via Auditor ---")
ssrf_headers = audit_security_headers("http://127.0.0.1:8000")
print(f"SSRF Auditor Result: {ssrf_headers.get('error')}")