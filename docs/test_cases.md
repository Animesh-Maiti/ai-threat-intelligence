# Benchmark Evaluation & Test Suite

This test suite establishes the ground-truth evaluation benchmark across real-world legitimate platforms and verified malicious/social-engineering attack vectors.

## Summary Matrix

| ID | Target / Input | Category | Expected Risk Tier | Primary Detected Indicators |
| :--- | :--- | :--- | :--- | :--- |
| **TC-01** | `https://github.com` | Enterprise SaaS | `Low Risk` | Valid DigiCert CA, SAN match, no threat listings |
| **TC-02** | `https://adamasuniversity.ac.in` | Academic Institution | `Low Risk` | Valid institutional CA, TLS active, clean reputation |
| **TC-03** | `https://www.onlinesbi.sbi` | High-Security Banking | `Low Risk` | Strict organization TLS, trusted root CA, genuine TLD |
| **TC-04** | `http://sbi-netbanking-verifykyc.top` | Phishing Lookalike | `High Risk` | Typosquatting heuristics, missing TLS, suspicious TLD |
| **TC-05** | Urgent KYC Deactivation SMS | Social Engineering | `High Risk` | Coercive urgency, credential harvesting, unverified link |
| **TC-06** | `https://raw.githubusercontent.com/katiesimilar6/` (or active URLhaus feed) | Active Malware Feed | `Confirmed Malicious` | Direct blacklist hit on URLhaus API, malware payload tag |

---

## Detailed Test Case Profiles

### TC-01: Global Developer Platform (Legitimate Benign)
* **Input Type:** URL
* **Target:** `https://github.com`
* **Evaluation Scenario:** Tests the TLS parser, root CA verification, and threat feed lookups on high-traffic legitimate infrastructure.
* **Expected Output:**
  * **Classification:** `Low Risk`
  * **Confidence Score:** ~0.10
  * **Technical Findings:** Valid DigiCert TLS certificate, active SAN matching, zero URLhaus listing, HTTPS enforced.
* **Recommended Action:** "Safe to browse. Ensure address bar confirms genuine organization domain."

---

### TC-02: Higher Education Institutional Portal (Legitimate Benign)
* **Input Type:** URL
* **Target:** `https://adamasuniversity.ac.in`
* **Evaluation Scenario:** Tests standard public institutional domains without enterprise EV certificates.
* **Expected Output:**
  * **Classification:** `Low Risk`
  * **Confidence Score:** ~0.10
  * **Technical Findings:** Trusted certificate authority, valid handshake, zero blacklist records.
* **Recommended Action:** "Safe to browse."

---

### TC-03: National Financial Institution (High-Trust Legitimate)
* **Input Type:** URL
* **Target:** `https://www.onlinesbi.sbi`
* **Evaluation Scenario:** Verifies that genuine banking infrastructure passes without false positives.
* **Expected Output:**
  * **Classification:** `Low Risk`
  * **Confidence Score:** ~0.10
  * **Technical Findings:** Strict TLS trust chain, verified organization identity, zero feed triggers.
* **Recommended Action:** "Legitimate banking portal verified."

---

### TC-04: Bank Impersonation / Homoglyph Harvester (Lookalike Phishing)
* **Input Type:** URL
* **Target:** `http://sbi-netbanking-verifykyc.top`
* **Evaluation Scenario:** Evaluates detection of domain brand squatting, insecure HTTP protocol, and high-risk TLDs without legitimate trust chains.
* **Expected Output:**
  * **Classification:** `High Risk`
  * **Confidence Score:** ≥ 0.75
  * **Technical Findings:** Insecure plaintext HTTP protocol, invalid/missing TLS, brand name squatted against legitimate banking keywords.
* **Recommended Action:** "Do not enter passwords, PINs, or credentials. High likelihood of credential harvesting."

---

### TC-05: Coercive KYC Deactivation Scam (Social Engineering Message)
* **Input Type:** Unstructured Scam Text
* **Target:** `"URGENT: Your SBI YONO account has been suspended due to pending KYC update. Click http://bit.ly/sbi-kyc-reactivate immediately to avoid permanent deactivation. Contact helpdesk at 9876543210."`
* **Evaluation Scenario:** Evaluates Gemini 1.5 Flash parsing of urgency patterns, extracted URL shortened links, and extraction of unverified contact numbers.
* **Expected Output:**
  * **Classification:** `High Risk`
  * **Confidence Score:** ≥ 0.75
  * **Technical Findings:**
    * Urgency Level: `High`
    * Extracted URL: `http://bit.ly/sbi-kyc-reactivate`
    * Extracted Phone: `9876543210`
    * Red Flags: Coercive urgency, account suspension threat, external link redirect.
* **Recommended Action:** "Do not click unverified links or share OTPs. Verify directly with your bank branch."

---

### TC-06: Active Blacklisted Malware Feed Entry (Threat Intelligence Match)
* **Input Type:** URL
* **Target:** Active entry from abuse.ch URLhaus (e.g., active SmartLoader/Mozi distribution URL)
* **Evaluation Scenario:** Tests passive external threat intelligence integration by confirming immediate categorization upon positive threat feed lookup.
* **Expected Output:**
  * **Classification:** `Confirmed Malicious`
  * **Confidence Score:** ≥ 0.95
  * **Technical Findings:** Direct URLhaus match (`is_listed: true`), tagged threat payload details.
* **Recommended Action:** "Access blocked immediately. Host is known to distribute malicious payloads."