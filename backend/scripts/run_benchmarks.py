import requests
import json

BASE_URL = "http://127.0.0.1:8000/api/v1"

BENCHMARK_URLS = [
    "https://github.com",
    "https://adamasuniversity.ac.in",
    "https://www.onlinesbi.sbi",
    "http://sbi-netbanking-verifykyc.top",
    "https://raw.githubusercontent.com/katiesimilar6/test/main/payload.exe"
]

BENCHMARK_MESSAGE = "URGENT: Your SBI YONO account has been suspended due to pending KYC update. Click http://bit.ly/sbi-kyc-reactivate immediately to avoid permanent deactivation. Contact helpdesk at 9876543210."

def run_tests():
    print("=== RUNNING BENCHMARK EVALUATIONS ===")
    
    # 1. Test URLs
    for url in BENCHMARK_URLS:
        print(f"\n[Testing URL]: {url}")
        try:
            res = requests.post(f"{BASE_URL}/analyze/url", json={"url": url}, timeout=15)
            if res.status_code == 200:
                data = res.json()
                print(f" -> Risk Tier : {data['risk_level']}")
                print(f" -> Score     : {data['confidence_score']}")
                print(f" -> SHA-256   : {data['report_sha256'][:16]}...")
            else:
                print(f" -> Failed ({res.status_code}): {res.text}")
        except Exception as e:
            print(f" -> Error: {e}")

    # 2. Test Message
    print(f"\n[Testing Coercive Message]:")
    try:
        res = requests.post(f"{BASE_URL}/analyze/message", json={"content": BENCHMARK_MESSAGE, "context": "SMS"}, timeout=10)
        if res.status_code == 200:
            data = res.json()
            print(f" -> Risk Tier : {data['risk_level']}")
            print(f" -> Score     : {data['confidence_score']}")
            print(f" -> Summary   : {data['summary']}")
            print(f" -> SHA-256   : {data['report_sha256'][:16]}...")
        else:
            print(f" -> Failed ({res.status_code}): {res.text}")
    except Exception as e:
        print(f" -> Error: {e}")

if __name__ == "__main__":
    run_tests()