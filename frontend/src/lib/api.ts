export type RiskLevel =
  | "Low Risk"
  | "Suspicious"
  | "High Risk"
  | "Confirmed Malicious"
  | "Inconclusive";

export interface ThreatAnalysisResponse {
  target: string;
  risk_level: RiskLevel;
  confidence_score: number;
  summary: string;
  campaign_correlation?: {
    is_campaign: boolean;
    campaign_id: string | null;
    related_reports_count: number;
    correlated_indicators: string[];
    explanation: string;
  };
  detected_indicators: string[];
  technical_evidence: Record<string, any>;
  recommended_actions: string[];
  report_sha256: string;
  on_chain_tx: string | null;
}

export interface VerificationResponse {
  report_sha256: string;
  is_verified: boolean;
  on_chain_tx: string | null;
  audit_data: Record<string, any> | null;
}

const API_BASE_URL = 
    process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

export async function analyzeUrl(url: string): Promise<ThreatAnalysisResponse> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 25_000);
  try {
    const response = await fetch(`${API_BASE_URL}/analyze/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });

    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new Error(errorBody.detail || `Request failed with status ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new Error("The scan is taking longer than expected. Please try again.");
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

export async function analyzeMessage(
  content: string,
  context: string = "SMS/Email"
): Promise<ThreatAnalysisResponse> {
  const response = await fetch(`${API_BASE_URL}/analyze/message`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content, context }),
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.detail || `Request failed with status ${response.status}`);
  }

  return response.json();
}

export async function verifyHash(hash: string): Promise<VerificationResponse> {
  const response = await fetch(
    `${API_BASE_URL}/verify/hash/${encodeURIComponent(hash)}`
  );

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.detail || `Request failed with status ${response.status}`);
  }

  return response.json();
}