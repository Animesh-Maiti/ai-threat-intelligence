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

const API_BASE_URL = 
    process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

export async function analyzeUrl(url: string): Promise<ThreatAnalysisResponse> {
  const response = await fetch(`${API_BASE_URL}/analyze/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.detail || `Request failed with status ${response.status}`);
  }

  return response.json();
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