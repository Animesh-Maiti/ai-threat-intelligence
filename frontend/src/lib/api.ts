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

const configuredApiOrigin = (
  process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000"
).replace(/\/+$/, "");
const API_BASE_URL = /\/api\/v1$/i.test(configuredApiOrigin)
  ? configuredApiOrigin
  : `${configuredApiOrigin}/api/v1`;

async function fetchWithTimeout(
  input: RequestInfo | URL,
  init: RequestInit = {}
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 25_000);
  try {
    return await fetch(input, {
      ...init,
      signal: controller.signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new Error("The request is taking longer than expected. Please try again.");
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function parseResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.detail || `Request failed with status ${response.status}`);
  }
  return response.json();
}

export async function analyzeUrl(url: string): Promise<ThreatAnalysisResponse> {
  const response = await fetchWithTimeout(`${API_BASE_URL}/analyze/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  return parseResponse<ThreatAnalysisResponse>(response);
}

export async function analyzeMessage(
  content: string,
  context: string = "SMS/Email"
): Promise<ThreatAnalysisResponse> {
  const response = await fetchWithTimeout(`${API_BASE_URL}/analyze/message`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content, context }),
  });
  return parseResponse<ThreatAnalysisResponse>(response);
}

export async function verifyHash(hash: string): Promise<VerificationResponse> {
  const response = await fetchWithTimeout(
    `${API_BASE_URL}/verify/hash/${encodeURIComponent(hash)}`
  );
  return parseResponse<VerificationResponse>(response);
}