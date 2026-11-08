export interface ThreatAnalysis {
  target: string;
  status: "pending" | "completed" | "failed";
}
