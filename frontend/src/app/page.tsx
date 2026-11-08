"use client";

import { useState } from "react";
import { analyzeUrl, analyzeMessage, ThreatAnalysisResponse } from "@/lib/api";

export default function Home() {
  const [tab, setTab] = useState<"url" | "message">("url");
  const [targetUrl, setTargetUrl] = useState("https://github.com");
  const [messageText, setMessageText] = useState(
    "URGENT: Your SBI account has been suspended due to pending KYC update. Click http://bit.ly/sbi-kyc-reactivate immediately to reactivate."
  );
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ThreatAnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      if (tab === "url") {
        const res = await analyzeUrl(targetUrl);
        setResult(res);
      } else {
        const res = await analyzeMessage(messageText, "SMS");
        setResult(res);
      }
    } catch (err: any) {
      setError(err.message || "An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  };

  const getBadgeColor = (risk?: string) => {
    switch (risk) {
      case "Low Risk":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      case "Suspicious":
        return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      case "High Risk":
        return "bg-orange-500/10 text-orange-400 border-orange-500/30";
      case "Confirmed Malicious":
        return "bg-rose-500/10 text-rose-400 border-rose-500/30";
      default:
        return "bg-zinc-800 text-zinc-300 border-zinc-700";
    }
  };

  return (
    <main className="min-h-screen bg-zinc-950 text-zinc-100 p-6 md:p-12 font-sans">
      <div className="max-w-4xl mx-auto space-y-8">
        <header className="border-b border-zinc-800 pb-6">
          <div className="flex items-center gap-3">
            <span className="w-3 h-3 rounded-full bg-indigo-500 animate-pulse" />
            <h1 className="text-2xl font-bold tracking-tight text-white">
              AI-Powered Web Threat & Digital Trust Intelligence
            </h1>
          </div>
          <p className="text-zinc-400 text-sm mt-1">
            Deterministic SSRF defense, TLS trust analysis, and LLM scam triage.
          </p>
        </header>

        <div className="flex border-b border-zinc-800">
          <button
            type="button"
            onClick={() => { setTab("url"); setResult(null); setError(null); }}
            className={`pb-3 px-4 text-sm font-medium transition-colors cursor-pointer ${
              tab === "url"
                ? "border-b-2 border-indigo-500 text-indigo-400"
                : "text-zinc-400 hover:text-zinc-200"
            }`}
          >
            URL & Domain Inspection
          </button>
          <button
            type="button"
            onClick={() => { setTab("message"); setResult(null); setError(null); }}
            className={`pb-3 px-4 text-sm font-medium transition-colors cursor-pointer ${
              tab === "message"
                ? "border-b-2 border-indigo-500 text-indigo-400"
                : "text-zinc-400 hover:text-zinc-200"
            }`}
          >
            Social Engineering / Scam Message
          </button>
        </div>

        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6 space-y-4">
          {tab === "url" ? (
            <div>
              <label className="block text-xs uppercase tracking-wider text-zinc-400 font-semibold mb-2">
                Target URL
              </label>
              <input
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://example.com"
                className="w-full bg-zinc-950 border border-zinc-700 rounded-lg px-4 py-2.5 text-zinc-200 focus:outline-none focus:border-indigo-500 text-sm font-mono"
              />
            </div>
          ) : (
            <div>
              <label className="block text-xs uppercase tracking-wider text-zinc-400 font-semibold mb-2">
                Suspicious Communication Payload
              </label>
              <textarea
                rows={4}
                value={messageText}
                onChange={(e) => setMessageText(e.target.value)}
                placeholder="Paste suspicious SMS, email, or phishing alert text..."
                className="w-full bg-zinc-950 border border-zinc-700 rounded-lg p-3 text-zinc-200 focus:outline-none focus:border-indigo-500 text-sm"
              />
            </div>
          )}

          <button
            type="button"
            onClick={handleAnalyze}
            disabled={loading}
            className="w-full bg-indigo-600 hover:bg-indigo-500 disabled:bg-zinc-800 disabled:text-zinc-500 text-white font-medium py-2.5 rounded-lg transition-all text-sm shadow-md cursor-pointer"
          >
            {loading ? "Analyzing Target Payload..." : "Execute Security Inspection"}
          </button>
        </div>

        {error && (
          <div className="p-4 bg-rose-500/10 border border-rose-500/30 text-rose-400 rounded-lg text-sm">
            <strong>Error:</strong> {error}
          </div>
        )}

        {result && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-zinc-800 pb-4">
              <div>
                <span className="text-xs uppercase tracking-wider text-zinc-500 block">Assessed Target</span>
                <span className="font-mono text-zinc-200 text-sm break-all">{result.target}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className={`px-3 py-1 rounded-md text-xs font-semibold uppercase tracking-wider border ${getBadgeColor(result.risk_level)}`}>
                  {result.risk_level}
                </span>
                <span className="text-zinc-400 text-sm font-mono">
                  {(result.confidence_score * 100).toFixed(0)}% Score
                </span>
              </div>
            </div>

            <div>
              <h3 className="text-xs uppercase tracking-wider text-zinc-400 font-semibold mb-1">
                Executive Assessment
              </h3>
              <p className="text-zinc-300 text-sm leading-relaxed">{result.summary}</p>
            </div>

            {result.detected_indicators.length > 0 && (
              <div>
                <h3 className="text-xs uppercase tracking-wider text-zinc-400 font-semibold mb-2">
                  Detected Threat Indicators ({result.detected_indicators.length})
                </h3>
                <ul className="space-y-1.5">
                  {result.detected_indicators.map((ind, i) => (
                    <li key={i} className="text-xs font-mono text-amber-300/90 flex items-start gap-2">
                      <span className="text-amber-500">•</span>
                      <span>{ind}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div className="p-3 bg-zinc-950 rounded-lg border border-zinc-800">
              <span className="text-[10px] uppercase tracking-wider text-zinc-500 block mb-1">
                Cryptographic Integrity Hash (SHA-256)
              </span>
              <p className="font-mono text-xs text-indigo-400 break-all">{result.report_sha256}</p>
            </div>
          </div>
        )}
      </div>
    </main>
  );
}