"use client";

import React, { useState } from "react";

interface ThreatResponse {
  target: string;
  risk_level: string;
  confidence_score: number;
  summary: string;
  detected_indicators: string[];
  technical_evidence: Record<string, any>;
  recommended_actions: string[];
  report_sha256: string;
  on_chain_tx: string | null;
}

interface VerificationResponse {
  report_sha256: string;
  is_verified: boolean;
  on_chain_tx: string | null;
  audit_data: Record<string, any> | null;
}

export default function ThreatDashboard() {
  const [activeTab, setActiveTab] = useState<"url" | "message" | "ledger">("url");
  const [urlInput, setUrlInput] = useState("");
  const [messageInput, setMessageInput] = useState("");
  const [hashInput, setHashInput] = useState("");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [analysisResult, setAnalysisResult] = useState<ThreatResponse | null>(null);
  const [verifyResult, setVerifyResult] = useState<VerificationResponse | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const API_BASE = "http://127.0.0.1:8000/api/v1";

  const handleCopy = async (text: string, label: string) => {
    try {
      if (navigator?.clipboard) {
        await navigator.clipboard.writeText(text);
      }
      setCopiedField(label);
      window.setTimeout(() => setCopiedField(null), 2000);
    } catch {
      setCopiedField(null);
    }
  };

  const analyzeUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput.trim()) return;
    setLoading(true);
    setError(null);
    setAnalysisResult(null);

    try {
      const res = await fetch(`${API_BASE}/analyze/url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: urlInput.trim() }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Server responded with ${res.status}`);
      }

      const data: ThreatResponse = await res.json();
      setAnalysisResult(data);
    } catch (err: any) {
      setError(err.message || "Failed to analyze target URL");
    } finally {
      setLoading(false);
    }
  };

  const analyzeMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!messageInput.trim()) return;
    setLoading(true);
    setError(null);
    setAnalysisResult(null);

    try {
      const res = await fetch(`${API_BASE}/analyze/message`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content: messageInput.trim(), context: "SMS/Email Scam" }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Server responded with ${res.status}`);
      }

      const data: ThreatResponse = await res.json();
      setAnalysisResult(data);
    } catch (err: any) {
      setError(err.message || "Failed to triage suspicious message");
    } finally {
      setLoading(false);
    }
  };

  const verifyHash = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!hashInput.trim()) return;
    setLoading(true);
    setError(null);
    setVerifyResult(null);

    try {
      const res = await fetch(`${API_BASE}/verify/hash/${encodeURIComponent(hashInput.trim())}`);
      if (!res.ok) {
        throw new Error(`Verification lookup returned status ${res.status}`);
      }

      const data: VerificationResponse = await res.json();
      setVerifyResult(data);
    } catch (err: any) {
      setError(err.message || "Ledger verification lookup failed");
    } finally {
      setLoading(false);
    }
  };

  const getRiskBadgeColor = (risk: string) => {
    switch (risk?.toLowerCase()) {
      case "low risk":
        return "bg-emerald-950/70 border-emerald-500/40 text-emerald-400";
      case "suspicious":
        return "bg-amber-950/70 border-amber-500/40 text-amber-400";
      case "high risk":
        return "bg-rose-950/70 border-rose-500/40 text-rose-400";
      case "confirmed malicious":
        return "bg-red-950/90 border-red-500 text-red-300 font-bold animate-pulse";
      default:
        return "bg-zinc-900 border-zinc-700 text-zinc-300";
    }
  };

  const renderThreatResult = (result: ThreatResponse | null) => {
    if (!result) {
      return null;
    }

    return (
      <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-5 shadow-2xl">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-4 border-b border-zinc-800">
          <div>
            <p className="text-[10px] uppercase tracking-[0.2em] text-cyan-400">Threat Assessment</p>
            <h3 className="mt-1 text-xl font-semibold text-white">{result.target}</h3>
          </div>
          <span className={`inline-flex items-center border rounded-full px-3 py-1 text-xs font-semibold ${getRiskBadgeColor(result.risk_level)}`}>
            {result.risk_level}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-5">
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
            <p className="text-zinc-400 text-xs uppercase tracking-[0.2em]">Confidence</p>
            <p className="mt-2 text-2xl font-bold text-cyan-400">
              {Math.round(result.confidence_score <= 1 ? result.confidence_score * 100 : result.confidence_score)}%
            </p>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
            <p className="text-zinc-400 text-xs uppercase tracking-[0.2em]">Report Hash</p>
            <div className="mt-2 flex flex-col items-start gap-2">
              <p className="text-xs font-mono text-zinc-200 break-all">{result.report_sha256}</p>
              <button
                type="button"
                onClick={() => {
                  setHashInput(result.report_sha256);
                  setVerifyResult(null);
                  setError(null);
                  setActiveTab("ledger");
                }}
                className="text-xs text-cyan-400 hover:text-cyan-300"
              >
                Verify in Ledger
              </button>
            </div>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
            <p className="text-zinc-400 text-xs uppercase tracking-[0.2em]">On-chain</p>
            <p className="mt-2 text-sm font-mono text-zinc-200 break-all">{result.on_chain_tx || "Not published"}</p>
          </div>
        </div>

        <div className="mt-6">
          <p className="text-zinc-400 text-xs uppercase tracking-[0.2em] mb-2">Summary</p>
          <p className="text-zinc-200 leading-relaxed">{result.summary}</p>
        </div>

        <div className="mt-6 grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
            <p className="text-zinc-400 text-xs uppercase tracking-[0.2em] mb-3">Detected Indicators</p>
            <ul className="space-y-2 text-sm text-zinc-200">
              {result.detected_indicators.length > 0 ? (
                result.detected_indicators.map((indicator, index) => (
                  <li key={`${indicator}-${index}`} className="flex items-start gap-2">
                    <span className="mt-1 h-1.5 w-1.5 rounded-full bg-cyan-400"></span>
                    <span>{indicator}</span>
                  </li>
                ))
              ) : (
                <li className="text-zinc-500">No indicators detected.</li>
              )}
            </ul>
          </div>

          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
            <p className="text-zinc-400 text-xs uppercase tracking-[0.2em] mb-3">Recommended Actions</p>
            <ul className="space-y-2 text-sm text-zinc-200">
              {result.recommended_actions.length > 0 ? (
                result.recommended_actions.map((action, index) => (
                  <li key={`${action}-${index}`} className="flex items-start gap-2">
                    <span className="mt-1 h-1.5 w-1.5 rounded-full bg-rose-400"></span>
                    <span>{action}</span>
                  </li>
                ))
              ) : (
                <li className="text-zinc-500">No actions recommended.</li>
              )}
            </ul>
          </div>
        </div>

        <div className="mt-6 bg-zinc-900 border border-zinc-800 rounded-lg p-4">
          <div className="flex items-center justify-between gap-3 mb-3">
            <p className="text-zinc-400 text-xs uppercase tracking-[0.2em]">Technical Evidence</p>
            <button
              type="button"
              onClick={() => handleCopy(JSON.stringify(result.technical_evidence, null, 2), "technical-evidence")}
              className="text-xs text-cyan-400 hover:text-cyan-300"
            >
              {copiedField === "technical-evidence" ? "Copied" : "Copy JSON"}
            </button>
          </div>
          <pre className="overflow-auto text-xs text-zinc-300 bg-black/40 rounded-md p-3">
            {JSON.stringify(result.technical_evidence ?? {}, null, 2)}
          </pre>
        </div>
      </div>
    );
  };

  const renderVerificationResult = (result: VerificationResponse | null) => {
    if (!result) {
      return null;
    }

    return (
      <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-5 shadow-2xl">
        <div className="flex items-center justify-between gap-3 pb-4 border-b border-zinc-800">
          <div>
            <p className="text-[10px] uppercase tracking-[0.2em] text-cyan-400">Ledger Verification</p>
            <h3 className="mt-1 text-xl font-semibold text-white">{result.report_sha256}</h3>
          </div>
          <span
            className={`inline-flex items-center border rounded-full px-3 py-1 text-xs font-semibold ${
              result.is_verified
                ? "bg-emerald-950/70 border-emerald-500/40 text-emerald-400"
                : "bg-rose-950/70 border-rose-500/40 text-rose-400"
            }`}
          >
            {result.is_verified ? "TAMPER-EVIDENT RECORD CONFIRMED" : "RECORD NOT FOUND"}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-5">
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
            <p className="text-zinc-400 text-xs uppercase tracking-[0.2em]">Verification Status</p>
            <p className="mt-2 text-lg font-semibold text-zinc-200">
              {result.is_verified ? "Threat report has been recorded on-chain" : "No corresponding on-chain artifact found"}
            </p>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
            <p className="text-zinc-400 text-xs uppercase tracking-[0.2em]">On-chain Transaction</p>
            <p className="mt-2 text-sm font-mono text-zinc-200 break-all">{result.on_chain_tx || "No transaction available"}</p>
          </div>
        </div>

        <div className="mt-6 bg-zinc-900 border border-zinc-800 rounded-lg p-4">
          <div className="flex items-center justify-between gap-3 mb-3">
            <p className="text-zinc-400 text-xs uppercase tracking-[0.2em]">Audit Data</p>
            <button
              type="button"
              onClick={() => handleCopy(JSON.stringify(result.audit_data ?? {}, null, 2), "audit-data")}
              className="text-xs text-cyan-400 hover:text-cyan-300"
            >
              {copiedField === "audit-data" ? "Copied" : "Copy JSON"}
            </button>
          </div>
          <pre className="overflow-auto text-xs text-zinc-300 bg-black/40 rounded-md p-3">
            {JSON.stringify(result.audit_data ?? {}, null, 2)}
          </pre>
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-black text-zinc-100 font-sans selection:bg-cyan-500 selection:text-black">
      <header className="border-b border-zinc-800 bg-zinc-950/80 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded-lg bg-cyan-500 flex items-center justify-center font-black text-black text-sm">
              AI
            </div>
            <div>
              <h1 className="text-base font-bold tracking-tight text-white flex items-center gap-2">
                HackMatrix26 <span className="text-zinc-500 text-xs font-normal">| AI Threat Intelligence & On-Chain Audit</span>
              </h1>
            </div>
          </div>
          <div className="flex items-center space-x-2 text-xs">
            <span className="flex h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span className="text-zinc-400 font-mono">CORE_ENGINE_ACTIVE</span>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-8">
        <div className="flex border-b border-zinc-800 space-x-2 mb-8">
          <button
            onClick={() => {
              setActiveTab("url");
              setError(null);
            }}
            className={`pb-3 px-4 text-sm font-semibold transition border-b-2 ${
              activeTab === "url"
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-zinc-400 hover:text-zinc-200"
            }`}
          >
            URL Threat Analyzer
          </button>
          <button
            onClick={() => {
              setActiveTab("message");
              setError(null);
            }}
            className={`pb-3 px-4 text-sm font-semibold transition border-b-2 ${
              activeTab === "message"
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-zinc-400 hover:text-zinc-200"
            }`}
          >
            Scam & Coercion Detector
          </button>
          <button
            onClick={() => {
              setActiveTab("ledger");
              setError(null);
            }}
            className={`pb-3 px-4 text-sm font-semibold transition border-b-2 ${
              activeTab === "ledger"
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-zinc-400 hover:text-zinc-200"
            }`}
          >
            Web3 Ledger Verification
          </button>
        </div>

        {activeTab === "url" && (
          <div className="space-y-6">
            <form onSubmit={analyzeUrl} className="bg-zinc-950 border border-zinc-800 rounded-xl p-5 shadow-2xl">
              <label className="block text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-2">
                Target URL or Domain Name
              </label>
              <div className="flex flex-col sm:flex-row gap-3">
                <input
                  type="text"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder="e.g. http://sbi-netbanking-verifykyc.top or https://github.com"
                  className="flex-1 bg-zinc-900 border border-zinc-700 rounded-lg px-4 py-2.5 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-cyan-500 font-mono"
                  required
                />
                <button
                  type="submit"
                  disabled={loading}
                  className="bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-black font-semibold text-sm px-6 py-2.5 rounded-lg transition"
                >
                  {loading ? "Inspecting Pipeline..." : "Analyze Threat"}
                </button>
              </div>
            </form>

            {error && (
              <div className="rounded-lg border border-rose-500/40 bg-rose-950/30 px-4 py-3 text-sm text-rose-200">
                {error}
              </div>
            )}

            {renderThreatResult(analysisResult)}
          </div>
        )}

        {activeTab === "message" && (
          <div className="space-y-6">
            <form onSubmit={analyzeMessage} className="bg-zinc-950 border border-zinc-800 rounded-xl p-5 shadow-2xl">
              <label className="block text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-2">
                Suspicious Message or Conversation
              </label>
              <textarea
                value={messageInput}
                onChange={(e) => setMessageInput(e.target.value)}
                placeholder="Paste the suspected SMS, email, chat message, or conversation excerpt here..."
                rows={6}
                className="w-full bg-zinc-900 border border-zinc-700 rounded-lg px-4 py-3 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-cyan-500 resize-none"
                required
              />
              <div className="mt-4 flex justify-end">
                <button
                  type="submit"
                  disabled={loading}
                  className="bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-black font-semibold text-sm px-6 py-2.5 rounded-lg transition"
                >
                  {loading ? "Triage in Progress..." : "Analyze Message"}
                </button>
              </div>
            </form>

            {error && (
              <div className="rounded-lg border border-rose-500/40 bg-rose-950/30 px-4 py-3 text-sm text-rose-200">
                {error}
              </div>
            )}

            {renderThreatResult(analysisResult)}
          </div>
        )}

        {activeTab === "ledger" && (
          <div className="space-y-6">
            <form onSubmit={verifyHash} className="bg-zinc-950 border border-zinc-800 rounded-xl p-5 shadow-2xl">
              <label className="block text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-2">
                Threat Report SHA-256 Hash
              </label>
              <div className="flex flex-col sm:flex-row gap-3">
                <input
                  type="text"
                  value={hashInput}
                  onChange={(e) => setHashInput(e.target.value)}
                  placeholder="Paste the report hash to verify its on-chain evidence"
                  className="flex-1 bg-zinc-900 border border-zinc-700 rounded-lg px-4 py-2.5 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-cyan-500 font-mono"
                  required
                />
                <button
                  type="submit"
                  disabled={loading}
                  className="bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-black font-semibold text-sm px-6 py-2.5 rounded-lg transition"
                >
                  {loading ? "Checking Ledger..." : "Verify Hash"}
                </button>
              </div>
            </form>

            {error && (
              <div className="rounded-lg border border-rose-500/40 bg-rose-950/30 px-4 py-3 text-sm text-rose-200">
                {error}
              </div>
            )}

            {renderVerificationResult(verifyResult)}
          </div>
        )}
      </main>
    </div>
  );
}
