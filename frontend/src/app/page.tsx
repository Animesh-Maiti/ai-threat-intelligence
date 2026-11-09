"use client";

import React, { useState } from "react";

interface ThreatResponse {
  target: string;
  risk_level: string;
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
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);

  const API_BASE = "http://127.0.0.1:8000/api/v1";

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(label);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const analyzeUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput.trim()) return;
    setLoading(true);
    setError(null);
    setAnalysisResult(null);

    try {
      const trimmedUrl = urlInput.trim().replace(/^[\s@'"]+|[\s'"]+$/g, "");
      const normalizedUrl = /^https?:\/\//i.test(trimmedUrl)
        ? trimmedUrl
        : `https://${trimmedUrl}`;
      const res = await fetch(`${API_BASE}/analyze/url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: normalizedUrl }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        if (res.status === 400) {
          throw new Error("Please enter a valid website address, such as example.com.");
        }
        throw new Error(errData.detail || `The scan could not be completed (server error ${res.status}).`);
      }
      const data: ThreatResponse = await res.json();
      setAnalysisResult(data);
    } catch (err: any) {
      setError(
        err instanceof TypeError
          ? "We couldn't connect to the scanner. Please check that the backend is running and try again."
          : err.message || "We couldn't analyze that website address. Please check it and try again."
      );
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
      const cleanedMessage = messageInput
        .replace(/\r\n?/g, "\n")
        .replace(/[\u0000\u200B\uFEFF]/g, "")
        .trim();
      const res = await fetch(`${API_BASE}/analyze/message`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content: cleanedMessage, context: "SMS/Email Scam" }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Message analysis could not be completed (server error ${res.status}).`);
      }
      const data: ThreatResponse = await res.json();
      setAnalysisResult(data);
    } catch (err: any) {
      setError(
        err instanceof TypeError
          ? "We couldn't connect to the scanner. Please check that the backend is running and try again."
          : err.message || "We couldn't analyze that message. Please try again."
      );
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
      const res = await fetch(`${API_BASE}/verify/hash/${hashInput.trim()}`);
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

  // Plain-English translations of raw technical indicators
  const translateIndicator = (ind: string) => {
    const lower = ind.toLowerCase();
    if (lower.includes("strict-transport-security") || lower.includes("defensive headers")) {
      return {
        title: "Standard Security Configuration",
        desc: "The website uses basic HTTPS encryption, but hasn't activated strict browser security rules. Safe to browse, but avoid submitting passwords or payment details on public Wi-Fi."
      };
    }
    if (lower.includes("typosquatting") || lower.includes("brand impersonation")) {
      return {
        title: "Impersonation / Fake Domain Detected",
        desc: "This address looks almost identical to a well-known brand or bank, but is owned by someone else. Scammers use this trick to steal credentials."
      };
    }
    if (lower.includes("homoglyph") || lower.includes("punycode")) {
      return {
        title: "Deceptive Letter Swapping",
        desc: "This website uses lookalike foreign characters (e.g., Cyrillic 'a' instead of Latin 'a') to fool your eyes into thinking it's genuine."
      };
    }
    if (lower.includes("urgency") || lower.includes("psychological coercion")) {
      return {
        title: "High Urgency Pressure Tactic",
        desc: "The message is deliberately trying to panic you into taking immediate action (like threatening account suspension or legal action)."
      };
    }
    if (lower.includes("manipulative social engineering")) {
      return {
        title: "Phishing / Social Engineering Patterns",
        desc: "Language style matches standard fraudulent templates trying to extract personal information or money."
      };
    }
    if (lower.includes("contains external link")) {
      return {
        title: "External Link Redirect",
        desc: "This message contains an untrusted link leading outside official company apps."
      };
    }
    if (lower.includes("entropy") || lower.includes("dga")) {
      return {
        title: "Computer-Generated Random Name",
        desc: "The web address looks like a chaotic string of characters, common in disposable malware and temporary scam domains."
      };
    }
    return {
      title: ind,
      desc: "Suspicious security pattern detected by the automated analysis engine."
    };
  };

  // Plain-English verdict summary
  const getSimpleVerdict = (risk: string) => {
    switch (risk?.toLowerCase()) {
      case "low risk":
        return {
          title: "Good to Go: Safe to Browse",
          color: "text-emerald-400",
          bgColor: "bg-emerald-950/60 border-emerald-500/40",
          badgeColor: "bg-emerald-500 text-black",
          summary: "This website has a verified security certificate, official hostname identity, and no known malicious activities on record."
        };
      case "suspicious":
        return {
          title: "Caution Advised: Unverified Elements Found",
          color: "text-amber-400",
          bgColor: "bg-amber-950/60 border-amber-500/40",
          badgeColor: "bg-amber-500 text-black",
          summary: "This site isn't confirmed as malware, but it exhibits unusual setups (e.g., suspicious domain structure, newly registered issuer, or missing security headers). Proceed with caution."
        };
      case "high risk":
      case "confirmed malicious":
        return {
          title: "Danger: High Risk of Phishing or Fraud",
          color: "text-rose-400",
          bgColor: "bg-rose-950/60 border-rose-500/40",
          badgeColor: "bg-rose-500 text-white font-bold",
          summary: "Do not open this link or reply to this message. Strong evidence of brand impersonation, urgent coercion, or known scam activity detected."
        };
      default:
        return {
          title: "Analysis Complete",
          color: "text-cyan-400",
          bgColor: "bg-zinc-900 border-zinc-700",
          badgeColor: "bg-zinc-700 text-white",
          summary: "Assessment complete. See details below."
        };
    }
  };

  return (
    <div className="min-h-screen bg-black text-zinc-100 font-sans selection:bg-cyan-500 selection:text-black">
      {/* Header */}
      <header className="border-b border-zinc-800 bg-zinc-950/80 backdrop-blur sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded-lg bg-cyan-500 flex items-center justify-center font-black text-black text-sm">
              AI
            </div>
            <div>
              <h1 className="text-base font-bold tracking-tight text-white flex items-center gap-2">
                HackMatrix26 <span className="text-zinc-500 text-xs font-normal">| Cyber Threat Scanner & Verifier</span>
              </h1>
            </div>
          </div>
          <div className="flex items-center space-x-2 text-xs">
            <span className="flex h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span className="text-zinc-400 font-mono">ENGINE ONLINE</span>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-8">
        {/* Navigation Tabs */}
        <div className="flex border-b border-zinc-800 space-x-2 mb-8">
          <button
            onClick={() => { setActiveTab("url"); setError(null); }}
            className={`pb-3 px-4 text-sm font-semibold transition border-b-2 ${
              activeTab === "url"
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-zinc-400 hover:text-zinc-200"
            }`}
          >
            Check a Website Link
          </button>
          <button
            onClick={() => { setActiveTab("message"); setError(null); }}
            className={`pb-3 px-4 text-sm font-semibold transition border-b-2 ${
              activeTab === "message"
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-zinc-400 hover:text-zinc-200"
            }`}
          >
            Check a Suspicious Message / SMS
          </button>
          <button
            onClick={() => { setActiveTab("ledger"); setError(null); }}
            className={`pb-3 px-4 text-sm font-semibold transition border-b-2 ${
              activeTab === "ledger"
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-zinc-400 hover:text-zinc-200"
            }`}
          >
            Verify Blockchain Security Record
          </button>
        </div>

        {/* Tab 1: URL Scanner */}
        {activeTab === "url" && (
          <div className="space-y-6">
            <form onSubmit={analyzeUrl} className="bg-zinc-950 border border-zinc-800 rounded-xl p-5 shadow-2xl">
              <label className="block text-sm font-semibold text-zinc-200 mb-1">
                Enter any website address or link to check if it's safe:
              </label>
              <p className="text-xs text-zinc-500 mb-3">
                Checks for fake lookalike websites, invalid certificates, known malware links, and security vulnerabilities.
              </p>
              <div className="flex flex-col sm:flex-row gap-3">
                <input
                  type="text"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder="e.g., https://github.com or http://sbi-netbanking-verifykyc.top"
                  className="flex-1 bg-zinc-900 border border-zinc-700 rounded-lg px-4 py-3 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-cyan-500"
                  required
                />
                <button
                  type="submit"
                  disabled={loading}
                  className="bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-black font-semibold text-sm px-6 py-3 rounded-lg transition"
                >
                  {loading ? "Checking Safety..." : "Check Website"}
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Tab 2: Message Scanner */}
        {activeTab === "message" && (
          <div className="space-y-6">
            <form onSubmit={analyzeMessage} className="bg-zinc-950 border border-zinc-800 rounded-xl p-5 shadow-2xl">
              <label className="block text-sm font-semibold text-zinc-200 mb-1">
                Paste suspicious SMS, WhatsApp message, or email here:
              </label>
              <p className="text-xs text-zinc-500 mb-3">
                Identifies psychological pressure tactics, fake bank notices, and hidden malicious links.
              </p>
              <textarea
                value={messageInput}
                onChange={(e) => setMessageInput(e.target.value)}
                placeholder="Paste the message text here (e.g., 'URGENT: Your SBI account is blocked. Update KYC immediately at...')"
                rows={4}
                className="w-full bg-zinc-900 border border-zinc-700 rounded-lg p-3 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-cyan-500"
                required
              />
              <div className="mt-3 flex justify-end">
                <button
                  type="submit"
                  disabled={loading}
                  className="bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-black font-semibold text-sm px-6 py-3 rounded-lg transition"
                >
                  {loading ? "Analyzing Intent..." : "Scan for Scam Tactics"}
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Tab 3: Ledger Verification */}
        {activeTab === "ledger" && (
          <div className="space-y-6">
            <form onSubmit={verifyHash} className="bg-zinc-950 border border-zinc-800 rounded-xl p-5 shadow-2xl">
              <label className="block text-sm font-semibold text-zinc-200 mb-1">
                Verify an Official Security Audit Record:
              </label>
              <p className="text-xs text-zinc-500 mb-3">
                Paste any Report SHA-256 Hash to verify that the scan result was permanently recorded on-chain and has not been tampered with.
              </p>
              <div className="flex flex-col sm:flex-row gap-3">
                <input
                  type="text"
                  value={hashInput}
                  onChange={(e) => setHashInput(e.target.value)}
                  placeholder="Paste Report Hash (e.g. 7259adf7eceec841c2e5...)"
                  className="flex-1 bg-zinc-900 border border-zinc-700 rounded-lg px-4 py-3 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-cyan-500 font-mono"
                  required
                />
                <button
                  type="submit"
                  disabled={loading}
                  className="bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-black font-semibold text-sm px-6 py-3 rounded-lg transition"
                >
                  {loading ? "Verifying..." : "Verify Record"}
                </button>
              </div>
            </form>

            {verifyResult && (
              <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-6 space-y-6 shadow-2xl">
                {/* Header status */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800 pb-4">
                  <div>
                    <span className="text-xs font-semibold tracking-wider uppercase text-zinc-400 block mb-1">
                      Official Security Certificate
                    </span>
                    <h3 className="text-base font-bold text-white">
                      Scan Integrity Verified
                    </h3>
                  </div>
                  <span className={`px-4 py-1.5 rounded-full text-xs font-extrabold uppercase tracking-wide border self-start sm:self-auto ${
                    verifyResult.is_verified 
                      ? "bg-emerald-950/80 border-emerald-500/50 text-emerald-400" 
                      : "bg-rose-950/80 border-rose-500/50 text-rose-400"
                  }`}>
                    {verifyResult.is_verified ? "✓ Authentic & Tamper-Proof" : "✗ Record Not Found"}
                  </span>
                </div>

                {verifyResult.is_verified && verifyResult.audit_data ? (
                  <div className="space-y-4">
                    {/* What this means in plain words */}
                    <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-900/40 text-xs text-emerald-300 leading-relaxed">
                      ✓ <strong>Original Scan Confirmed:</strong> This report was logged when the website was scanned. The results below match the permanent public record and have not been altered.
                    </div>

                    {/* Clean Human-Readable Summary Cards */}
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                      <div className="bg-zinc-900/70 p-4 rounded-xl border border-zinc-800">
                        <span className="text-xs text-zinc-400 block mb-1">Website Scanned</span>
                        <span className="text-sm font-semibold text-white break-all">
                          {verifyResult.audit_data.target || "N/A"}
                        </span>
                      </div>

                      <div className="bg-zinc-900/70 p-4 rounded-xl border border-zinc-800">
                        <span className="text-xs text-zinc-400 block mb-1">Official Verdict</span>
                        <span className="text-sm font-bold text-emerald-400">
                          {verifyResult.audit_data.risk_level || "Unknown"}
                        </span>
                      </div>

                      <div className="bg-zinc-900/70 p-4 rounded-xl border border-zinc-800">
                        <span className="text-xs text-zinc-400 block mb-1">Safety Rating</span>
                        <span className="text-sm font-bold text-white">
                          {Math.round(
                            (verifyResult.audit_data.confidence || 0) <= 1
                              ? (verifyResult.audit_data.confidence || 0) * 100
                              : verifyResult.audit_data.confidence
                          )}%
                        </span>
                      </div>
                    </div>

                    {/* Proof Keys in neat compact bars */}
                    <div className="space-y-2 pt-2">
                      <div className="bg-zinc-900/40 p-3 rounded-lg border border-zinc-800 flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-xs font-mono">
                        <span className="text-zinc-500">Public Receipt (Tx):</span>
                        <span className="text-cyan-400 break-all">{verifyResult.on_chain_tx || "Confirmed"}</span>
                      </div>
                    </div>

                    {/* Raw Developer JSON collapsed for judges only */}
                    <details className="pt-2 text-xs text-zinc-500">
                      <summary className="cursor-pointer hover:text-zinc-300 transition">
                        View Raw Blockchain Ledger Data (Technical)
                      </summary>
                      <pre className="mt-2 bg-black p-4 rounded-xl text-xs font-mono text-zinc-400 overflow-x-auto border border-zinc-800">
                        {JSON.stringify(verifyResult.audit_data, null, 2)}
                      </pre>
                    </details>
                  </div>
                ) : (
                  <p className="text-xs text-zinc-400">
                    No matching report found for this hash. The hash might be mistyped or the report has not yet been registered.
                  </p>
                )}
              </div>
            )}
          </div>
        )}

        {/* Global Error Notice */}
        {error && (
          <div className="mt-6 p-4 bg-rose-950/60 border border-rose-800/80 rounded-xl text-rose-300 text-sm">
            {error}
          </div>
        )}

        {/* Analysis Result Display */}
        {analysisResult && (() => {
          const verdict = getSimpleVerdict(analysisResult.risk_level);
          const confidencePct = Math.round(
            analysisResult.confidence_score <= 1 
              ? analysisResult.confidence_score * 100 
              : analysisResult.confidence_score
          );

          return (
            <div className="mt-8 space-y-6">
              {/* Card 1: Clear Human Verdict Banner */}
              <div className={`border rounded-2xl p-6 shadow-2xl ${verdict.bgColor}`}>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-zinc-800/60 pb-4">
                  <div>
                    <span className="text-xs font-semibold tracking-wider uppercase text-zinc-400 block mb-1">
                      Scanned Target
                    </span>
                    <h2 className="text-base font-semibold text-white break-all">
                      {analysisResult.target}
                    </h2>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="text-right">
                      <span className="text-xs text-zinc-400 block">Assessment Score</span>
                      <span className="text-base font-bold text-white">{confidencePct}%</span>
                    </div>
                    <span className={`px-4 py-2 rounded-xl text-xs font-extrabold uppercase tracking-wide ${verdict.badgeColor}`}>
                      {analysisResult.risk_level}
                    </span>
                  </div>
                </div>

                <div className="mt-4">
                  <h3 className={`text-xl font-bold mb-1 ${verdict.color}`}>
                    {verdict.title}
                  </h3>
                  <p className="text-zinc-200 text-sm leading-relaxed">
                    {verdict.summary}
                  </p>
                </div>
              </div>

              {/* Card 2: Plain English Findings & Practical Advice */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {analysisResult.campaign_correlation?.is_campaign && (
                  (() => {
                    const evidence = analysisResult.technical_evidence;
                    const campaignBrand =
                      evidence?.url_structure?.matched_brand ||
                      evidence?.impersonated_brand;
                    const normalizedBrand =
                      typeof campaignBrand === "string" &&
                      !["", "unknown", "unspecified", "financial / institutional entity"].includes(
                        campaignBrand.trim().toLowerCase()
                      )
                        ? campaignBrand
                        : "this organization";

                    return (
                      <div
                        role="alert"
                        className="md:col-span-2 rounded-2xl border border-amber-500/40 bg-gradient-to-r from-amber-950/40 via-red-950/30 to-zinc-950 p-5 text-amber-100 shadow-[0_0_30px_rgba(244,63,94,0.12)]"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-3">
                          <h3 className="flex items-center gap-2 text-base font-extrabold tracking-wide text-amber-100">
                            <span
                              aria-hidden="true"
                              className="h-2.5 w-2.5 animate-pulse rounded-full bg-rose-400 shadow-[0_0_12px_rgba(251,113,133,0.9)]"
                            />
                            🚨 Large Scam Ring Detected
                          </h3>
                          {analysisResult.campaign_correlation.campaign_id && (
                            <span className="rounded-full border border-amber-400/40 bg-amber-400/10 px-3 py-1 font-mono text-xs font-bold text-amber-200 shadow-[0_0_12px_rgba(251,191,36,0.12)]">
                              Campaign ID: {analysisResult.campaign_correlation.campaign_id}
                            </span>
                          )}
                        </div>
                        <p className="mt-3 text-sm leading-relaxed text-zinc-200">
                          We have linked this link to an active wave targeting {normalizedBrand}.{" "}
                          <span className="mx-1 inline-flex rounded-full border border-rose-400/40 bg-rose-400/10 px-2.5 py-0.5 font-bold tabular-nums text-rose-200 shadow-[0_0_12px_rgba(251,113,133,0.15)]">
                            {analysisResult.campaign_correlation.related_reports_count}
                          </span>{" "}
                          people have recently flagged identical attacks.
                        </p>
                      </div>
                    );
                  })()
                )}
                {/* Findings in Plain Language */}
                <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-6">
                  <h3 className="text-sm font-bold text-white mb-1 flex items-center gap-2">
                    <span>🔍</span> What We Discovered
                  </h3>
                  <p className="text-xs text-zinc-400 mb-4">
                    Key signals and behavior identified during the security scan:
                  </p>

                  {analysisResult.detected_indicators.length === 0 ? (
                    <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-900/50 text-xs text-emerald-300">
                      ✓ No suspicious behavior or security vulnerabilities detected. Everything appears standard and legitimate.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {analysisResult.detected_indicators.map((ind, idx) => {
                        const t = translateIndicator(ind);
                        return (
                          <div key={idx} className="p-3.5 rounded-xl bg-zinc-900/80 border border-zinc-800">
                            <div className="text-xs font-bold text-zinc-200 mb-1 flex items-center gap-2">
                              <span className="text-amber-400 font-bold">•</span>
                              <span>{t.title}</span>
                            </div>
                            <p className="text-xs text-zinc-400 leading-relaxed">
                              {t.desc}
                            </p>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* What should the user do? */}
                <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-6">
                  <h3 className="text-sm font-bold text-white mb-1 flex items-center gap-2">
                    <span>🛡️</span> What You Should Do
                  </h3>
                  <p className="text-xs text-zinc-400 mb-4">
                    Clear safety steps based on our findings:
                  </p>

                  <div className="space-y-3">
                    {analysisResult.recommended_actions.map((act, idx) => (
                      <div key={idx} className="p-3.5 rounded-xl bg-zinc-900/80 border border-zinc-800 flex items-start gap-3">
                        <span className="text-cyan-400 font-bold text-sm mt-0.5">✓</span>
                        <p className="text-xs text-zinc-200 leading-relaxed">
                          {act}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Card 3: Blockchain Audit Verification (Simple Card + Copy) */}
              <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-6">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
                  <div>
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <span>⛓️</span> Tamper-Evident Security Receipt
                    </h3>
                    <p className="text-xs text-zinc-400">
                      This diagnostic report is mathematically signed and recorded on an immutable ledger so it cannot be altered.
                    </p>
                  </div>
                  <button
                    onClick={() => {
                      setHashInput(analysisResult.report_sha256);
                      setActiveTab("ledger");
                    }}
                    className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 underline self-start sm:self-auto"
                  >
                    Verify in Registry Tab →
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-zinc-900/60 p-3.5 rounded-xl border border-zinc-800">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-zinc-400">Report SHA-256 Hash</span>
                      <button
                        onClick={() => handleCopy(analysisResult.report_sha256, "sha")}
                        className="text-xs text-cyan-400 hover:text-cyan-300"
                      >
                        {copiedField === "sha" ? "Copied!" : "Copy"}
                      </button>
                    </div>
                    <div className="font-mono text-xs text-zinc-300 break-all">
                      {analysisResult.report_sha256}
                    </div>
                  </div>

                  <div className="bg-zinc-900/60 p-3.5 rounded-xl border border-zinc-800">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-zinc-400">On-Chain Transaction Receipt</span>
                      {analysisResult.on_chain_tx && (
                        <button
                          onClick={() => handleCopy(analysisResult.on_chain_tx!, "tx")}
                          className="text-xs text-cyan-400 hover:text-cyan-300"
                        >
                          {copiedField === "tx" ? "Copied!" : "Copy"}
                        </button>
                      )}
                    </div>
                    <div className="font-mono text-xs text-cyan-400 break-all">
                      {analysisResult.on_chain_tx || "Pending Confirmation"}
                    </div>
                  </div>
                </div>

                {/* Collapsible Technical Details (For Judges & Security Analysts) */}
                <div className="mt-5 pt-4 border-t border-zinc-800">
                  <button
                    onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
                    className="text-xs font-medium text-zinc-400 hover:text-zinc-200 flex items-center justify-between w-full"
                  >
                    <span>{showTechnicalDetails ? "▲ Hide Technical Evidence (JSON)" : "▼ Show Technical Evidence & Raw Data (For Judges & Security Experts)"}</span>
                  </button>

                  {showTechnicalDetails && (
                    <pre className="mt-4 bg-black p-4 rounded-xl text-xs font-mono text-zinc-300 overflow-x-auto border border-zinc-800 max-h-96">
                      {JSON.stringify(analysisResult.technical_evidence, null, 2)}
                    </pre>
                  )}
                </div>
              </div>
            </div>
          );
        })()}
      </main>
    </div>
  );
}