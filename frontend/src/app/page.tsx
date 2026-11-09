"use client";

import React, { useRef, useState } from "react";
import {
  analyzeMessage,
  analyzeUrl,
  ThreatAnalysisResponse,
  VerificationResponse,
  verifyHash,
} from "@/lib/api";

type ScanMode = "url" | "message" | "verify";
const CONNECTION_STATUS =
  "Connecting to threat intelligence engine... (if this is the first scan, the free cloud service may take 15-30s to wake up)";

interface RecentScan {
  id: string;
  result: ThreatAnalysisResponse;
  scannedAt: Date;
}

const riskStyles: Record<string, { label: string; badge: string; dot: string }> = {
  "low risk": {
    label: "Safe",
    badge: "bg-emerald-50 text-emerald-700 ring-emerald-200",
    dot: "bg-emerald-500",
  },
  suspicious: {
    label: "Suspicious",
    badge: "bg-amber-50 text-amber-700 ring-amber-200",
    dot: "bg-amber-500",
  },
  "high risk": {
    label: "Malicious",
    badge: "bg-rose-50 text-rose-700 ring-rose-200",
    dot: "bg-rose-500",
  },
  "confirmed malicious": {
    label: "Malicious",
    badge: "bg-rose-50 text-rose-700 ring-rose-200",
    dot: "bg-rose-500",
  },
  inconclusive: {
    label: "Inconclusive",
    badge: "bg-slate-100 text-slate-600 ring-slate-200",
    dot: "bg-slate-400",
  },
};

function getRiskStyle(risk: string) {
  return (
    riskStyles[risk?.toLowerCase()] ?? {
      label: risk || "Unknown",
      badge: "bg-slate-100 text-slate-600 ring-slate-200",
      dot: "bg-slate-400",
    }
  );
}

function getVerdict(risk: string) {
  switch (risk?.toLowerCase()) {
    case "low risk":
      return {
        title: "This link looks safe",
        description:
          "No significant threats were identified in this scan. Always check that the address belongs to the organization you expect.",
        panel: "border-emerald-200 bg-emerald-50/70",
        accent: "text-emerald-700",
      };
    case "suspicious":
      return {
        title: "Use caution with this link",
        description:
          "Some unusual signals were found. Avoid entering passwords or payment details until you verify the source.",
        panel: "border-amber-200 bg-amber-50/80",
        accent: "text-amber-700",
      };
    default:
      return {
        title: "This may be a threat",
        description:
          "The scan found signals associated with phishing or fraud. Do not open the link or share personal information.",
        panel: "border-rose-200 bg-rose-50/80",
        accent: "text-rose-700",
      };
  }
}

function displayTime(date: Date) {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

export default function ThreatDashboard() {
  const [activeTab, setActiveTab] = useState<ScanMode>("url");
  const [urlInput, setUrlInput] = useState("");
  const [messageInput, setMessageInput] = useState("");
  const [hashInput, setHashInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [analysisResult, setAnalysisResult] =
    useState<ThreatAnalysisResponse | null>(null);
  const [verifyResult, setVerifyResult] = useState<VerificationResponse | null>(
    null
  );
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const historyRef = useRef<HTMLElement>(null);

  const clearResults = (mode: ScanMode) => {
    setActiveTab(mode);
    setError(null);
    setAnalysisResult(null);
    setVerifyResult(null);
    setMobileNavOpen(false);
  };

  const handleCopy = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(label);
      window.setTimeout(() => setCopiedField(null), 2000);
    } catch {
      setError("Clipboard access is unavailable in this browser.");
    }
  };

  const saveScan = (result: ThreatAnalysisResponse) => {
    setAnalysisResult(result);
    setVerifyResult(null);
    setRecentScans((scans) => [
      {
        id: `${result.report_sha256}-${Date.now()}`,
        result,
        scannedAt: new Date(),
      },
      ...scans,
    ]);
  };

  const runUrlScan = async (inputUrl: string) => {
    const rawUrl = inputUrl.trim().replace(/^[\s@'"]+|[\s'"]+$/g, "");
    if (!rawUrl) return;

    const normalizedUrl = /^https?:\/\//i.test(rawUrl)
      ? rawUrl
      : `https://${rawUrl}`;
    setUrlInput(normalizedUrl);
    setLoading(true);
    setError(null);
    setAnalysisResult(null);
    setVerifyResult(null);

    try {
      saveScan(await analyzeUrl(normalizedUrl));
    } catch (scanError) {
      setError(
        scanError instanceof TypeError
          ? CONNECTION_STATUS
          : scanError instanceof Error
            ? scanError.message
            : "We couldn't analyze that website address. Please try again."
      );
    } finally {
      setLoading(false);
    }
  };

  const handleCheckUrl = (event: React.FormEvent) => {
    event.preventDefault();
    void runUrlScan(urlInput);
  };

  const switchTabAndFocus = (tab: ScanMode, inputId: string) => {
    clearResults(tab);
    window.setTimeout(() => document.getElementById(inputId)?.focus(), 0);
  };

  const handleCheckMessage = async (event: React.FormEvent) => {
    event.preventDefault();
    const cleanedMessage = messageInput
      .replace(/\r\n?/g, "\n")
      .replace(/[\u0000\u200B\uFEFF]/g, "")
      .trim();
    if (!cleanedMessage) return;

    setLoading(true);
    setError(null);
    setAnalysisResult(null);
    setVerifyResult(null);
    try {
      saveScan(await analyzeMessage(cleanedMessage, "SMS/Email Scam"));
    } catch (scanError) {
      setError(
        scanError instanceof TypeError
          ? CONNECTION_STATUS
          : scanError instanceof Error
            ? scanError.message
            : "We couldn't analyze that message. Please try again."
      );
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyHash = async (event: React.FormEvent) => {
    event.preventDefault();
    const hash = hashInput.trim();
    if (!hash) return;

    setLoading(true);
    setError(null);
    setVerifyResult(null);
    setAnalysisResult(null);
    try {
      setVerifyResult(await verifyHash(hash));
    } catch (verifyError) {
      setError(
        verifyError instanceof TypeError
          ? CONNECTION_STATUS
          : verifyError instanceof Error
            ? verifyError.message
            : "Ledger verification lookup failed. Please try again."
      );
    } finally {
      setLoading(false);
    }
  };

  const pasteFromClipboard = async () => {
    try {
      const clipboardText = await navigator.clipboard.readText();
      if (activeTab === "message") {
        setMessageInput(clipboardText);
      } else if (activeTab === "verify") {
        setHashInput(clipboardText.trim());
      } else {
        setUrlInput(clipboardText);
      }
      setError(null);
    } catch {
      setError("Clipboard access is unavailable. Please paste the copied text into the field.");
    }
  };

  const navItems: { label: string; icon: string; action: () => void }[] = [
    { label: "Home", icon: "⌂", action: () => clearResults("url") },
    {
      label: "Scan History",
      icon: "◷",
      action: () => {
        clearResults("url");
        window.setTimeout(
          () => historyRef.current?.scrollIntoView({ behavior: "smooth" }),
          0
        );
      },
    },
    {
      label: "Message Scam AI",
      icon: "✉",
      action: () => clearResults("message"),
    },
    {
      label: "Verify Blockchain Record",
      icon: "⛓",
      action: () => clearResults("verify"),
    },
  ];

  const activeResult = analysisResult;
  const verdict = activeResult ? getVerdict(activeResult.risk_level) : null;
  const confidence = activeResult
    ? Math.round(
        activeResult.confidence_score <= 1
          ? activeResult.confidence_score * 100
          : activeResult.confidence_score
      )
    : 0;
  const evidence = activeResult?.technical_evidence ?? {};
  const campaignBrand =
    evidence.url_structure?.matched_brand || evidence.impersonated_brand;
  const validCampaignBrand =
    typeof campaignBrand === "string" &&
    ![
      "",
      "unknown",
      "unspecified",
      "financial / institutional entity",
    ].includes(campaignBrand.trim().toLowerCase());

  return (
    <div className="min-h-screen bg-[#F4F7FC] font-sans text-slate-800">
      {mobileNavOpen && (
        <div
          aria-hidden="true"
          className="fixed inset-0 z-30 bg-slate-950/30 lg:hidden"
          onClick={() => setMobileNavOpen(false)}
        />
      )}

      <aside
        className={`fixed inset-y-0 left-0 z-40 flex w-[270px] flex-col border-r border-slate-200/80 bg-white px-5 py-6 shadow-sm transition-transform lg:translate-x-0 ${
          mobileNavOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="flex items-center justify-between">
          <a
            href="#home"
            className="flex items-center gap-3 px-2"
            onClick={() => clearResults("url")}
          >
            <span className="flex h-11 w-11 items-center justify-center rounded-2xl bg-blue-600 text-lg font-black text-white shadow-md shadow-blue-600/20">
              TG
            </span>
            <span>
              <span className="block text-lg font-bold tracking-tight text-slate-900">
                TrustGuard
              </span>
              <span className="block text-xs text-slate-500">
                Browse Safe. Stay Secure.
              </span>
            </span>
          </a>
          <button
            aria-label="Close navigation"
            onClick={() => setMobileNavOpen(false)}
            className="flex h-9 w-9 items-center justify-center rounded-xl text-slate-500 hover:bg-slate-100 lg:hidden"
          >
            ×
          </button>
        </div>

        <div className="mt-10">
          <p className="px-3 text-[11px] font-bold uppercase tracking-[0.16em] text-slate-400">
            Workspace
          </p>
          <nav className="mt-3 space-y-1.5" aria-label="Main navigation">
            {navItems.map((item, index) => {
              const active =
                (index === 0 && activeTab === "url" && !analysisResult) ||
                (index === 2 && activeTab === "message") ||
                (index === 3 && activeTab === "verify");
              return (
                <button
                  key={item.label}
                  onClick={item.action}
                  disabled={loading}
                  className={`flex w-full items-center gap-3 rounded-xl px-3 py-3 text-left text-sm font-medium transition ${
                    active
                      ? "bg-blue-50 text-blue-700"
                      : "text-slate-600 hover:bg-slate-50 hover:text-slate-900"
                  }`}
                >
                  <span
                    className={`flex h-7 w-7 items-center justify-center rounded-lg text-base ${
                      active ? "bg-white text-blue-600 shadow-sm" : "text-slate-400"
                    }`}
                  >
                    {item.icon}
                  </span>
                  {item.label}
                  {index === 1 && recentScans.length > 0 && (
                    <span className="ml-auto rounded-full bg-slate-100 px-2 py-0.5 text-[10px] text-slate-500">
                      {recentScans.length}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        <div className="mt-auto rounded-2xl border border-emerald-100 bg-emerald-50/80 p-4">
          <div className="flex items-center gap-2 text-xs font-semibold text-emerald-800">
            <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-500" />
            ⚡ Powered by AI Intelligence
          </div>
          <p className="mt-1.5 pl-4 text-[11px] text-emerald-700">
            Scanner services are online
          </p>
        </div>
        <p className="mt-4 px-2 text-[11px] text-slate-400">
          HackMatrix26 · Threat Intelligence
        </p>
      </aside>

      <div className="min-h-screen lg:pl-[270px]">
        <header className="sticky top-0 z-20 border-b border-slate-200/80 bg-[#F4F7FC]/90 backdrop-blur">
          <div className="mx-auto flex h-[68px] max-w-[1440px] items-center justify-between px-4 sm:px-7 lg:px-10">
            <button
              aria-label="Open navigation"
              onClick={() => setMobileNavOpen(true)}
              className="flex h-10 w-10 items-center justify-center rounded-xl border border-slate-200 bg-white text-slate-700 lg:hidden"
            >
              ☰
            </button>
            <div className="hidden items-center gap-2 text-xs font-medium text-slate-500 sm:flex">
              <span className="h-2 w-2 rounded-full bg-emerald-500" />
              Threat intelligence active
            </div>
            <div className="ml-auto flex items-center gap-3">
              <span className="hidden rounded-full border border-blue-100 bg-white px-3 py-1.5 text-xs font-semibold text-blue-700 sm:inline-flex">
                ✦ AI-Powered Threat Detection
              </span>
              <span className="flex h-9 w-9 items-center justify-center rounded-full bg-blue-100 text-sm font-bold text-blue-700">
                TG
              </span>
            </div>
          </div>
        </header>

        <main
          id="home"
          className="mx-auto max-w-[1440px] px-4 pb-14 pt-8 sm:px-7 lg:px-10 lg:pt-10"
        >
          <section className="mb-8">
            <p className="inline-flex items-center gap-2 rounded-full border border-blue-100 bg-white px-3.5 py-1.5 text-xs font-semibold text-blue-700 shadow-sm">
              <span className="text-blue-500">✦</span> AI-Powered Threat Detection
            </p>
            <div className="mt-5 flex flex-col justify-between gap-4 md:flex-row md:items-end">
              <div>
                <h1 className="max-w-3xl text-3xl font-extrabold tracking-tight text-slate-900 sm:text-4xl lg:text-[42px]">
                  Detect Threats, Stay Safe Online
                </h1>
                <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-500 sm:text-base">
                  Check suspicious links and messages with AI-powered threat
                  intelligence, then verify every report with a cryptographic
                  receipt.
                </p>
              </div>
              <div className="hidden items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-xs text-slate-500 shadow-sm md:flex">
                <span className="text-base">🛡️</span>
                Private, fast, and easy to use
              </div>
            </div>
          </section>

          <section className="rounded-3xl border border-blue-50 bg-white p-4 shadow-md shadow-slate-200/50 sm:p-6 lg:p-7">
            <div className="flex flex-col gap-5">
              <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-center">
                <div>
                  <h2 className="text-lg font-bold text-slate-900">
                    What would you like to check?
                  </h2>
                  <p className="mt-1 text-sm text-slate-500">
                    Choose a scan type to get started.
                  </p>
                </div>
                <div className="flex flex-wrap gap-1.5 rounded-2xl bg-slate-100 p-1.5">
                  {(
                    [
                      ["url", "Check Website Link"],
                      ["message", "Suspicious Message / SMS"],
                      ["verify", "Verify Blockchain Record"],
                    ] as const
                  ).map(([mode, label]) => (
                    <button
                      key={mode}
                      disabled={loading}
                      onClick={() => clearResults(mode)}
                      className={`rounded-xl px-3 py-2 text-xs font-semibold transition sm:px-4 sm:text-sm ${
                        activeTab === mode
                          ? "bg-white text-blue-700 shadow-sm"
                          : "text-slate-500 hover:text-slate-800"
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>

              {activeTab === "url" && (
                <form onSubmit={handleCheckUrl}>
                  <label htmlFor="url-input" className="sr-only">
                    Website address to scan
                  </label>
                  <div className="flex flex-col gap-2 rounded-2xl border border-slate-200 bg-slate-50 p-2 focus-within:border-blue-300 focus-within:ring-4 focus-within:ring-blue-50 sm:flex-row sm:items-center">
                    <span className="hidden pl-3 text-xl text-slate-400 sm:inline">
                      ⌕
                    </span>
                    <input
                      id="url-input"
                      value={urlInput}
                      disabled={loading}
                      onChange={(event) => setUrlInput(event.target.value)}
                      placeholder="Paste a website URL or enter a domain"
                      className="min-w-0 flex-1 bg-transparent px-3 py-3 text-sm text-slate-800 outline-none placeholder:text-slate-400 sm:px-1"
                      required
                      type="text"
                    />
                    <button
                      disabled={loading}
                      className="inline-flex items-center justify-center gap-2 rounded-xl bg-blue-600 px-6 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700 disabled:cursor-wait disabled:opacity-60"
                    >
                      {loading ? (
                        <>
                          <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/40 border-t-white" />
                          Scanning…
                        </>
                      ) : (
                        <>Scan Now <span aria-hidden="true">→</span></>
                      )}
                    </button>
                  </div>
                </form>
              )}

              {activeTab === "message" && (
                <form onSubmit={handleCheckMessage}>
                  <label htmlFor="message-input" className="mb-2 block text-sm font-medium text-slate-700">
                    Paste the suspicious message
                  </label>
                  <textarea
                    id="message-input"
                    rows={4}
                    value={messageInput}
                    disabled={loading}
                    onChange={(event) => setMessageInput(event.target.value)}
                    placeholder="Paste SMS, WhatsApp forwards, emails, or messages with suspicious links…"
                    className="w-full resize-y rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm leading-6 text-slate-800 outline-none placeholder:text-slate-400 focus:border-blue-300 focus:ring-4 focus:ring-blue-50"
                    required
                  />
                  <div className="mt-3 flex justify-end">
                    <button
                      disabled={loading}
                      className="inline-flex items-center gap-2 rounded-xl bg-blue-600 px-6 py-3 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:opacity-60"
                    >
                      {loading ? (
                        <>
                          <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/40 border-t-white" />
                          Analyzing message…
                        </>
                      ) : (
                        "Analyze Message →"
                      )}
                    </button>
                  </div>
                </form>
              )}

              {activeTab === "verify" && (
                <form onSubmit={handleVerifyHash}>
                  <label htmlFor="verify-input" className="mb-2 block text-sm font-medium text-slate-700">
                    Verify a SHA-256 security report
                  </label>
                  <div className="flex flex-col gap-2 rounded-2xl border border-slate-200 bg-slate-50 p-2 sm:flex-row sm:items-center">
                    <span className="hidden pl-3 text-lg text-slate-400 sm:inline">⛓</span>
                    <input
                      id="verify-input"
                      value={hashInput}
                      disabled={loading}
                      onChange={(event) => setHashInput(event.target.value)}
                      placeholder="Paste report hash"
                      className="min-w-0 flex-1 bg-transparent px-3 py-3 font-mono text-sm text-slate-800 outline-none placeholder:font-sans placeholder:text-slate-400 sm:px-1"
                      required
                    />
                    <button
                      disabled={loading}
                      className="inline-flex items-center justify-center gap-2 rounded-xl bg-blue-600 px-6 py-3 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:opacity-60"
                    >
                      {loading ? (
                        <>
                          <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/40 border-t-white" />
                          Verifying…
                        </>
                      ) : (
                        "Verify Record →"
                      )}
                    </button>
                  </div>
                </form>
              )}

              <div className="flex flex-wrap items-center gap-2">
                <span className="mr-1 text-xs font-medium text-slate-400">
                  Quick actions
                </span>
                <button
                  type="button"
                  onClick={pasteFromClipboard}
                  disabled={loading}
                  className="rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-600 transition hover:border-blue-200 hover:text-blue-700"
                >
                  ⎘ Paste from Clipboard
                </button>
                {activeTab === "url" && (
                  <>
                    <button
                      type="button"
                      onClick={() => void runUrlScan("https://adamasuniversity.ac.in")}
                      disabled={loading}
                      className="rounded-full border border-emerald-100 bg-emerald-50/70 px-3 py-1.5 text-xs font-medium text-emerald-700 transition hover:bg-emerald-100"
                    >
                      Test Benign (Adamas)
                    </button>
                    <button
                      type="button"
                      onClick={() => void runUrlScan("http://sbi-kyc-reactivate.top")}
                      disabled={loading}
                      className="rounded-full border border-rose-100 bg-rose-50/70 px-3 py-1.5 text-xs font-medium text-rose-700 transition hover:bg-rose-100"
                    >
                      Test Phishing (SBI Scam)
                    </button>
                  </>
                )}
                {loading && (
                  <p role="status" className="w-full pt-1 text-xs text-blue-700">
                    {CONNECTION_STATUS}
                  </p>
                )}
              </div>

              {error && (
                <div
                  role="alert"
                  className="rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700"
                >
                  {error}
                </div>
              )}
            </div>
          </section>

          {activeResult && verdict && (
            <section className="mt-8 space-y-5" aria-live="polite">
              <div className={`rounded-3xl border p-5 shadow-sm sm:p-7 ${verdict.panel}`}>
                {activeResult.campaign_correlation?.is_campaign &&
                  activeResult.risk_level !== "Low Risk" && (
                  <div className="mb-6 rounded-2xl border border-amber-300 bg-gradient-to-r from-amber-50 via-rose-50 to-white p-4 shadow-sm sm:p-5">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <h2 className="flex items-center gap-2 font-bold text-rose-800">
                        <span className="h-2.5 w-2.5 animate-pulse rounded-full bg-rose-500" />
                        🚨 Large Scam Ring Detected
                      </h2>
                      {activeResult.campaign_correlation.campaign_id && (
                        <span className="rounded-full border border-amber-300 bg-white px-3 py-1.5 font-mono text-xs font-bold text-amber-800 shadow-sm">
                          Campaign ID: {activeResult.campaign_correlation.campaign_id}
                        </span>
                      )}
                    </div>
                    <p className="mt-2 text-sm leading-6 text-slate-700">
                      We have linked this link to an active wave targeting{" "}
                      {validCampaignBrand ? campaignBrand : "this organization"}.{" "}
                      <span className="inline-flex rounded-full border border-rose-200 bg-rose-100 px-2.5 py-0.5 font-bold tabular-nums text-rose-800">
                        {activeResult.campaign_correlation.related_reports_count}
                      </span>{" "}
                      people have recently flagged identical attacks.
                    </p>
                  </div>
                )}
                <div className="flex flex-col justify-between gap-5 sm:flex-row sm:items-start">
                  <div className="min-w-0">
                    <p className="text-xs font-bold uppercase tracking-[0.14em] text-slate-500">
                      Scan result
                    </p>
                    <h2 className={`mt-2 text-2xl font-bold ${verdict.accent}`}>
                      {verdict.title}
                    </h2>
                    <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
                      {activeResult.summary || verdict.description}
                    </p>
                    <p className="mt-4 break-all rounded-xl border border-white/80 bg-white/70 px-3 py-2 font-mono text-xs text-slate-600">
                      {activeResult.target}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-3">
                    <div className="rounded-2xl border border-white/80 bg-white/80 px-4 py-3 text-center shadow-sm">
                      <p className="text-[11px] font-medium text-slate-500">Confidence</p>
                      <p className="mt-1 text-xl font-bold text-slate-900">{confidence}%</p>
                    </div>
                    <span className={`rounded-full px-3 py-2 text-xs font-bold ring-1 ring-inset ${getRiskStyle(activeResult.risk_level).badge}`}>
                      {getRiskStyle(activeResult.risk_level).label}
                    </span>
                  </div>
                </div>
              </div>

              <div className="grid gap-5 lg:grid-cols-2">
                <div className="rounded-2xl border border-blue-100 bg-blue-50/50 p-5 sm:p-6">
                  <div className="flex items-center gap-2">
                    <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-white text-blue-600 shadow-sm">⌕</span>
                    <div>
                      <h3 className="font-bold text-slate-900">What We Discovered</h3>
                      <p className="text-xs text-slate-500">Signals from this scan</p>
                    </div>
                  </div>
                  {activeResult.detected_indicators.length === 0 ? (
                    <p className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50/70 p-4 text-sm text-emerald-800">
                      No suspicious indicators were detected in this scan.
                    </p>
                  ) : (
                    <ul className="mt-4 space-y-2.5">
                      {activeResult.detected_indicators.map((indicator, index) => (
                        <li key={`${indicator}-${index}`} className="flex gap-2.5 rounded-xl border border-white bg-white/80 p-3 text-sm leading-5 text-slate-700">
                          <span className="mt-0.5 text-blue-600">•</span>
                          {indicator}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>

                <div className="rounded-2xl border border-emerald-200 bg-emerald-50/50 p-5 sm:p-6">
                  <div className="flex items-center gap-2">
                    <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-white text-emerald-600 shadow-sm">✓</span>
                    <div>
                      <h3 className="font-bold text-slate-900">What You Should Do</h3>
                      <p className="text-xs text-slate-500">Recommended next steps</p>
                    </div>
                  </div>
                  <ul className="mt-4 space-y-2.5">
                    {activeResult.recommended_actions.map((action, index) => (
                      <li key={`${action}-${index}`} className="flex gap-2.5 rounded-xl border border-white bg-white/80 p-3 text-sm leading-5 text-slate-700">
                        <span className="text-emerald-600">✓</span>
                        {action}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              <div className="overflow-hidden rounded-3xl border border-blue-100 bg-white shadow-sm">
                <div className="border-b border-slate-100 bg-gradient-to-r from-blue-50/80 to-white px-5 py-5 sm:px-7">
                  <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-blue-600 text-white shadow-sm">⛓</span>
                        <h3 className="font-bold text-slate-900">Cryptographic Verification Receipt</h3>
                      </div>
                      <p className="mt-2 text-xs leading-5 text-slate-500">
                        This report is hashed and registered for tamper-evident verification.
                      </p>
                    </div>
                    <button
                      onClick={() => {
                        setHashInput(activeResult.report_sha256);
                        clearResults("verify");
                      }}
                      className="self-start rounded-xl border border-blue-200 bg-white px-4 py-2 text-xs font-semibold text-blue-700 transition hover:bg-blue-50 sm:self-auto"
                    >
                      Verify this report →
                    </button>
                  </div>
                </div>
                <div className="grid gap-3 p-5 sm:grid-cols-2 sm:p-7">
                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-xs font-semibold text-slate-500">Report SHA-256</p>
                      <button
                        onClick={() => handleCopy(activeResult.report_sha256, "sha")}
                        className="text-xs font-semibold text-blue-600 hover:text-blue-800"
                      >
                        {copiedField === "sha" ? "Copied" : "Copy"}
                      </button>
                    </div>
                    <p className="mt-2 break-all font-mono text-xs leading-5 text-slate-700">
                      {activeResult.report_sha256}
                    </p>
                  </div>
                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-xs font-semibold text-slate-500">Ledger transaction receipt</p>
                      {activeResult.on_chain_tx && (
                        <button
                          onClick={() => handleCopy(activeResult.on_chain_tx!, "tx")}
                          className="text-xs font-semibold text-blue-600 hover:text-blue-800"
                        >
                          {copiedField === "tx" ? "Copied" : "Copy"}
                        </button>
                      )}
                    </div>
                    <p className="mt-2 break-all font-mono text-xs leading-5 text-blue-700">
                      {activeResult.on_chain_tx || "Receipt pending"}
                    </p>
                  </div>
                </div>
              </div>

              <details
                open={showTechnicalDetails}
                onToggle={(event) =>
                  setShowTechnicalDetails(event.currentTarget.open)
                }
                className="rounded-2xl border border-slate-200 bg-white shadow-sm"
              >
                <summary className="cursor-pointer list-none px-5 py-4 text-sm font-semibold text-slate-700 marker:hidden">
                  <span className="flex items-center justify-between">
                    Technical Inspector <span className="text-xs font-normal text-slate-400">For Judges · Raw JSON and HTTP evidence</span>
                  </span>
                </summary>
                <pre className="max-h-[480px] overflow-auto border-t border-slate-100 bg-slate-950 p-4 text-xs leading-5 text-slate-100 sm:p-6">
                  {JSON.stringify(
                    {
                      technical_evidence: activeResult.technical_evidence,
                      detected_indicators: activeResult.detected_indicators,
                      campaign_correlation: activeResult.campaign_correlation,
                    },
                    null,
                    2
                  )}
                </pre>
              </details>
            </section>
          )}

          {verifyResult && (
            <section className="mt-8 rounded-3xl border border-blue-100 bg-white p-5 shadow-sm sm:p-7">
              <div className="flex flex-col justify-between gap-4 border-b border-slate-100 pb-5 sm:flex-row sm:items-center">
                <div>
                  <p className="text-xs font-bold uppercase tracking-[0.14em] text-slate-400">
                    Blockchain record verification
                  </p>
                  <h2 className="mt-2 text-2xl font-bold text-slate-900">
                    {verifyResult.is_verified
                      ? "Report integrity verified"
                      : "No matching report found"}
                  </h2>
                </div>
                <span className={`w-fit rounded-full px-3 py-2 text-xs font-bold ring-1 ring-inset ${
                  verifyResult.is_verified
                    ? "bg-emerald-50 text-emerald-700 ring-emerald-200"
                    : "bg-rose-50 text-rose-700 ring-rose-200"
                }`}>
                  {verifyResult.is_verified ? "✓ Authentic record" : "Not verified"}
                </span>
              </div>
              {verifyResult.is_verified && verifyResult.audit_data ? (
                <>
                  <p className="mt-5 rounded-2xl border border-emerald-200 bg-emerald-50/70 p-4 text-sm leading-6 text-emerald-800">
                    The report hash matches a record in the verification ledger.
                  </p>
                  <div className="mt-4 grid gap-3 sm:grid-cols-2">
                    <div className="rounded-2xl bg-slate-50 p-4">
                      <p className="text-xs font-semibold text-slate-500">Scanned target</p>
                      <p className="mt-2 break-all text-sm font-medium text-slate-800">
                        {verifyResult.audit_data.target || "Not available"}
                      </p>
                    </div>
                    <div className="rounded-2xl bg-slate-50 p-4">
                      <p className="text-xs font-semibold text-slate-500">Risk level</p>
                      <p className="mt-2 text-sm font-bold text-slate-800">
                        {verifyResult.audit_data.risk_level || "Unknown"}
                      </p>
                    </div>
                    <div className="rounded-2xl bg-slate-50 p-4 sm:col-span-2">
                      <p className="text-xs font-semibold text-slate-500">Transaction receipt</p>
                      <p className="mt-2 break-all font-mono text-xs leading-5 text-blue-700">
                        {verifyResult.on_chain_tx || "Not available"}
                      </p>
                    </div>
                  </div>
                  <details className="mt-5 rounded-xl border border-slate-200">
                    <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-slate-600">
                      Technical ledger data
                    </summary>
                    <pre className="max-h-96 overflow-auto rounded-b-xl bg-slate-950 p-4 text-xs text-slate-100">
                      {JSON.stringify(verifyResult.audit_data, null, 2)}
                    </pre>
                  </details>
                </>
              ) : (
                <p className="mt-5 text-sm text-slate-500">
                  Check that the hash is correct or run a scan to create a report.
                </p>
              )}
            </section>
          )}

          {!analysisResult && !verifyResult && (
            <>
              <section className="mt-8 grid gap-4 md:grid-cols-3">
                <button
                  type="button"
                  disabled={loading}
                  onClick={() => switchTabAndFocus("url", "url-input")}
                  className="rounded-2xl border border-emerald-100 bg-white p-5 text-left shadow-sm cursor-pointer transition-all duration-200 hover:-translate-y-1 hover:shadow-md hover:border-emerald-300"
                >
                  <span className="flex h-11 w-11 items-center justify-center rounded-2xl bg-emerald-50 text-xl text-emerald-700">⌕</span>
                  <h3 className="mt-4 font-bold text-slate-900">Threat Detection</h3>
                  <p className="mt-2 text-sm leading-6 text-slate-500">
                    Identify malicious websites, harmful links, and deceptive domains.
                  </p>
                </button>
                <button
                  type="button"
                  disabled={loading}
                  onClick={() => switchTabAndFocus("message", "message-input")}
                  className="rounded-2xl border border-rose-100 bg-white p-5 text-left shadow-sm cursor-pointer transition-all duration-200 hover:-translate-y-1 hover:shadow-md hover:border-rose-300"
                >
                  <span className="flex h-11 w-11 items-center justify-center rounded-2xl bg-rose-50 text-xl text-rose-700">✉</span>
                  <h3 className="mt-4 font-bold text-slate-900">Fraud Detection</h3>
                  <p className="mt-2 text-sm leading-6 text-slate-500">
                    Spot urgent SMS scams, phishing attempts, and fake payment requests.
                  </p>
                </button>
                <button
                  type="button"
                  disabled={loading}
                  onClick={() => switchTabAndFocus("verify", "verify-input")}
                  className="rounded-2xl border border-violet-100 bg-white p-5 text-left shadow-sm cursor-pointer transition-all duration-200 hover:-translate-y-1 hover:shadow-md hover:border-indigo-300"
                >
                  <span className="flex h-11 w-11 items-center justify-center rounded-2xl bg-violet-50 text-xl text-violet-700">⛓</span>
                  <h3 className="mt-4 font-bold text-slate-900">Fake URL & Web3 Proof</h3>
                  <p className="mt-2 text-sm leading-6 text-slate-500">
                    Detect lookalike domains and verify scan integrity with an on-chain receipt.
                  </p>
                </button>
              </section>

              <section className="mt-8 grid gap-5 xl:grid-cols-[1.65fr_1fr]">
                <article
                  ref={historyRef}
                  id="scan-history"
                  className="rounded-3xl border border-blue-50 bg-white p-5 shadow-sm sm:p-6"
                >
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <h2 className="font-bold text-slate-900">Recent Scans</h2>
                      <p className="mt-1 text-xs text-slate-500">Your scans in this session</p>
                    </div>
                    <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-500">
                      {recentScans.length} total
                    </span>
                  </div>
                  {recentScans.length === 0 ? (
                    <div className="mt-5 rounded-2xl border border-dashed border-slate-200 bg-slate-50/70 px-4 py-8 text-center">
                      <span className="text-2xl">🛡️</span>
                      <p className="mt-2 text-sm font-medium text-slate-700">Your scan history will appear here</p>
                      <p className="mt-1 text-xs text-slate-400">Run a website or message check to get started.</p>
                    </div>
                  ) : (
                    <div className="mt-4 overflow-x-auto">
                      <table className="w-full min-w-[560px] text-left text-sm">
                        <thead>
                          <tr className="border-b border-slate-100 text-[11px] uppercase tracking-wider text-slate-400">
                            <th className="px-3 py-3 font-semibold">Target</th>
                            <th className="px-3 py-3 font-semibold">Status</th>
                            <th className="px-3 py-3 font-semibold">Scanned</th>
                            <th className="px-3 py-3 text-right font-semibold">Report</th>
                          </tr>
                        </thead>
                        <tbody>
                          {recentScans.slice(0, 8).map((scan) => {
                            const style = getRiskStyle(scan.result.risk_level);
                            return (
                              <tr key={scan.id} className="border-b border-slate-50 last:border-0">
                                <td className="max-w-[240px] truncate px-3 py-3 font-medium text-slate-700">
                                  {scan.result.target}
                                </td>
                                <td className="px-3 py-3">
                                  <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-semibold ring-1 ring-inset ${style.badge}`}>
                                    <span className={`h-1.5 w-1.5 rounded-full ${style.dot}`} />
                                    {style.label}
                                  </span>
                                </td>
                                <td className="px-3 py-3 text-xs text-slate-500">
                                  {displayTime(scan.scannedAt)}
                                </td>
                                <td className="px-3 py-3 text-right">
                                  <button
                                    onClick={() => {
                                      setAnalysisResult(scan.result);
                                      setVerifyResult(null);
                                      setActiveTab(scan.result.target === "Pasted Message" ? "message" : "url");
                                    }}
                                    className="text-xs font-semibold text-blue-600 hover:text-blue-800"
                                  >
                                    View report
                                  </button>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}
                </article>

                <article className="relative overflow-hidden rounded-3xl border border-blue-100 bg-gradient-to-br from-blue-600 to-indigo-700 p-6 text-white shadow-md">
                  <div className="absolute -right-8 -top-8 h-36 w-36 rounded-full border-[20px] border-white/10" />
                  <div className="relative">
                    <span className="flex h-11 w-11 items-center justify-center rounded-2xl bg-white/15 text-xl">✦</span>
                    <h2 className="mt-5 text-xl font-bold">Stay Alert, Stay Safe!</h2>
                    <p className="mt-2 text-sm leading-6 text-blue-100">
                      A few quick checks can help protect your accounts and identity.
                    </p>
                    <ul className="mt-5 space-y-3 text-sm leading-5 text-white/95">
                      <li className="flex gap-2"><span>✓</span> Check the full sender address before you click.</li>
                      <li className="flex gap-2"><span>✓</span> Never share passwords, PINs, or OTPs from a message link.</li>
                      <li className="flex gap-2"><span>✓</span> Verify urgent requests through official channels.</li>
                    </ul>
                  </div>
                </article>
              </section>
            </>
          )}

          <footer className="mt-10 flex flex-col justify-between gap-2 border-t border-slate-200 pt-5 text-xs text-slate-400 sm:flex-row">
            <span>TrustGuard · HackMatrix26 Threat Intelligence</span>
            <span>Scan carefully. Verify independently.</span>
          </footer>
        </main>
      </div>
    </div>
  );
}
