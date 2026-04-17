"use client";

import { FormEvent, useMemo, useState } from "react";

type UrlApiResult = {
  inputUrl: string;
  normalizedUrl: string;
  hostname: string;
  risk: {
    score: number;
    level: string;
    finalUrl?: string;
    suspiciousIndicators: string[];
    virusTotal?: {
      malicious: number;
      suspicious: number;
      harmless: number;
      undetected: number;
    };
  };
  dns: {
    records: Record<string, string[]>;
    errors: string[];
  };
};

type QrApiResult = {
  findings: Array<
    | {
        type: "url";
        payload: string;
        risk: {
          score: number;
          level: string;
          finalUrl?: string;
          suspiciousIndicators: string[];
        };
        dns: {
          records: Record<string, string[]>;
          errors: string[];
        };
      }
    | {
        type: "text";
        payload: string;
      }
  >;
};

const EMPTY_RECORDS: Record<string, string[]> = {};

function renderDns(records?: Record<string, string[]>) {
  const safeRecords = records ?? EMPTY_RECORDS;
  return (
    <table>
      <thead>
        <tr>
          <th>Type</th>
          <th>Records</th>
        </tr>
      </thead>
      <tbody>
        {Object.entries(safeRecords).map(([type, list]) => (
          <tr key={type}>
            <td>{type}</td>
            <td className="mono">{list.length ? list.join("\n") : "-"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function renderDnsErrors(errors?: string[]) {
  if (!errors || errors.length === 0) {
    return null;
  }
  return (
    <div className="mono" style={{ marginTop: 8 }}>
      DNS lookup notes: {errors.join(" | ")}
    </div>
  );
}

export default function HomePage() {
  const [urlInput, setUrlInput] = useState("");
  const [urlResult, setUrlResult] = useState<UrlApiResult | null>(null);
  const [urlError, setUrlError] = useState("");
  const [urlLoading, setUrlLoading] = useState(false);

  const [qrFile, setQrFile] = useState<File | null>(null);
  const [qrResult, setQrResult] = useState<QrApiResult | null>(null);
  const [qrError, setQrError] = useState("");
  const [qrLoading, setQrLoading] = useState(false);

  const topQrFinding = useMemo(
    () => qrResult?.findings.find((f) => f.type === "url"),
    [qrResult],
  );

  async function handleUrlSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setUrlLoading(true);
    setUrlError("");
    setUrlResult(null);
    try {
      const response = await fetch("/api/analyze-url", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url: urlInput }),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error ?? "Failed to analyze URL");
      }
      setUrlResult(payload as UrlApiResult);
    } catch (error) {
      setUrlError(error instanceof Error ? error.message : "Failed to analyze URL");
    } finally {
      setUrlLoading(false);
    }
  }

  async function handleQrSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setQrLoading(true);
    setQrError("");
    setQrResult(null);
    try {
      const form = new FormData();
      if (qrFile) {
        form.append("qr", qrFile);
      }
      const response = await fetch("/api/analyze-qr", {
        method: "POST",
        body: form,
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error ?? "Failed to analyze QR");
      }
      setQrResult(payload as QrApiResult);
    } catch (error) {
      setQrError(error instanceof Error ? error.message : "Failed to analyze QR");
    } finally {
      setQrLoading(false);
    }
  }

  return (
    <main className="page">
      <section className="hero">
        <h1>PhishScope Web</h1>
        <p>Upload a QR or paste a URL to get phishing risk score and full DNS signals.</p>
      </section>

      <section className="grid">
        <article className="card">
          <h2>URL Analyzer</h2>
          <form onSubmit={handleUrlSubmit}>
            <label>
              URL / Domain
              <input
                type="text"
                value={urlInput}
                onChange={(event) => setUrlInput(event.target.value)}
                placeholder="example.com or https://example.com/login"
                required
              />
            </label>
            <button type="submit" disabled={urlLoading}>
              {urlLoading ? "Scanning..." : "Scan URL"}
            </button>
          </form>
          {urlError ? <div className="error">{urlError}</div> : null}

          {urlResult ? (
            <>
              <div className="score">
                <strong>Score: {urlResult.risk.score}</strong>
                <span className={`pill ${urlResult.risk.level}`}>{urlResult.risk.level}</span>
              </div>
              <p className="mono">Host: {urlResult.hostname}</p>
              <p className="mono">Final URL: {urlResult.risk.finalUrl ?? "-"}</p>
              <p className="mono">
                Indicators: {urlResult.risk.suspiciousIndicators.join(" | ") || "None"}
              </p>
              {renderDns(urlResult.dns.records)}
              {renderDnsErrors(urlResult.dns.errors)}
            </>
          ) : null}
        </article>

        <article className="card">
          <h2>QR Analyzer</h2>
          <form onSubmit={handleQrSubmit}>
            <label>
              Upload QR Image
              <input
                type="file"
                accept=".png,.jpg,.jpeg,.webp,.bmp,.gif"
                onChange={(event) => setQrFile(event.target.files?.[0] ?? null)}
                required
              />
            </label>
            <button type="submit" disabled={qrLoading}>
              {qrLoading ? "Scanning..." : "Scan QR"}
            </button>
          </form>
          {qrError ? <div className="error">{qrError}</div> : null}

          {topQrFinding && topQrFinding.type === "url" ? (
            <>
              <div className="score">
                <strong>Score: {topQrFinding.risk.score}</strong>
                <span className={`pill ${topQrFinding.risk.level}`}>{topQrFinding.risk.level}</span>
              </div>
              <p className="mono">Payload URL: {topQrFinding.payload}</p>
              <p className="mono">Final URL: {topQrFinding.risk.finalUrl ?? "-"}</p>
              <p className="mono">
                Indicators: {topQrFinding.risk.suspiciousIndicators.join(" | ") || "None"}
              </p>
              {renderDns(topQrFinding.dns.records)}
              {renderDnsErrors(topQrFinding.dns.errors)}
            </>
          ) : null}
        </article>
      </section>
    </main>
  );
}
