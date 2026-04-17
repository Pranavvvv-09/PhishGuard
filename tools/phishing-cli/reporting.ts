import { writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import type { DomainAnalysisReport, QrScanReport } from "./types";
import { ensureDirectory } from "./utils";

function csvEscape(value: string | number | boolean | undefined): string {
  if (value === undefined) {
    return "";
  }
  const raw = String(value);
  if (raw.includes(",") || raw.includes('"') || raw.includes("\n")) {
    return `"${raw.replaceAll('"', '""')}"`;
  }
  return raw;
}

export async function writeJsonReport(path: string, payload: unknown): Promise<void> {
  await ensureDirectory(dirname(path));
  await writeFile(path, JSON.stringify(payload, null, 2), "utf8");
}

export async function writeDomainCsvReport(path: string, report: DomainAnalysisReport): Promise<void> {
  await ensureDirectory(dirname(path));
  const header = [
    "domain",
    "technique",
    "similarity",
    "levenshtein_distance",
    "registered",
    "risk_score",
    "risk_level",
    "dns_records",
    "ct_hits",
    "ct_issuers",
    "registrar",
    "age_days",
    "threat_feed",
    "website_similarity",
    "vt_malicious",
    "vt_suspicious",
    "vt_harmless",
    "vt_undetected",
    "vt_reputation",
    "indicators",
  ];

  const rows = report.findings.map((entry) =>
    [
      csvEscape(entry.variant.asciiDomain),
      csvEscape(entry.variant.technique),
      csvEscape(entry.variant.similarity),
      csvEscape(entry.variant.levenshteinDistance),
      csvEscape(entry.registration.isRegistered),
      csvEscape(entry.score),
      csvEscape(entry.level),
      csvEscape((entry.registration.dnsRecordTypes ?? []).join("|")),
      csvEscape(entry.registration.certificateTransparencyHits),
      csvEscape((entry.registration.certificateIssuers ?? []).join("|")),
      csvEscape(entry.intelligence.registrar),
      csvEscape(entry.intelligence.registrantAgeDays),
      csvEscape(entry.intelligence.threatFeedMatched),
      csvEscape(entry.intelligence.websiteSimilarity),
      csvEscape(entry.intelligence.virusTotal?.malicious),
      csvEscape(entry.intelligence.virusTotal?.suspicious),
      csvEscape(entry.intelligence.virusTotal?.harmless),
      csvEscape(entry.intelligence.virusTotal?.undetected),
      csvEscape(entry.intelligence.virusTotal?.reputation),
      csvEscape(entry.indicators.join(" | ")),
    ].join(","),
  );

  await writeFile(path, [header.join(","), ...rows].join("\n"), "utf8");
}

export async function writeQrCsvReport(path: string, report: QrScanReport): Promise<void> {
  await ensureDirectory(dirname(path));
  const header = [
    "source",
    "payload_type",
    "decoded_payload",
    "risk_score",
    "risk_level",
    "expanded_url",
    "final_url",
    "threat_feed",
    "vt_malicious",
    "vt_suspicious",
    "vt_harmless",
    "vt_undetected",
    "vt_reputation",
    "indicators",
    "notes",
  ];

  const rows = report.findings.map((entry) =>
    [
      csvEscape(entry.source),
      csvEscape(entry.payloadType),
      csvEscape(entry.decodedPayload),
      csvEscape(entry.analysis?.score),
      csvEscape(entry.analysis?.level),
      csvEscape(entry.analysis?.expandedUrl),
      csvEscape(entry.analysis?.finalUrl),
      csvEscape(entry.analysis?.threatFeedMatched),
      csvEscape(entry.analysis?.virusTotal?.malicious),
      csvEscape(entry.analysis?.virusTotal?.suspicious),
      csvEscape(entry.analysis?.virusTotal?.harmless),
      csvEscape(entry.analysis?.virusTotal?.undetected),
      csvEscape(entry.analysis?.virusTotal?.reputation),
      csvEscape(entry.analysis?.suspiciousIndicators.join(" | ")),
      csvEscape(entry.notes.join(" | ")),
    ].join(","),
  );

  await writeFile(path, [header.join(","), ...rows].join("\n"), "utf8");
}

export async function writeDomainHtmlReport(path: string, report: DomainAnalysisReport): Promise<void> {
  await ensureDirectory(dirname(path));
  const rows = report.findings
    .map(
      (entry) => `
        <tr>
          <td>${entry.variant.asciiDomain}</td>
          <td>${entry.variant.technique}</td>
          <td>${entry.variant.similarity}%</td>
          <td>${entry.variant.levenshteinDistance}</td>
          <td>${entry.registration.isRegistered ? "yes" : "no"}</td>
          <td>${entry.score}</td>
          <td>${entry.level}</td>
          <td>${entry.indicators.join("<br/>")}</td>
        </tr>
      `,
    )
    .join("");

  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Domain Threat Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; background: #f7f7f7; color: #111; }
    h1 { margin-bottom: 8px; }
    .meta { margin-bottom: 16px; color: #444; }
    table { border-collapse: collapse; width: 100%; background: white; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; font-size: 13px; }
    th { background: #f0f0f0; }
    tr:nth-child(even) { background: #fafafa; }
  </style>
</head>
<body>
  <h1>Domain Threat Report</h1>
  <div class="meta">Legitimate domain: <strong>${report.legitimateDomain}</strong><br/>Analyzed: ${
    report.analyzedAt
  }<br/>Generated: ${report.candidatesGenerated} variants; Registered: ${
    report.registeredCandidates
  }</div>
  <table>
    <thead>
      <tr>
        <th>Variant</th>
        <th>Technique</th>
        <th>Similarity</th>
        <th>Levenshtein</th>
        <th>Registered</th>
        <th>Score</th>
        <th>Level</th>
        <th>Indicators</th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>
</body>
</html>`;

  await writeFile(path, html, "utf8");
}

export async function writeQrHtmlReport(path: string, report: QrScanReport): Promise<void> {
  await ensureDirectory(dirname(path));
  const rows = report.findings
    .map(
      (entry) => `
        <tr>
          <td>${entry.source}</td>
          <td>${entry.payloadType}</td>
          <td>${entry.decodedPayload || "-"}</td>
          <td>${entry.analysis?.score ?? "-"}</td>
          <td>${entry.analysis?.level ?? "-"}</td>
          <td>${entry.analysis?.finalUrl ?? "-"}</td>
          <td>${
            entry.analysis?.virusTotal
              ? `${entry.analysis.virusTotal.malicious}/${entry.analysis.virusTotal.suspicious}/${entry.analysis.virusTotal.harmless}/${entry.analysis.virusTotal.undetected}`
              : "-"
          }</td>
          <td>${entry.analysis?.suspiciousIndicators.join("<br/>") ?? "-"}</td>
          <td>${entry.notes.join("<br/>")}</td>
        </tr>
      `,
    )
    .join("");

  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Quishing Scan Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; background: #f7f7f7; color: #111; }
    h1 { margin-bottom: 8px; }
    .meta { margin-bottom: 16px; color: #444; }
    table { border-collapse: collapse; width: 100%; background: white; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; font-size: 13px; }
    th { background: #f0f0f0; }
    tr:nth-child(even) { background: #fafafa; }
  </style>
</head>
<body>
  <h1>Quishing Scan Report</h1>
  <div class="meta">Scanned: ${report.scannedAt}<br/>Inputs: ${report.totalInputs}; Decoded: ${
    report.decodedCount
  }</div>
  <table>
    <thead>
      <tr>
        <th>Source</th>
        <th>Type</th>
        <th>Payload</th>
        <th>Risk Score</th>
        <th>Risk Level</th>
        <th>Final URL</th>
        <th>VT (M/S/H/U)</th>
        <th>Indicators</th>
        <th>Notes</th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>
</body>
</html>`;

  await writeFile(path, html, "utf8");
}
