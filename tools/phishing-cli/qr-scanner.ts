import { access, readFile } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { basename, extname } from "node:path";
import { domainToUnicode } from "node:url";

import {
  HIGH_VALUE_BRANDS,
  PHISHY_URL_KEYWORDS,
  SUSPICIOUS_TLDS,
  URL_SHORTENERS,
} from "./constants";
import type { QrScanFinding, QrScanReport, QuishingUrlAnalysis, VirusTotalReputation } from "./types";
import { isLikelyIpHost, levenshteinDistance, toRiskLevel } from "./utils";

const IMAGE_EXTENSIONS = new Set([".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"]);
const virusTotalRuntimeCache = new Map<string, VirusTotalReputation | null>();

interface VirusTotalDomainResponse {
  data?: {
    attributes?: {
      reputation?: number;
      last_analysis_date?: number;
      last_analysis_stats?: {
        malicious?: number;
        suspicious?: number;
        harmless?: number;
        undetected?: number;
      };
    };
  };
}

function isHttpUrl(value: string): boolean {
  return /^https?:\/\//i.test(value.trim());
}

export function normalizePotentialUrl(value: string): string | undefined {
  const trimmed = value.trim();
  if (!trimmed || /\s/.test(trimmed)) {
    return undefined;
  }

  const candidate = isHttpUrl(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    const parsed = new URL(candidate);
    if (!/^https?:$/i.test(parsed.protocol)) {
      return undefined;
    }
    if (!parsed.hostname || !parsed.hostname.includes(".")) {
      return undefined;
    }
    return parsed.toString();
  } catch {
    return undefined;
  }
}

async function canReadPath(path: string): Promise<boolean> {
  try {
    await access(path, fsConstants.R_OK);
    return true;
  } catch {
    return false;
  }
}

export async function decodeQrFromBuffer(buffer: Buffer, filename = "upload.png"): Promise<string[]> {
  const bytes = new Uint8Array(buffer.byteLength);
  bytes.set(buffer);
  const formData = new FormData();
  formData.append("file", new Blob([bytes]), filename);

  const response = await fetch("https://api.qrserver.com/v1/read-qr-code/", {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    throw new Error(`QR decode failed with status ${response.status}`);
  }

  const parsed = (await response.json()) as Array<{
    symbol: Array<{ data: string | null; error: string | null }>;
  }>;

  return parsed
    .flatMap((item) => item.symbol)
    .map((symbol) => symbol.data ?? "")
    .map((item) => item.trim())
    .filter(Boolean);
}

async function decodeQrFromImagePath(path: string): Promise<string[]> {
  const buffer = await readFile(path);
  return decodeQrFromBuffer(buffer, basename(path));
}

async function expandAndFollowRedirects(urlInput: string): Promise<{
  expandedUrl?: string;
  finalUrl?: string;
  redirectChain: string[];
}> {
  const redirectChain: string[] = [urlInput];
  let current = urlInput;

  for (let i = 0; i < 6; i += 1) {
    try {
      const response = await fetch(current, {
        method: "HEAD",
        redirect: "manual",
        headers: {
          "user-agent": "phishing-cli-research-bot/1.0",
        },
      });

      const location = response.headers.get("location");
      const isRedirect = response.status >= 300 && response.status < 400 && location;
      if (!isRedirect) {
        return {
          expandedUrl: redirectChain.length > 1 ? redirectChain[1] : undefined,
          finalUrl: current,
          redirectChain,
        };
      }

      const resolved = new URL(location, current).toString();
      redirectChain.push(resolved);
      current = resolved;
    } catch {
      return {
        expandedUrl: redirectChain.length > 1 ? redirectChain[1] : undefined,
        finalUrl: current,
        redirectChain,
      };
    }
  }

  return {
    expandedUrl: redirectChain.length > 1 ? redirectChain[1] : undefined,
    finalUrl: current,
    redirectChain,
  };
}

function hasMixedScriptConfusables(hostname: string): boolean {
  const unicode = domainToUnicode(hostname);
  const hasLatin = /[a-z]/i.test(unicode);
  const hasCyrillicOrGreek = /[\u0370-\u03FF\u0400-\u04FF]/.test(unicode);
  return hasLatin && hasCyrillicOrGreek;
}

function normalizeLeetspeak(value: string): string {
  return value
    .toLowerCase()
    .replaceAll("0", "o")
    .replaceAll("1", "l")
    .replaceAll("3", "e")
    .replaceAll("4", "a")
    .replaceAll("5", "s")
    .replaceAll("7", "t")
    .replaceAll("8", "b")
    .replaceAll("9", "g")
    .replace(/[^a-z]/g, "");
}

function hostLabels(hostname: string): string[] {
  return hostname.split(".").filter(Boolean);
}

function hostTokens(hostname: string): string[] {
  return hostLabels(hostname)
    .flatMap((label) => label.split(/[-_]+/))
    .filter(Boolean);
}

function detectBrandImpersonation(hostname: string): { score: number; indicators: string[] } {
  const indicators: string[] = [];
  let score = 0;
  const tokens = hostTokens(hostname);

  const hostKeywordHits = PHISHY_URL_KEYWORDS.filter((keyword) => hostname.includes(keyword));
  if (hostKeywordHits.length > 0) {
    score += Math.min(14, 6 + hostKeywordHits.length * 3);
    indicators.push(`Phishing-related keywords in host: ${hostKeywordHits.join(", ")}`);
  }

  const matches: string[] = [];
  for (const token of tokens) {
    const tokenLower = token.toLowerCase();
    const normalizedToken = normalizeLeetspeak(tokenLower);
    if (normalizedToken.length < 4) {
      continue;
    }

    for (const brand of HIGH_VALUE_BRANDS) {
      if (tokenLower === brand) {
        continue;
      }

      if (normalizedToken === brand) {
        score += 30;
        matches.push(`"${token}" -> ${brand} (leet impersonation)`);
        break;
      }

      const distance = levenshteinDistance(normalizedToken, brand);
      const maxLen = Math.max(normalizedToken.length, brand.length);
      const similarity = 1 - distance / maxLen;
      if (distance > 0 && (distance <= 2 || similarity >= 0.78)) {
        score += 18;
        matches.push(`"${token}" ~ ${brand} (distance ${distance})`);
        break;
      }
    }
  }

  if (matches.length > 0) {
    indicators.push(`Brand impersonation signal: ${matches.join("; ")}`);
  }

  const labelCount = hostLabels(hostname).length;
  if (labelCount >= 4) {
    score += 8;
    indicators.push(`Deep subdomain chain (${labelCount} labels)`);
  }

  return { score: Math.min(45, score), indicators };
}

async function fetchVirusTotalReputation(hostname: string): Promise<VirusTotalReputation | undefined> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY?.trim();
  if (!apiKey) {
    return undefined;
  }

  const cached = virusTotalRuntimeCache.get(hostname);
  if (cached !== undefined) {
    return cached ?? undefined;
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8_000);
    const response = await fetch(
      `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(hostname)}`,
      {
        signal: controller.signal,
        headers: {
          "x-apikey": apiKey,
        },
      },
    );
    clearTimeout(timeout);

    if (!response.ok) {
      virusTotalRuntimeCache.set(hostname, null);
      return undefined;
    }

    const payload = (await response.json()) as VirusTotalDomainResponse;
    const stats = payload.data?.attributes?.last_analysis_stats;
    if (!stats) {
      virusTotalRuntimeCache.set(hostname, null);
      return undefined;
    }

    const result: VirusTotalReputation = {
      source: "virustotal",
      malicious: stats.malicious ?? 0,
      suspicious: stats.suspicious ?? 0,
      harmless: stats.harmless ?? 0,
      undetected: stats.undetected ?? 0,
      reputation: payload.data?.attributes?.reputation,
      lastAnalysisDate: payload.data?.attributes?.last_analysis_date
        ? new Date(payload.data.attributes.last_analysis_date * 1_000).toISOString()
        : undefined,
    };
    virusTotalRuntimeCache.set(hostname, result);
    return result;
  } catch {
    virusTotalRuntimeCache.set(hostname, null);
    return undefined;
  }
}

export async function analyzeQrUrl(urlInput: string): Promise<QuishingUrlAnalysis> {
  const suspiciousIndicators: string[] = [];
  let score = 0;
  let threatFeedMatched = false;

  const redirects = await expandAndFollowRedirects(urlInput);
  const finalUrl = redirects.finalUrl ?? urlInput;
  const parsedFinal = new URL(finalUrl);
  const finalHost = parsedFinal.hostname.toLowerCase();

  if (parsedFinal.protocol === "http:") {
    score += 12;
    suspiciousIndicators.push("Uses HTTP instead of HTTPS");
  }

  if (URL_SHORTENERS.has(new URL(urlInput).hostname.toLowerCase())) {
    score += 20;
    suspiciousIndicators.push("URL shortener used in QR payload");
  }

  if (redirects.redirectChain.length >= 3) {
    score += 18;
    suspiciousIndicators.push(`Long redirect chain (${redirects.redirectChain.length} hops)`);
  }

  if (finalHost.startsWith("xn--") || hasMixedScriptConfusables(finalHost)) {
    score += 30;
    suspiciousIndicators.push("Potential IDN homograph / mixed-script domain");
  }

  const brandSignals = detectBrandImpersonation(finalHost);
  if (brandSignals.score > 0) {
    score += brandSignals.score;
    suspiciousIndicators.push(...brandSignals.indicators);
  }

  if (isLikelyIpHost(finalHost)) {
    score += 24;
    suspiciousIndicators.push("Destination uses raw IP address");
  }

  const tld = finalHost.split(".").pop() ?? "";
  if (SUSPICIOUS_TLDS.has(tld)) {
    score += 10;
    suspiciousIndicators.push(`Suspicious TLD \".${tld}\"`);
  }

  if (finalUrl.length > 120) {
    score += 8;
    suspiciousIndicators.push("Unusually long URL");
  }

  if (finalUrl.includes("@")) {
    score += 12;
    suspiciousIndicators.push("Contains @ symbol (possible URL obfuscation)");
  }

  const lowerPath = `${parsedFinal.pathname}${parsedFinal.search}`.toLowerCase();
  const keywordHits = PHISHY_URL_KEYWORDS.filter((keyword) => lowerPath.includes(keyword));
  if (keywordHits.length > 0) {
    score += Math.min(20, keywordHits.length * 6);
    suspiciousIndicators.push(`Phishing-related keywords in path/query: ${keywordHits.join(", ")}`);
  }

  const openPhishUrl = process.env.OPENPHISH_FEED_URL;
  if (openPhishUrl) {
    try {
      const response = await fetch(openPhishUrl);
      if (response.ok) {
        const feed = await response.text();
        const hit = feed
          .split(/\r?\n/)
          .some((line) => line.toLowerCase().includes(finalHost));
        if (hit) {
          threatFeedMatched = true;
          score += 28;
          suspiciousIndicators.push("Destination matched threat feed entry");
        }
      }
    } catch {
      // Threat feed is optional.
    }
  }

  const virusTotal = await fetchVirusTotalReputation(finalHost);
  if (virusTotal) {
    if (virusTotal.malicious > 0) {
      score += Math.min(30, 16 + virusTotal.malicious * 2);
      suspiciousIndicators.push(`VirusTotal malicious detections: ${virusTotal.malicious}`);
    }
    if (virusTotal.suspicious > 0) {
      score += Math.min(16, 8 + virusTotal.suspicious * 2);
      suspiciousIndicators.push(`VirusTotal suspicious detections: ${virusTotal.suspicious}`);
    }
    if (virusTotal.malicious === 0 && virusTotal.suspicious === 0) {
      suspiciousIndicators.push("VirusTotal: no malicious/suspicious detections");
    }
  }

  score = Math.min(100, score);

  return {
    originalUrl: urlInput,
    expandedUrl: redirects.expandedUrl,
    finalUrl,
    redirectChain: redirects.redirectChain,
    suspiciousIndicators,
    threatFeedMatched,
    virusTotal,
    score,
    level: toRiskLevel(score),
  };
}

export async function scanQrInputs(inputs: string[]): Promise<QrScanReport> {
  const findings: QrScanFinding[] = [];

  for (const input of inputs) {
    const trimmed = input.trim();
    if (!trimmed) {
      findings.push({
        source: input,
        decodedPayload: "",
        payloadType: "empty",
        notes: ["Input was empty."],
      });
      continue;
    }

    const ext = extname(trimmed).toLowerCase();
    const looksLikeImagePath = IMAGE_EXTENSIONS.has(ext) && (await canReadPath(trimmed));
    if (looksLikeImagePath) {
      try {
        const payloads = await decodeQrFromImagePath(trimmed);
        if (payloads.length === 0) {
          findings.push({
            source: trimmed,
            decodedPayload: "",
            payloadType: "empty",
            notes: ["No QR payload could be decoded."],
          });
          continue;
        }

        for (const payload of payloads) {
          const normalizedPayloadUrl = normalizePotentialUrl(payload);
          if (normalizedPayloadUrl) {
            const analysis = await analyzeQrUrl(normalizedPayloadUrl);
            findings.push({
              source: trimmed,
              decodedPayload: normalizedPayloadUrl,
              payloadType: "url",
              analysis,
              notes: ["Decoded from image using QR server API."],
            });
          } else {
            findings.push({
              source: trimmed,
              decodedPayload: payload,
              payloadType: "text",
              notes: ["Decoded QR payload is non-URL text."],
            });
          }
        }
      } catch (error) {
        findings.push({
          source: trimmed,
          decodedPayload: "",
          payloadType: "empty",
          notes: [`Failed to decode QR image: ${error instanceof Error ? error.message : "unknown error"}`],
        });
      }
      continue;
    }

    const normalizedDirectUrl = normalizePotentialUrl(trimmed);
    if (normalizedDirectUrl) {
      const analysis = await analyzeQrUrl(normalizedDirectUrl);
      findings.push({
        source: normalizedDirectUrl,
        decodedPayload: normalizedDirectUrl,
        payloadType: "url",
        analysis,
        notes: ["Input treated as URL payload."],
      });
      continue;
    }

    findings.push({
      source: trimmed,
      decodedPayload: trimmed,
      payloadType: "text",
      notes: ["Input treated as plain text payload."],
    });
  }

  return {
    scannedAt: new Date().toISOString(),
    totalInputs: inputs.length,
    decodedCount: findings.filter((entry) => entry.payloadType !== "empty").length,
    findings,
  };
}
