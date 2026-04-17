import { resolve } from "node:dns/promises";
import { Socket } from "node:net";
import { join } from "node:path";

import { VARIANT_TECHNIQUE_WEIGHTS } from "./constants";
import { ToolCache } from "./cache";
import type {
  DomainAnalysisOptions,
  DomainAnalysisReport,
  DomainFinding,
  DomainIntelligence,
  DomainVariant,
  RegistrationCheck,
  VirusTotalReputation,
  WhoisInfo,
} from "./types";
import { daysBetween, parseDate, parseDomainParts, runWithConcurrency, toRiskLevel } from "./utils";

const CACHE_PATH = join(process.cwd(), ".cache", "phishing-cli-cache.json");
const THREAT_FEED_TTL_MS = 6 * 60 * 60 * 1_000;
const VIRUSTOTAL_CACHE_TTL_MS = 12 * 60 * 60 * 1_000;

const DEFAULT_WHOIS_SERVERS: Record<string, string> = {
  com: "whois.verisign-grs.com",
  net: "whois.verisign-grs.com",
  org: "whois.pir.org",
  io: "whois.nic.io",
  ai: "whois.nic.ai",
  in: "whois.registry.in",
  co: "whois.nic.co",
  app: "whois.nic.google",
  dev: "whois.nic.google",
  xyz: "whois.nic.xyz",
};

interface CertificateTransparencyEntry {
  issuer_name?: string;
}

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

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolvePromise, rejectPromise) => {
    const timeout = setTimeout(() => rejectPromise(new Error("timeout")), timeoutMs);
    promise
      .then((result) => {
        clearTimeout(timeout);
        resolvePromise(result);
      })
      .catch((error) => {
        clearTimeout(timeout);
        rejectPromise(error);
      });
  });
}

async function queryWhoisServer(
  server: string,
  query: string,
  timeoutMs: number,
): Promise<string> {
  return withTimeout(
    new Promise<string>((resolvePromise, rejectPromise) => {
      const socket = new Socket();
      let data = "";

      socket.setTimeout(timeoutMs);
      socket.connect(43, server, () => {
        socket.write(`${query}\r\n`);
      });

      socket.on("data", (chunk) => {
        data += chunk.toString();
      });

      socket.on("end", () => {
        resolvePromise(data);
      });

      socket.on("timeout", () => {
        socket.destroy();
        rejectPromise(new Error(`WHOIS timeout for ${server}`));
      });

      socket.on("error", (error) => {
        socket.destroy();
        rejectPromise(error);
      });
    }),
    timeoutMs + 1_500,
  );
}

function parseWhoisDate(raw: string): string | undefined {
  const match = raw.match(
    /(creation date|created on|registered on|domain registration date|created):\s*(.+)$/im,
  );
  return match?.[2]?.trim();
}

function parseWhois(raw: string): WhoisInfo {
  const lower = raw.toLowerCase();
  const noMatchPatterns = [
    "no match for",
    "not found",
    "status: free",
    "domain not found",
    "no data found",
    "available for registration",
  ];
  const registered = !noMatchPatterns.some((pattern) => lower.includes(pattern));

  const registrar = raw.match(/registrar:\s*(.+)$/im)?.[1]?.trim();
  const createdDate = parseWhoisDate(raw);
  const updatedDate = raw.match(/updated date:\s*(.+)$/im)?.[1]?.trim();
  const expiryDate = raw.match(/(registry expiry date|expiration date|paid-till):\s*(.+)$/im)?.[2]?.trim();
  const nameServers = [...raw.matchAll(/name server:\s*(.+)$/gim)].map((entry) =>
    entry[1].trim().toLowerCase(),
  );
  const statusLines = [...raw.matchAll(/status:\s*(.+)$/gim)].map((entry) => entry[1].trim());

  return {
    raw,
    registered,
    registrar,
    createdDate,
    updatedDate,
    expiryDate,
    nameServers,
    statusLines,
  };
}

async function discoverWhoisServer(tld: string): Promise<string | undefined> {
  const known = DEFAULT_WHOIS_SERVERS[tld];
  if (known) {
    return known;
  }

  try {
    const ianaResponse = await queryWhoisServer("whois.iana.org", tld, 4_000);
    const whoisLine = ianaResponse.match(/^whois:\s*(.+)$/im)?.[1]?.trim();
    if (whoisLine) {
      DEFAULT_WHOIS_SERVERS[tld] = whoisLine;
      return whoisLine;
    }
  } catch {
    return undefined;
  }

  return undefined;
}

async function fetchWhois(domain: string): Promise<WhoisInfo | undefined> {
  const tld = domain.split(".").pop();
  if (!tld) {
    return undefined;
  }

  const server = await discoverWhoisServer(tld);
  if (!server) {
    return undefined;
  }

  try {
    const raw = await queryWhoisServer(server, domain, 6_000);
    const parsed = parseWhois(raw);
    parsed.whoisServer = server;
    return parsed;
  } catch {
    return undefined;
  }
}

async function resolveDnsRecordTypes(hostname: string): Promise<{ hits: string[]; errors: string[] }> {
  const rrTypes = ["A", "AAAA", "NS", "MX", "CNAME"] as const;
  const hits: string[] = [];
  const errors: string[] = [];

  for (const rrType of rrTypes) {
    try {
      const result = await withTimeout(resolve(hostname, rrType), 3_500);
      if (Array.isArray(result) && result.length > 0) {
        hits.push(rrType);
      }
    } catch (error) {
      if (error instanceof Error) {
        errors.push(`${rrType}:${error.message}`);
      } else {
        errors.push(`${rrType}:unknown_error`);
      }
    }
  }

  return { hits, errors };
}

async function fetchCertificateTransparency(domain: string): Promise<CertificateTransparencyEntry[]> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5_000);
    const response = await fetch(
      `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`,
      { signal: controller.signal },
    );
    clearTimeout(timeout);

    if (!response.ok) {
      return [];
    }

    const text = await response.text();
    if (!text.trim()) {
      return [];
    }

    try {
      const parsed = JSON.parse(text) as CertificateTransparencyEntry[];
      return parsed;
    } catch {
      return [];
    }
  } catch {
    return [];
  }
}

function tokenizeHtmlText(raw: string): Set<string> {
  const plain = raw
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/[^a-z0-9\s]/gi, " ")
    .toLowerCase();

  const tokens = plain
    .split(/\s+/)
    .filter((token) => token.length > 2)
    .slice(0, 1_200);
  return new Set(tokens);
}

function jaccardSimilarity(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 || b.size === 0) {
    return 0;
  }

  let intersection = 0;
  for (const token of a) {
    if (b.has(token)) {
      intersection += 1;
    }
  }
  const union = a.size + b.size - intersection;
  if (union === 0) {
    return 0;
  }
  return Number(((intersection / union) * 100).toFixed(2));
}

async function fetchSiteText(domain: string): Promise<Set<string> | undefined> {
  const urls = [`https://${domain}`, `http://${domain}`];
  for (const url of urls) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5_000);
      const response = await fetch(url, {
        signal: controller.signal,
        redirect: "follow",
        headers: {
          "user-agent": "phishing-cli-research-bot/1.0",
        },
      });
      clearTimeout(timeout);
      if (!response.ok) {
        continue;
      }
      const html = await response.text();
      return tokenizeHtmlText(html);
    } catch {
      continue;
    }
  }
  return undefined;
}

async function loadThreatFeedHosts(
  cache: ToolCache,
  enabled: boolean,
): Promise<Set<string>> {
  if (!enabled) {
    return new Set<string>();
  }

  const cached = cache.getThreatHosts(THREAT_FEED_TTL_MS);
  if (cached) {
    return new Set(cached);
  }

  const openPhishUrl = process.env.OPENPHISH_FEED_URL ?? "https://openphish.com/feed.txt";
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8_000);
    const response = await fetch(openPhishUrl, { signal: controller.signal });
    clearTimeout(timeout);
    if (!response.ok) {
      return new Set<string>();
    }
    const text = await response.text();
    const hosts = text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .slice(0, 200_000)
      .map((line) => {
        try {
          return new URL(line).hostname.toLowerCase();
        } catch {
          return "";
        }
      })
      .filter(Boolean);

    const deduped = [...new Set(hosts)];
    cache.setThreatHosts(deduped);
    return new Set(deduped);
  } catch {
    return new Set<string>();
  }
}

function isThreatMatched(hostname: string, feedHosts: Set<string>): boolean {
  if (feedHosts.size === 0) {
    return false;
  }
  if (feedHosts.has(hostname)) {
    return true;
  }
  const labels = hostname.split(".");
  for (let i = 1; i < labels.length - 1; i += 1) {
    const candidate = labels.slice(i).join(".");
    if (feedHosts.has(candidate)) {
      return true;
    }
  }
  return false;
}

async function fetchVirusTotalReputation(
  hostname: string,
  cache: ToolCache,
  enabled: boolean,
): Promise<VirusTotalReputation | undefined> {
  if (!enabled) {
    return undefined;
  }

  const apiKey = process.env.VIRUSTOTAL_API_KEY?.trim();
  if (!apiKey) {
    return undefined;
  }

  const cached = cache.getVirusTotal(hostname, VIRUSTOTAL_CACHE_TTL_MS);
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
      cache.setVirusTotal(hostname, null);
      return undefined;
    }

    const payload = (await response.json()) as VirusTotalDomainResponse;
    const stats = payload.data?.attributes?.last_analysis_stats;
    if (!stats) {
      cache.setVirusTotal(hostname, null);
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

    cache.setVirusTotal(hostname, result);
    return result;
  } catch {
    cache.setVirusTotal(hostname, null);
    return undefined;
  }
}

function scoreFinding(
  variant: DomainVariant,
  registration: RegistrationCheck,
  intelligence: DomainIntelligence,
): { score: number; indicators: string[] } {
  let score = 0;
  const indicators: string[] = [];

  const techniqueWeight = VARIANT_TECHNIQUE_WEIGHTS[variant.technique] ?? 10;
  score += techniqueWeight;
  indicators.push(`Technique: ${variant.technique}`);

  score += Math.round((variant.similarity / 100) * 35);
  indicators.push(`Visual similarity ${variant.similarity}%`);
  indicators.push(`Levenshtein distance ${variant.levenshteinDistance}`);

  if (registration.isRegistered) {
    score += 18;
    indicators.push("Domain appears registered (DNS/WHOIS/CT)");
  }

  if (registration.certificateTransparencyHits > 0) {
    score += 8;
    indicators.push(`Certificate transparency entries: ${registration.certificateTransparencyHits}`);
  }

  if (intelligence.registrantAgeDays !== undefined) {
    if (intelligence.registrantAgeDays < 30) {
      score += 20;
      indicators.push(`Recently registered (${intelligence.registrantAgeDays} days old)`);
    } else if (intelligence.registrantAgeDays < 180) {
      score += 10;
      indicators.push(`Relatively new domain (${intelligence.registrantAgeDays} days old)`);
    }
  }

  if (intelligence.websiteSimilarity !== undefined) {
    if (intelligence.websiteSimilarity > 55) {
      score += 18;
      indicators.push(`Website content similarity ${intelligence.websiteSimilarity}%`);
    } else if (intelligence.websiteSimilarity > 30) {
      score += 9;
      indicators.push(`Moderate website similarity ${intelligence.websiteSimilarity}%`);
    }
  }

  if (intelligence.threatFeedMatched) {
    score += 25;
    indicators.push("Host appears in phishing threat feed");
  }

  const vt = intelligence.virusTotal;
  if (vt) {
    if (vt.malicious > 0) {
      score += Math.min(35, 20 + vt.malicious * 2);
      indicators.push(`VirusTotal malicious detections: ${vt.malicious}`);
    }
    if (vt.suspicious > 0) {
      score += Math.min(18, 8 + vt.suspicious * 2);
      indicators.push(`VirusTotal suspicious detections: ${vt.suspicious}`);
    }
    if (vt.malicious === 0 && vt.suspicious === 0) {
      indicators.push("VirusTotal: no malicious/suspicious detections");
    }
  }

  return { score: Math.min(100, score), indicators };
}

async function computeRegistration(
  variant: DomainVariant,
  cache: ToolCache,
  cacheTtlMs: number,
): Promise<RegistrationCheck> {
  const cached = cache.getRegistration(variant.asciiDomain, cacheTtlMs);
  if (cached) {
    return cached;
  }

  const [dnsSignals, ctSignals] = await Promise.all([
    resolveDnsRecordTypes(variant.asciiDomain),
    fetchCertificateTransparency(variant.asciiDomain),
  ]);

  let whois: WhoisInfo | undefined;
  if (dnsSignals.hits.length > 0 || ctSignals.length > 0 || variant.similarity >= 65) {
    whois = await fetchWhois(variant.asciiDomain);
  }

  const registration: RegistrationCheck = {
    isRegistered:
      dnsSignals.hits.length > 0 ||
      ctSignals.length > 0 ||
      Boolean(whois?.registered),
    dnsRecordTypes: dnsSignals.hits,
    dnsErrors: dnsSignals.errors,
    whois,
    certificateTransparencyHits: ctSignals.length,
    certificateIssuers: [...new Set(ctSignals.map((entry) => entry.issuer_name ?? "").filter(Boolean))].slice(
      0,
      5,
    ),
  };

  cache.setRegistration(variant.asciiDomain, registration);
  return registration;
}

export async function analyzeDomainVariants(
  legitimateDomainInput: string,
  variants: DomainVariant[],
  options: DomainAnalysisOptions = {},
): Promise<DomainAnalysisReport> {
  const parts = parseDomainParts(legitimateDomainInput);
  const registeredOnly = options.registeredOnly ?? true;
  const includeThreatFeeds = options.includeThreatFeeds ?? true;
  const includeContentSimilarity = options.includeContentSimilarity ?? true;
  const includeVirusTotal = options.includeVirusTotal ?? true;
  const concurrency = Math.max(1, options.concurrency ?? 10);
  const delayMs = Math.max(0, options.delayMs ?? 40);
  const cacheTtlMs = options.cacheTtlMs ?? 24 * 60 * 60 * 1_000;

  const cache = new ToolCache(CACHE_PATH);
  await cache.init();
  const threatHosts = await loadThreatFeedHosts(cache, includeThreatFeeds);

  const legitTextTokens = includeContentSimilarity
    ? await fetchSiteText(parts.registrableDomain)
    : undefined;

  const findings = await runWithConcurrency(
    variants,
    async (variant): Promise<DomainFinding> => {
      const registration = await computeRegistration(variant, cache, cacheTtlMs);
      const threatFeedMatched = isThreatMatched(variant.asciiDomain, threatHosts);

      let websiteSimilarity: number | undefined;
      if (
        includeContentSimilarity &&
        legitTextTokens &&
        registration.isRegistered
      ) {
        const candidateTokens = await fetchSiteText(variant.asciiDomain);
        if (candidateTokens) {
          websiteSimilarity = jaccardSimilarity(legitTextTokens, candidateTokens);
        }
      }

      const createdDate = parseDate(registration.whois?.createdDate);
      const registrantAgeDays = createdDate ? daysBetween(createdDate) : undefined;
      const virusTotal =
        registration.isRegistered && includeVirusTotal
          ? await fetchVirusTotalReputation(variant.asciiDomain, cache, includeVirusTotal)
          : undefined;

      const intelligence: DomainIntelligence = {
        host: variant.asciiDomain,
        threatFeedMatched,
        websiteSimilarity,
        registrantAgeDays,
        registrar: registration.whois?.registrar,
        certIssuerSamples: registration.certificateIssuers,
        virusTotal,
      };

      const scored = scoreFinding(variant, registration, intelligence);
      return {
        variant,
        registration,
        intelligence,
        score: scored.score,
        level: toRiskLevel(scored.score),
        indicators: scored.indicators,
      };
    },
    concurrency,
    delayMs,
  );

  await cache.persist();

  const filtered = registeredOnly ? findings.filter((entry) => entry.registration.isRegistered) : findings;
  filtered.sort((a, b) => b.score - a.score);

  return {
    legitimateDomain: parts.registrableDomain,
    analyzedAt: new Date().toISOString(),
    candidatesGenerated: variants.length,
    candidatesEvaluated: findings.length,
    registeredCandidates: findings.filter((entry) => entry.registration.isRegistered).length,
    findings: filtered,
  };
}
