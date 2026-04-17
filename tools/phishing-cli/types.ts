export type VariantTechnique =
  | "omission"
  | "repetition"
  | "character_swap"
  | "keyboard_adjacency"
  | "tld_swap"
  | "hyphenation";

export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface DomainParts {
  sourceInput: string;
  hostname: string;
  registrableDomain: string;
  baseLabel: string;
  tld: string;
  prefixLabels: string[];
}

export interface DomainVariant {
  sourceDomain: string;
  displayDomain: string;
  asciiDomain: string;
  technique: VariantTechnique;
  mutation: string;
  similarity: number;
  levenshteinDistance: number;
  normalizedSource: string;
  normalizedCandidate: string;
}

export interface WhoisInfo {
  raw?: string;
  registered: boolean;
  registrar?: string;
  createdDate?: string;
  updatedDate?: string;
  expiryDate?: string;
  nameServers: string[];
  statusLines: string[];
  whoisServer?: string;
}

export interface RegistrationCheck {
  isRegistered: boolean;
  dnsRecordTypes: string[];
  dnsErrors: string[];
  whois?: WhoisInfo;
  certificateTransparencyHits: number;
  certificateIssuers: string[];
}

export interface DomainIntelligence {
  host: string;
  threatFeedMatched: boolean;
  websiteSimilarity?: number;
  registrantAgeDays?: number;
  registrar?: string;
  certIssuerSamples: string[];
  virusTotal?: VirusTotalReputation;
}

export interface VirusTotalReputation {
  source: "virustotal";
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  reputation?: number;
  lastAnalysisDate?: string;
}

export interface DomainFinding {
  variant: DomainVariant;
  registration: RegistrationCheck;
  intelligence: DomainIntelligence;
  score: number;
  level: RiskLevel;
  indicators: string[];
}

export interface DomainAnalysisReport {
  legitimateDomain: string;
  analyzedAt: string;
  candidatesGenerated: number;
  candidatesEvaluated: number;
  registeredCandidates: number;
  findings: DomainFinding[];
}

export interface DomainAnalysisOptions {
  maxVariants?: number;
  includeThreatFeeds?: boolean;
  includeContentSimilarity?: boolean;
  includeVirusTotal?: boolean;
  concurrency?: number;
  delayMs?: number;
  cacheTtlMs?: number;
  registeredOnly?: boolean;
}

export interface QuishingUrlAnalysis {
  originalUrl: string;
  expandedUrl?: string;
  finalUrl?: string;
  redirectChain: string[];
  suspiciousIndicators: string[];
  threatFeedMatched: boolean;
  virusTotal?: VirusTotalReputation;
  score: number;
  level: RiskLevel;
}

export interface QrScanFinding {
  source: string;
  decodedPayload: string;
  payloadType: "url" | "text" | "empty";
  analysis?: QuishingUrlAnalysis;
  notes: string[];
}

export interface QrScanReport {
  scannedAt: string;
  totalInputs: number;
  decodedCount: number;
  findings: QrScanFinding[];
}
