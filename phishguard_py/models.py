from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

RiskLevel = Literal["low", "medium", "high", "critical"]
VariantTechnique = Literal[
    "omission",
    "repetition",
    "character_swap",
    "keyboard_adjacency",
    "tld_swap",
    "hyphenation",
]


class DomainParts(BaseModel):
    sourceInput: str
    hostname: str
    registrableDomain: str
    baseLabel: str
    tld: str
    prefixLabels: List[str] = Field(default_factory=list)


class DomainVariant(BaseModel):
    sourceDomain: str
    displayDomain: str
    asciiDomain: str
    technique: VariantTechnique
    mutation: str
    similarity: float
    levenshteinDistance: int
    normalizedSource: str
    normalizedCandidate: str


class WhoisInfo(BaseModel):
    registered: bool = False
    registrar: Optional[str] = None
    createdDate: Optional[str] = None
    updatedDate: Optional[str] = None
    expiryDate: Optional[str] = None
    whoisServer: Optional[str] = None
    nameServers: List[str] = Field(default_factory=list)
    source: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


class RegistrationCheck(BaseModel):
    isRegistered: bool
    dnsRecordTypes: List[str] = Field(default_factory=list)
    dnsErrors: List[str] = Field(default_factory=list)
    certificateTransparencyHits: int = 0
    certificateIssuers: List[str] = Field(default_factory=list)
    dnsRecords: Dict[str, List[str]] = Field(default_factory=dict)
    whois: Optional[WhoisInfo] = None


class VirusTotalReputation(BaseModel):
    source: Literal["virustotal"] = "virustotal"
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: Optional[int] = None
    lastAnalysisDate: Optional[str] = None


class DomainIntelligence(BaseModel):
    host: str
    threatFeedMatched: bool = False
    websiteSimilarity: Optional[float] = None
    suspiciousKeywords: List[str] = Field(default_factory=list)
    brandImpersonationSignal: Optional[str] = None
    registrantAgeDays: Optional[int] = None
    registrationDate: Optional[str] = None
    updatedDate: Optional[str] = None
    expiryDate: Optional[str] = None
    recentRegistrationWindow: Optional[
        Literal["very_new_0_14d", "new_15_30d", "young_31_180d", "mature_180d_plus"]
    ] = None
    registrar: Optional[str] = None
    hostingProvider: Optional[str] = None
    networkProvider: Optional[str] = None
    resolvedIps: List[str] = Field(default_factory=list)
    nameServers: List[str] = Field(default_factory=list)
    whoisServer: Optional[str] = None
    certIssuerSamples: List[str] = Field(default_factory=list)
    virusTotal: Optional[VirusTotalReputation] = None


class DomainFinding(BaseModel):
    variant: DomainVariant
    registration: RegistrationCheck
    intelligence: DomainIntelligence
    score: int
    level: RiskLevel
    indicators: List[str] = Field(default_factory=list)


class DomainAnalysisReport(BaseModel):
    legitimateDomain: str
    analyzedAt: str
    candidatesGenerated: int
    candidatesEvaluated: int
    registeredCandidates: int
    findings: List[DomainFinding] = Field(default_factory=list)


class UrlAnalysisReport(BaseModel):
    inputUrl: str
    normalizedUrl: str
    finalUrl: str
    hostname: str
    score: int
    level: RiskLevel
    verdict: str
    reasons: List[str] = Field(default_factory=list)
    indicators: List[str] = Field(default_factory=list)
    redirectHops: int = 0
    isHttps: bool = True
    isIpHost: bool = False
    dnsRecordTypes: List[str] = Field(default_factory=list)
    dnsErrors: List[str] = Field(default_factory=list)
    dnsRecords: Dict[str, List[str]] = Field(default_factory=dict)
    whois: Optional[WhoisInfo] = None
    virusTotal: Optional[VirusTotalReputation] = None
    domainAgeDays: Optional[int] = None
    whitelistMatched: bool = False
    scoreBreakdown: List[str] = Field(default_factory=list)
    ruleOverrides: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
