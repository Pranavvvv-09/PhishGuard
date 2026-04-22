from __future__ import annotations

from typing import Any, Dict, List, Tuple

from .models import DomainIntelligence, DomainVariant, RegistrationCheck
from .utils import to_risk_level

VARIANT_TECHNIQUE_WEIGHTS: Dict[str, int] = {
    "omission": 18,
    "repetition": 14,
    "character_swap": 15,
    "keyboard_adjacency": 16,
    "tld_swap": 12,
    "hyphenation": 13,
}


def score_domain_finding(
    variant: DomainVariant,
    registration: RegistrationCheck,
    intelligence: DomainIntelligence,
) -> Tuple[int, List[str]]:
    score = 0
    indicators: List[str] = []

    score += VARIANT_TECHNIQUE_WEIGHTS.get(variant.technique, 10)
    indicators.append(f"Technique: {variant.technique}")

    score += round((variant.similarity / 100) * 35)
    indicators.append(f"Visual similarity {variant.similarity}%")
    indicators.append(f"Levenshtein distance {variant.levenshteinDistance}")

    if intelligence.suspiciousKeywords:
        score += min(16, 6 + len(intelligence.suspiciousKeywords) * 3)
        indicators.append(f"Suspicious domain keywords: {', '.join(intelligence.suspiciousKeywords)}")

    if intelligence.brandImpersonationSignal:
        score += 18
        indicators.append(f"Brand impersonation signal: {intelligence.brandImpersonationSignal}")

    if registration.isRegistered:
        score += 18
        indicators.append("Domain appears registered (DNS/RDAP)")

    if intelligence.registrationDate:
        indicators.append(f"Registered at: {intelligence.registrationDate}")
    if intelligence.updatedDate:
        indicators.append(f"Last updated: {intelligence.updatedDate}")
    if intelligence.expiryDate:
        indicators.append(f"Expires at: {intelligence.expiryDate}")

    if intelligence.registrantAgeDays is not None:
        if intelligence.recentRegistrationWindow == "very_new_0_14d":
            score += 28
            indicators.append(f"Very new domain ({intelligence.registrantAgeDays} days old)")
        elif intelligence.recentRegistrationWindow == "new_15_30d":
            score += 20
            indicators.append(f"Recently registered ({intelligence.registrantAgeDays} days old)")
        elif intelligence.recentRegistrationWindow == "young_31_180d":
            score += 10
            indicators.append(f"Relatively new domain ({intelligence.registrantAgeDays} days old)")
        else:
            indicators.append(f"Domain age: {intelligence.registrantAgeDays} days")

    if intelligence.threatFeedMatched:
        score += 25
        indicators.append("Host appears in threat feed")

    if intelligence.hostingProvider:
        indicators.append(f"DNS/hosting provider: {intelligence.hostingProvider}")
    if intelligence.networkProvider:
        indicators.append(f"Network provider: {intelligence.networkProvider}")
    if intelligence.registrar:
        indicators.append(f"Registrar: {intelligence.registrar}")

    vt = intelligence.virusTotal
    if vt:
        if vt.malicious > 0:
            score += min(35, 20 + vt.malicious * 2)
            indicators.append(f"VirusTotal malicious detections: {vt.malicious}")
        if vt.suspicious > 0:
            score += min(18, 8 + vt.suspicious * 2)
            indicators.append(f"VirusTotal suspicious detections: {vt.suspicious}")
        if vt.malicious == 0 and vt.suspicious == 0:
            indicators.append("VirusTotal: no malicious/suspicious detections")

    return min(100, score), indicators


def score_url_signals(signals: Dict[str, Any]) -> Tuple[int, List[str], List[str], List[str], List[str]]:
    score = 0
    indicators: List[str] = []
    reasons: List[str] = []
    breakdown: List[str] = []
    overrides: List[str] = []

    def add(points: int, label: str) -> None:
        nonlocal score
        if points == 0:
            return
        score += points
        sign = "+" if points > 0 else ""
        breakdown.append(f"{label} {sign}{points}")

    if signals.get("is_http"):
        add(10, "HTTP instead of HTTPS")
        indicators.append("Uses HTTP instead of HTTPS")
        reasons.append("URL is not using HTTPS")

    if signals.get("ip_host"):
        add(25, "IP-based host")
        indicators.append("Uses raw IP address as host")
        reasons.append("IP-based URLs are often used to hide malicious hosts")

    if signals.get("shortener_used"):
        add(16, "URL shortener")
        indicators.append("Shortened URL detected")
        reasons.append("Shorteners can hide the real destination")

    redirect_hops = int(signals.get("redirect_hops", 0))
    if redirect_hops >= 3:
        add(14, "Long redirect chain")
        indicators.append(f"Long redirect chain ({redirect_hops} hops)")
        reasons.append("Multiple redirects can be used for obfuscation")
    elif redirect_hops == 2:
        add(6, "Two redirects detected")

    if signals.get("mixed_script"):
        add(24, "Mixed-script host")
        indicators.append("Mixed script / IDN homograph pattern")
        reasons.append("Host contains visually deceptive characters")

    if signals.get("suspicious_tld"):
        add(10, "Suspicious TLD")
        indicators.append(f'Suspicious TLD ".{signals["suspicious_tld"]}"')

    url_length = int(signals.get("url_length", 0))
    if url_length >= 140:
        add(10, "Very long URL")
        indicators.append("Unusually long URL")
    elif url_length >= 100:
        add(5, "Long URL")

    if signals.get("has_at_symbol"):
        add(10, "@ symbol in URL")
        indicators.append("Contains @ symbol (possible obfuscation)")

    subdomain_count = int(signals.get("subdomain_count", 0))
    if subdomain_count >= 3:
        add(8, "Too many subdomains")
        indicators.append(f"Excessive subdomains ({subdomain_count})")

    if signals.get("uncommon_port"):
        add(8, "Uncommon URL port")
        indicators.append("Uses uncommon network port")

    query_count = int(signals.get("query_param_count", 0))
    if query_count >= 5:
        add(8, "Many query parameters")
        indicators.append(f"Many query parameters ({query_count})")
    elif query_count >= 3:
        add(4, "Several query parameters")

    encoded_hits = int(signals.get("encoded_obfuscation_count", 0))
    if encoded_hits > 0:
        add(min(10, 4 + encoded_hits * 2), "Encoded URL obfuscation")
        indicators.append("Encoded characters suggest obfuscation")

    host_keywords = signals.get("host_keywords", [])
    if host_keywords:
        points = min(14, 6 + len(host_keywords) * 3)
        add(points, "Suspicious host keywords")
        indicators.append(f"Suspicious keywords in host: {', '.join(host_keywords)}")
        reasons.append("Host contains phishing-related keywords")

    path_keywords = signals.get("path_keywords", [])
    if path_keywords:
        points = min(16, len(path_keywords) * 4)
        add(points, "Suspicious path/query keywords")
        indicators.append(f"Suspicious keywords in path/query: {', '.join(path_keywords)}")
        reasons.append("Path/query contains phishing-related language")

    brand_signal = signals.get("brand_signal")
    similarity_score = float(signals.get("similarity_score", 0))

    if similarity_score > 80:
        add(25, "High brand similarity")
        indicators.append("Domain resembles known brand")
        reasons.append("Hostname is highly similar to a known brand")

    if brand_signal:
        base = 25
        if similarity_score >= 80:
            base += 10
        elif similarity_score >= 70:
            base += 5

        if signals.get("dns_found"):
            base += 5
            indicators.append("Impersonating domain appears active (DNS found)")

        if signals.get("is_http") or not signals.get("is_https", True):
            base += 10
            indicators.append("Brand impersonation over HTTP")

        add(base, "Brand impersonation")
        indicators.append(f"Brand impersonation signal: {brand_signal}")
        reasons.append("URL appears to impersonate a known brand")

    domain_age_days = signals.get("domain_age_days")
    if isinstance(domain_age_days, int):
        if domain_age_days <= 30:
            add(20, "New domain age (<=30 days)")
            indicators.append(f"Very new domain ({domain_age_days} days old)")
            reasons.append("Recently registered domains are common in phishing")
        elif domain_age_days <= 90:
            add(10, "Young domain age (<=90 days)")
            indicators.append(f"Young domain ({domain_age_days} days old)")

    vt = signals.get("virustotal")
    if vt:
        vt_malicious = int(vt.get("malicious", 0))
        vt_suspicious = int(vt.get("suspicious", 0))
        vt_harmless = int(vt.get("harmless", 0))
        total = vt_malicious + vt_suspicious + vt_harmless
        ratio = (vt_malicious / total) if total > 0 else 0

        if vt_malicious >= 5 or ratio > 0.2:
            add(25, "VirusTotal strong malicious ratio")
            indicators.append("VirusTotal strongly malicious")
            reasons.append("Threat intelligence strongly indicates malicious behavior")
        elif vt_malicious >= 2:
            add(10, "VirusTotal mild malicious ratio")
            indicators.append("VirusTotal mildly suspicious")
            reasons.append("Threat intelligence indicates mild malicious behavior")
        else:
            # Ignore small noise from low-confidence detections.
            pass

    # Rule-based overrides
    login_terms = {"login", "signin", "sign-in", "verify", "auth", "password", "otp"}
    has_login_keyword = any(item in login_terms for item in [*host_keywords, *path_keywords])
    if brand_signal and has_login_keyword and score < 65:
        delta = 65 - score
        add(delta, "Rule override: brand + login keyword")
        overrides.append("brand impersonation + login keyword => HIGH risk")
        reasons.append("Rule hit: brand impersonation combined with login-style bait")

    if signals.get("ip_host") and (signals.get("is_http") or not signals.get("is_https", True)) and score < 70:
        delta = 70 - score
        add(delta, "Rule override: IP host + no HTTPS")
        overrides.append("ip host + no https => HIGH risk")
        reasons.append("Rule hit: direct IP destination over non-secure HTTP")

    if isinstance(domain_age_days, int) and domain_age_days <= 90 and (host_keywords or path_keywords) and score < 60:
        delta = 60 - score
        add(delta, "Rule override: new domain + suspicious keywords")
        overrides.append("new domain + suspicious keyword => HIGH risk")
        reasons.append("Rule hit: young domain plus phishing-themed wording")

    if signals.get("whitelist_matched"):
        discount = -25
        add(discount, "Whitelist trust adjustment")
        indicators.append("Host matched trusted whitelist")
        reasons.append("Known safe base domain matched whitelist")

    if not reasons and not indicators:
        reasons.append("No strong phishing signals were detected")

    score = max(0, min(100, score))
    return score, indicators, reasons, breakdown, overrides


def url_recommendations(level: str) -> List[str]:
    level_norm = level.lower()
    if level_norm in {"critical", "high"}:
        return [
            "Do not open this URL in a browser.",
            "Do not enter credentials or payment details.",
            "Verify the domain through official channels before any action.",
        ]
    if level_norm == "medium":
        return [
            "Proceed with caution and verify domain spelling carefully.",
            "Avoid login/payment actions unless independently confirmed.",
            "Cross-check with the official website from a trusted bookmark.",
        ]
    return [
        "No strong phishing signals found, but stay cautious.",
        "Still verify sender/context before sharing sensitive information.",
    ]


def risk_level_from_score(score: int) -> str:
    return to_risk_level(score)
