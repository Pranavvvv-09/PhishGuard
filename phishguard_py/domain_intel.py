from __future__ import annotations

import asyncio
import os
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urljoin, urlparse

import httpx

from .domain_keywords import (
    DEFAULT_BRANDS,
    DEFAULT_SUSPICIOUS_KEYWORDS,
    DEFAULT_WHITELIST,
    detect_brand_signal,
    detect_keyword_matches,
    is_whitelisted_host,
)
from .dns_checks import resolve_dns_records
from .models import (
    DomainAnalysisReport,
    DomainFinding,
    DomainIntelligence,
    DomainVariant,
    RegistrationCheck,
    UrlAnalysisReport,
    VirusTotalReputation,
    WhoisInfo,
)
from .scoring import risk_level_from_score, score_domain_finding, score_url_signals, url_recommendations
from .utils import (
    days_between,
    is_ip_host,
    normalize_url_input,
    parse_date,
    parse_domain_parts,
    run_with_semaphore,
    utc_now_iso,
)

RDAP_CACHE: Dict[str, WhoisInfo | None] = {}
IP_PROVIDER_CACHE: Dict[str, str | None] = {}
VT_CACHE: Dict[str, VirusTotalReputation | None] = {}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "cutt.ly",
    "buff.ly",
    "tiny.cc",
}

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "shop",
    "buzz",
    "zip",
    "gq",
    "tk",
    "work",
    "support",
    "monster",
    "fit",
    "country",
}


def _extract_vcard_name(entity: Dict[str, Any]) -> Optional[str]:
    vcard_array = entity.get("vcardArray")
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return None
    entries = vcard_array[1]
    if not isinstance(entries, list):
        return None
    for row in entries:
        if isinstance(row, list) and len(row) >= 4 and row[0] == "fn" and isinstance(row[3], str):
            return row[3].strip() or None
    return None


def _extract_event_date(payload: Dict[str, Any], event_action: str) -> Optional[str]:
    events = payload.get("events", [])
    if not isinstance(events, list):
        return None
    for event in events:
        if not isinstance(event, dict):
            continue
        if str(event.get("eventAction", "")).lower() == event_action.lower():
            value = event.get("eventDate")
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _classify_registration_window(age_days: Optional[int]) -> Optional[str]:
    if age_days is None:
        return None
    if age_days <= 14:
        return "very_new_0_14d"
    if age_days <= 30:
        return "new_15_30d"
    if age_days <= 180:
        return "young_31_180d"
    return "mature_180d_plus"


def _guess_hosting_provider(nameservers: List[str], registrar: Optional[str]) -> Optional[str]:
    text = " ".join([*nameservers, registrar or ""]).lower()
    if not text.strip():
        return None
    if "cloudflare" in text:
        return "Cloudflare"
    if "awsdns" in text or "route53" in text:
        return "Amazon Route 53"
    if "domaincontrol.com" in text or "godaddy" in text:
        return "GoDaddy DNS"
    if "google" in text:
        return "Google Cloud DNS"
    if "azure" in text or "windows.net" in text:
        return "Microsoft Azure DNS"
    if "digitalocean" in text:
        return "DigitalOcean"
    if "namecheap" in text:
        return "Namecheap DNS"
    if "vercel-dns" in text:
        return "Vercel DNS"
    return None


def _detect_mixed_script(hostname: str) -> bool:
    has_latin = any("a" <= char.lower() <= "z" for char in hostname)
    has_non_latin = any(ord(char) > 127 for char in hostname)
    return has_latin and has_non_latin


async def _follow_redirects(client: httpx.AsyncClient, url_input: str) -> tuple[Optional[str], str, List[str]]:
    chain = [url_input]
    current = url_input

    for _ in range(6):
        try:
            response = await client.get(current, follow_redirects=False)
        except Exception:
            break
        location = response.headers.get("location")
        if response.status_code in {301, 302, 303, 307, 308} and location:
            resolved = urljoin(current, location)
            if resolved == current:
                break
            chain.append(resolved)
            current = resolved
            continue
        break

    expanded = chain[1] if len(chain) > 1 else None
    return expanded, current, chain


async def _fetch_domain_rdap(client: httpx.AsyncClient, hostname: str) -> Optional[WhoisInfo]:
    if hostname in RDAP_CACHE:
        return RDAP_CACHE[hostname]

    try:
        response = await client.get(f"https://rdap.org/domain/{hostname}")
        if response.status_code != 200:
            RDAP_CACHE[hostname] = None
            return None

        payload = response.json()
        nameservers = []
        for item in payload.get("nameservers", []):
            if not isinstance(item, dict):
                continue
            ldh_name = item.get("ldhName")
            if isinstance(ldh_name, str) and ldh_name.strip():
                nameservers.append(ldh_name.strip().lower().rstrip("."))

        registrar = None
        for entity in payload.get("entities", []):
            if not isinstance(entity, dict):
                continue
            roles = [str(role).lower() for role in entity.get("roles", []) if isinstance(role, str)]
            if "registrar" in roles:
                registrar = _extract_vcard_name(entity)
                if registrar:
                    break

        whois = WhoisInfo(
            registered=True,
            registrar=registrar,
            createdDate=_extract_event_date(payload, "registration"),
            updatedDate=_extract_event_date(payload, "last changed"),
            expiryDate=_extract_event_date(payload, "expiration"),
            whoisServer=payload.get("port43"),
            nameServers=sorted(set(nameservers)),
            source="rdap",
            raw=payload,
        )
        RDAP_CACHE[hostname] = whois
        return whois
    except Exception:
        RDAP_CACHE[hostname] = None
        return None


async def _fetch_ip_provider(client: httpx.AsyncClient, ip: str) -> Optional[str]:
    if ip in IP_PROVIDER_CACHE:
        return IP_PROVIDER_CACHE[ip]

    try:
        response = await client.get(f"https://rdap.org/ip/{ip}")
        if response.status_code != 200:
            IP_PROVIDER_CACHE[ip] = None
            return None
        payload = response.json()
        provider = payload.get("name") or payload.get("handle")
        if not provider:
            entities = payload.get("entities", [])
            if isinstance(entities, list):
                for entity in entities:
                    if not isinstance(entity, dict):
                        continue
                    provider = _extract_vcard_name(entity)
                    if provider:
                        break
        final = str(provider).strip() if provider else None
        IP_PROVIDER_CACHE[ip] = final
        return final
    except Exception:
        IP_PROVIDER_CACHE[ip] = None
        return None


async def _fetch_virustotal(
    client: httpx.AsyncClient,
    hostname: str,
    enabled: bool,
) -> Optional[VirusTotalReputation]:
    if not enabled:
        return None
    if hostname in VT_CACHE:
        return VT_CACHE[hostname]

    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        VT_CACHE[hostname] = None
        return None

    try:
        response = await client.get(
            f"https://www.virustotal.com/api/v3/domains/{hostname}",
            headers={"x-apikey": api_key},
        )
        if response.status_code != 200:
            VT_CACHE[hostname] = None
            return None
        payload = response.json()
        attrs = payload.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result = VirusTotalReputation(
            malicious=int(stats.get("malicious", 0)),
            suspicious=int(stats.get("suspicious", 0)),
            harmless=int(stats.get("harmless", 0)),
            undetected=int(stats.get("undetected", 0)),
            reputation=attrs.get("reputation"),
            lastAnalysisDate=None,
        )
        VT_CACHE[hostname] = result
        return result
    except Exception:
        VT_CACHE[hostname] = None
        return None


async def analyze_domain_variants(
    legitimate_domain_input: str,
    variants: List[DomainVariant],
    *,
    include_rdap: bool = False,
    include_virustotal: bool = False,
    suspicious_keywords: Optional[List[str]] = None,
    brand_keywords: Optional[List[str]] = None,
    registered_only: bool = True,
    concurrency: int = 10,
) -> DomainAnalysisReport:
    parts = parse_domain_parts(legitimate_domain_input)
    suspicious_wordlist = suspicious_keywords or list(DEFAULT_SUSPICIOUS_KEYWORDS)
    brand_wordlist = brand_keywords or list(DEFAULT_BRANDS)

    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
        async def worker(variant: DomainVariant) -> DomainFinding:
            records, hits, errors = await asyncio.to_thread(resolve_dns_records, variant.asciiDomain)
            is_registered = bool(hits)

            whois: Optional[WhoisInfo] = None
            if include_rdap and is_registered:
                whois = await _fetch_domain_rdap(client, variant.asciiDomain)

            registration = RegistrationCheck(
                isRegistered=is_registered or bool(whois and whois.registered),
                dnsRecordTypes=hits,
                dnsErrors=errors,
                certificateTransparencyHits=0,
                certificateIssuers=[],
                dnsRecords=records,
                whois=whois,
            )

            resolved_ips = list(dict.fromkeys(records.get("A", []) + records.get("AAAA", [])))[:8]
            nameservers = sorted(
                set(
                    (whois.nameServers if whois and whois.nameServers else records.get("NS", []))
                )
            )[:8]

            registration_date = whois.createdDate if whois else None
            updated_date = whois.updatedDate if whois else None
            expiry_date = whois.expiryDate if whois else None
            registered_dt = parse_date(registration_date)
            age_days = days_between(registered_dt) if registered_dt else None

            network_provider = None
            if include_rdap and resolved_ips:
                network_provider = await _fetch_ip_provider(client, resolved_ips[0])

            hosting_provider = _guess_hosting_provider(nameservers, whois.registrar if whois else None)

            vt = await _fetch_virustotal(client, variant.asciiDomain, include_virustotal and registration.isRegistered)
            keyword_matches = detect_keyword_matches(variant.asciiDomain, suspicious_wordlist)
            brand_signal, _, _ = detect_brand_signal(variant.asciiDomain, brand_wordlist)

            intelligence = DomainIntelligence(
                host=variant.asciiDomain,
                threatFeedMatched=False,
                websiteSimilarity=None,
                suspiciousKeywords=keyword_matches,
                brandImpersonationSignal=brand_signal,
                registrantAgeDays=age_days,
                registrationDate=registration_date,
                updatedDate=updated_date,
                expiryDate=expiry_date,
                recentRegistrationWindow=_classify_registration_window(age_days),
                registrar=whois.registrar if whois else None,
                hostingProvider=hosting_provider,
                networkProvider=network_provider,
                resolvedIps=resolved_ips,
                nameServers=nameservers,
                whoisServer=whois.whoisServer if whois else None,
                certIssuerSamples=[],
                virusTotal=vt,
            )

            score, indicators = score_domain_finding(variant, registration, intelligence)
            return DomainFinding(
                variant=variant,
                registration=registration,
                intelligence=intelligence,
                score=score,
                level=risk_level_from_score(score),
                indicators=indicators,
            )

        findings = await run_with_semaphore(variants, worker, concurrency=concurrency)

    if registered_only:
        findings = [item for item in findings if item.registration.isRegistered]
    findings.sort(key=lambda item: item.score, reverse=True)

    return DomainAnalysisReport(
        legitimateDomain=parts.registrableDomain,
        analyzedAt=utc_now_iso(),
        candidatesGenerated=len(variants),
        candidatesEvaluated=len(variants),
        registeredCandidates=sum(1 for item in findings if item.registration.isRegistered),
        findings=findings,
    )


async def analyze_suspicious_url(
    url_input: str,
    *,
    include_dns: bool = True,
    include_rdap: bool = True,
    include_virustotal: bool = False,
    suspicious_keywords: Optional[List[str]] = None,
    brand_keywords: Optional[List[str]] = None,
) -> UrlAnalysisReport:
    normalized = normalize_url_input(url_input)
    if not normalized:
        raise ValueError(f"Invalid URL input: {url_input}")

    suspicious_wordlist = suspicious_keywords or list(DEFAULT_SUSPICIOUS_KEYWORDS)
    brand_wordlist = brand_keywords or list(DEFAULT_BRANDS)

    async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
        _, final_url, redirect_chain = await _follow_redirects(client, normalized)
        parsed_initial = urlparse(normalized)
        parsed_final = urlparse(final_url)
        final_host = (parsed_final.hostname or "").lower()

        if not final_host:
            raise ValueError(f"Cannot parse hostname from URL: {url_input}")

        host_keywords = detect_keyword_matches(final_host, suspicious_wordlist)
        path_blob = f"{parsed_final.path}{parsed_final.query}".lower()
        path_keywords = [keyword for keyword in suspicious_wordlist if keyword in path_blob]
        brand_signal, _, similarity_score = detect_brand_signal(final_host, brand_wordlist)

        dns_records: Dict[str, List[str]] = {}
        dns_hits: List[str] = []
        dns_errors: List[str] = []
        if include_dns and not is_ip_host(final_host):
            dns_records, dns_hits, dns_errors = await asyncio.to_thread(resolve_dns_records, final_host)

        whois: Optional[WhoisInfo] = None
        if include_rdap and not is_ip_host(final_host):
            whois = await _fetch_domain_rdap(client, final_host)

        vt = await _fetch_virustotal(client, final_host, include_virustotal)
        vt_payload = vt.model_dump() if vt else None
        parsed_created = parse_date(whois.createdDate) if whois and whois.createdDate else None
        domain_age_days = days_between(parsed_created) if parsed_created else None
        query_params = parse_qsl(parsed_final.query, keep_blank_values=True)
        subdomain_count = max(0, len([x for x in final_host.split(".")[:-2] if x])) if "." in final_host else 0
        uncommon_port = parsed_final.port is not None and parsed_final.port not in {80, 443}
        encoded_hits = sum(
            final_url.lower().count(token)
            for token in ("%40", "%2f", "%2e", "%25", "%3a", "%3d")
        )
        whitelist_matched = is_whitelisted_host(final_host, list(DEFAULT_WHITELIST))

        signals = {
            "is_http": parsed_final.scheme.lower() == "http",
            "is_https": parsed_final.scheme.lower() == "https",
            "shortener_used": parsed_initial.hostname.lower() in URL_SHORTENERS if parsed_initial.hostname else False,
            "redirect_hops": max(0, len(redirect_chain) - 1),
            "mixed_script": final_host.startswith("xn--") or _detect_mixed_script(final_host),
            "ip_host": is_ip_host(final_host),
            "suspicious_tld": (
                final_host.split(".")[-1] if final_host.split(".")[-1] in SUSPICIOUS_TLDS else None
            ),
            "url_length": len(final_url),
            "has_at_symbol": "@" in final_url,
            "subdomain_count": subdomain_count,
            "uncommon_port": uncommon_port,
            "query_param_count": len(query_params),
            "encoded_obfuscation_count": encoded_hits,
            "host_keywords": host_keywords,
            "path_keywords": path_keywords,
            "brand_signal": brand_signal,
            "similarity_score": similarity_score,
            "domain_age_days": domain_age_days,
            "whitelist_matched": whitelist_matched,
            "dns_found": bool(dns_hits),
            "virustotal": vt_payload,
        }

        score, indicators, reasons, score_breakdown, rule_overrides = score_url_signals(signals)
        level = risk_level_from_score(score)

        if include_dns:
            if dns_hits:
                indicators.append(f"DNS records found: {', '.join(dns_hits)}")
            else:
                indicators.append("DNS: unavailable (skipped/not found)")
        if include_rdap:
            if whois and whois.registrar:
                indicators.append(f"WHOIS registrar: {whois.registrar}")
            elif whois is None:
                indicators.append("WHOIS: unavailable (skipped/not found)")
        if include_virustotal and vt is None:
            indicators.append("VirusTotal: unavailable (skipped or no API response)")

        verdict_map = {
            "critical": "Likely phishing. Block and investigate immediately.",
            "high": "High phishing risk. Avoid interaction and verify independently.",
            "medium": "Potentially suspicious. Verify carefully before proceeding.",
            "low": "No strong phishing evidence, but remain cautious.",
        }

        return UrlAnalysisReport(
            inputUrl=url_input,
            normalizedUrl=normalized,
            finalUrl=final_url,
            hostname=final_host,
            score=score,
            level=level,
            verdict=verdict_map.get(level, verdict_map["medium"]),
            reasons=reasons[:5],
            indicators=indicators[:12],
            redirectHops=max(0, len(redirect_chain) - 1),
            isHttps=parsed_final.scheme.lower() == "https",
            isIpHost=is_ip_host(final_host),
            dnsRecordTypes=dns_hits,
            dnsErrors=dns_errors,
            dnsRecords=dns_records,
            whois=whois,
            virusTotal=vt,
            domainAgeDays=domain_age_days,
            whitelistMatched=whitelist_matched,
            scoreBreakdown=score_breakdown,
            ruleOverrides=rule_overrides,
            recommendations=url_recommendations(level),
        )
