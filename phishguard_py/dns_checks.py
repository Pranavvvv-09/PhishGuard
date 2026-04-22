from __future__ import annotations

from typing import Dict, List

import dns.exception
import dns.resolver


DNS_TYPES = ["A", "AAAA", "NS", "MX", "CNAME", "TXT"]


def _normalize_dns_answer(record_type: str, answer: dns.resolver.Answer) -> List[str]:
    values: List[str] = []
    for item in answer:
        text = str(item).strip()
        if record_type in {"MX", "NS"} and text.endswith("."):
            text = text[:-1]
        values.append(text)
    return values


def resolve_dns_records(hostname: str, lifetime: float = 3.5) -> tuple[Dict[str, List[str]], List[str], List[str]]:
    records: Dict[str, List[str]] = {}
    hits: List[str] = []
    errors: List[str] = []
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = lifetime

    for record_type in DNS_TYPES:
        try:
            answer = resolver.resolve(hostname, record_type, raise_on_no_answer=False)
            parsed = _normalize_dns_answer(record_type, answer) if answer.rrset else []
            records[record_type] = parsed
            if parsed:
                hits.append(record_type)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            records[record_type] = []
        except dns.exception.Timeout:
            records[record_type] = []
            errors.append(f"{record_type}:timeout")
        except Exception as exc:  # defensive fallback
            records[record_type] = []
            errors.append(f"{record_type}:{exc}")

    return records, hits, errors
