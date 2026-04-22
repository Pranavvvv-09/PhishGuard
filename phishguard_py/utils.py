from __future__ import annotations

import asyncio
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable, List, Sequence, TypeVar
from urllib.parse import urlparse

import tldextract
from Levenshtein import distance as levenshtein_distance_raw

from .models import DomainParts, RiskLevel

T = TypeVar("T")
U = TypeVar("U")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_parent_dir(path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def normalize_host_input(input_value: str) -> str:
    raw = input_value.strip()
    if not raw:
        raise ValueError("Input is empty.")
    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise ValueError(f"Cannot parse hostname from input: {input_value}")
    return host


def normalize_url_input(input_value: str) -> str | None:
    raw = input_value.strip()
    if not raw or " " in raw:
        return None
    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"}:
        return None
    if not parsed.hostname or "." not in parsed.hostname:
        return None
    return candidate


def parse_domain_parts(input_value: str) -> DomainParts:
    host = normalize_host_input(input_value)
    extracted = tldextract.extract(host)
    if not extracted.domain or not extracted.suffix:
        raise ValueError(f"Cannot extract registrable domain from input: {input_value}")

    base_label = extracted.domain.lower()
    tld = extracted.suffix.lower()
    registrable_domain = f"{base_label}.{tld}"
    prefix_labels = [label for label in extracted.subdomain.split(".") if label] if extracted.subdomain else []

    return DomainParts(
        sourceInput=input_value,
        hostname=host,
        registrableDomain=registrable_domain,
        baseLabel=base_label,
        tld=tld,
        prefixLabels=prefix_labels,
    )


def is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def levenshtein_metrics(a: str, b: str) -> tuple[int, float, str, str]:
    normalized_a = "".join(char for char in a.lower() if char.isalnum())
    normalized_b = "".join(char for char in b.lower() if char.isalnum())
    if not normalized_a or not normalized_b:
        return max(len(normalized_a), len(normalized_b)), 0.0, normalized_a, normalized_b
    dist = levenshtein_distance_raw(normalized_a, normalized_b)
    max_len = max(len(normalized_a), len(normalized_b))
    score = max(0.0, min(100.0, round((1 - (dist / max_len)) * 100, 2)))
    return dist, score, normalized_a, normalized_b


def to_risk_level(score: int) -> RiskLevel:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if candidate.endswith("Z"):
        candidate = candidate.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


def days_between(date_value: datetime, now: datetime | None = None) -> int:
    reference = now or datetime.now(timezone.utc)
    if date_value.tzinfo is None:
        date_value = date_value.replace(tzinfo=timezone.utc)
    return max(0, int((reference - date_value).total_seconds() // 86400))


def parse_formats(raw: str | None) -> list[str]:
    if not raw:
        return ["json"]
    allowed = {"json", "csv", "html"}
    formats = [item.strip().lower() for item in raw.split(",") if item.strip()]
    result = [fmt for fmt in formats if fmt in allowed]
    return result or ["json"]


def safe_json_dumps(payload: object) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False)


async def run_with_semaphore(
    inputs: Sequence[T],
    worker: Callable[[T], Awaitable[U]],
    concurrency: int = 10,
) -> list[U]:
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def wrapped(item: T) -> U:
        async with semaphore:
            return await worker(item)

    return await asyncio.gather(*(wrapped(item) for item in inputs))
