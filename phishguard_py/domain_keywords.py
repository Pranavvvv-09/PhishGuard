from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Optional, Tuple

import tldextract

from .utils import levenshtein_metrics

# Production-ready suspicious keyword baseline
DEFAULT_SUSPICIOUS_KEYWORDS = [
    # Authentication / Login
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "authenticate",
    "auth",
    "password",
    "passcode",
    "pin",
    "otp",
    "2fa",
    "mfa",
    "secure-login",
    "account-login",
    # Urgency / Threat
    "urgent",
    "immediate",
    "alert",
    "warning",
    "suspended",
    "locked",
    "blocked",
    "restricted",
    "action-required",
    "security-alert",
    "unauthorized",
    "fraud",
    "breach",
    "compromised",
    # Financial / Payment
    "payment",
    "billing",
    "invoice",
    "refund",
    "transaction",
    "bank",
    "credit",
    "debit",
    "card",
    "wallet",
    "crypto",
    "transfer",
    "withdraw",
    "deposit",
    "paypal",
    # Account Actions
    "update",
    "confirm",
    "reset",
    "recovery",
    "restore",
    "activate",
    "reactivate",
    "validate",
    "upgrade",
    "unlock",
    "re-authenticate",
    # Scam / Bait
    "free",
    "bonus",
    "reward",
    "gift",
    "prize",
    "offer",
    "limited",
    "exclusive",
    "winner",
    "claim",
    "promotion",
    "discount",
    # Technical / URL Tricks
    "secure",
    "account",
    "support",
    "service",
    "portal",
    "access",
    "dashboard",
    "webmail",
    "client",
    "server",
    "auth-secure",
]

DEFAULT_BRANDS = [
    "google",
    "gmail",
    "microsoft",
    "office365",
    "outlook",
    "apple",
    "icloud",
    "amazon",
    "netflix",
    "paypal",
    "facebook",
    "instagram",
    "linkedin",
    "twitter",
    "bank",
    "coinbase",
    "binance",
]

DEFAULT_WHITELIST = [
    "google.com",
    "github.com",
    "microsoft.com",
]

_LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"})


def _normalize_token(value: str) -> str:
    return "".join(char for char in value.lower().translate(_LEET_MAP) if char.isalnum())


def _clean_items(items: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for item in items:
        value = item.strip().lower()
        if not value or value.startswith("#"):
            continue
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def load_indicator_list(path: Path | None, fallback: List[str]) -> List[str]:
    if path is None:
        return list(fallback)
    try:
        content = path.read_text(encoding="utf-8")
        return _clean_items(content.splitlines()) or list(fallback)
    except Exception:
        return list(fallback)


def extract_domain_tokens(hostname: str) -> List[str]:
    tokens: List[str] = []
    for label in hostname.lower().split("."):
        for token in label.split("-"):
            token = token.strip()
            if token:
                tokens.append(token)
    return tokens


def detect_keyword_matches(hostname: str, suspicious_keywords: List[str] | None = None) -> List[str]:
    wordlist = suspicious_keywords or DEFAULT_SUSPICIOUS_KEYWORDS
    haystack = hostname.lower()
    matches = [keyword for keyword in wordlist if keyword and keyword in haystack]
    return _clean_items(matches)


def detect_brand_signal(hostname: str, brands: List[str] | None = None) -> Tuple[Optional[str], int, float]:
    brand_list = brands or DEFAULT_BRANDS
    tokens = extract_domain_tokens(hostname)
    normalized_brands = [(brand, _normalize_token(brand)) for brand in brand_list]

    best_signal: Optional[str] = None
    best_strength = 0
    best_similarity = 0.0

    for token in tokens:
        normalized_token = _normalize_token(token)
        if len(normalized_token) < 4:
            continue
        for raw_brand, normalized_brand in normalized_brands:
            if not normalized_brand:
                continue
            if normalized_token == normalized_brand and token != raw_brand:
                signal = f'"{token}" -> {raw_brand} (leet impersonation)'
                return signal, 30, 100.0
            dist, similarity, _, _ = levenshtein_metrics(normalized_token, normalized_brand)
            if dist > 0 and (dist <= 2 or similarity >= 78):
                if similarity > best_similarity:
                    best_signal = f'"{token}" ~ {raw_brand} (distance {dist})'
                    best_strength = 18
                    best_similarity = similarity
    return best_signal, best_strength, best_similarity


def is_whitelisted_host(hostname: str, whitelist: List[str] | None = None) -> bool:
    allowed = [item.lower().strip() for item in (whitelist or DEFAULT_WHITELIST) if item.strip()]
    if not allowed:
        return False
    host = hostname.lower().strip().rstrip(".")
    extracted = tldextract.extract(host)
    registrable = f"{extracted.domain}.{extracted.suffix}" if extracted.domain and extracted.suffix else host
    return any(registrable == item or host == item or host.endswith(f".{item}") for item in allowed)
