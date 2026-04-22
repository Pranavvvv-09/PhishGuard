from __future__ import annotations

from typing import Dict, List, Set

from .models import DomainVariant
from .utils import levenshtein_metrics, parse_domain_parts

COMMON_TLDS = ["com", "co", "net", "org", "io", "ai", "in", "app", "dev", "xyz"]

KEYBOARD_NEIGHBORS: Dict[str, List[str]] = {
    "a": ["q", "w", "s", "z"],
    "b": ["v", "g", "h", "n"],
    "c": ["x", "d", "f", "v"],
    "d": ["s", "e", "r", "f", "c", "x"],
    "e": ["w", "s", "d", "r"],
    "f": ["d", "r", "t", "g", "v", "c"],
    "g": ["f", "t", "y", "h", "b", "v"],
    "h": ["g", "y", "u", "j", "n", "b"],
    "i": ["u", "j", "k", "o"],
    "j": ["h", "u", "i", "k", "n", "m"],
    "k": ["j", "i", "o", "l", "m"],
    "l": ["k", "o", "p"],
    "m": ["n", "j", "k"],
    "n": ["b", "h", "j", "m"],
    "o": ["i", "k", "l", "p"],
    "p": ["o", "l"],
    "q": ["w", "a"],
    "r": ["e", "d", "f", "t"],
    "s": ["a", "w", "e", "d", "x", "z"],
    "t": ["r", "f", "g", "y"],
    "u": ["y", "h", "j", "i"],
    "v": ["c", "f", "g", "b"],
    "w": ["q", "a", "s", "e"],
    "x": ["z", "s", "d", "c"],
    "y": ["t", "g", "h", "u"],
    "z": ["a", "s", "x"],
}


def _valid_domain(domain: str) -> bool:
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not all(char.isalnum() or char == "-" for char in label):
            return False
    return True


def generate_domain_variants(
    input_domain: str,
    max_variants: int = 25,
    tlds: List[str] | None = None,
) -> List[DomainVariant]:
    parts = parse_domain_parts(input_domain)
    max_variants = max(1, min(25, int(max_variants)))
    tld_pool = tlds or COMMON_TLDS
    prefix = f"{'.'.join(parts.prefixLabels)}." if parts.prefixLabels else ""
    label = parts.baseLabel

    raw_candidates: list[tuple[str, str, str]] = []
    seen: Set[str] = set()

    def push(mutated_label_or_domain: str, technique: str, mutation: str, absolute: bool = False) -> None:
        if len(raw_candidates) >= max_variants:
            return
        candidate = mutated_label_or_domain if absolute else f"{prefix}{mutated_label_or_domain}.{parts.tld}"
        candidate = candidate.lower()
        if candidate in seen or not _valid_domain(candidate):
            return
        seen.add(candidate)
        raw_candidates.append((candidate, technique, mutation))

    for idx in range(len(label)):
        omitted = f"{label[:idx]}{label[idx + 1:]}"
        if len(omitted) >= 2:
            push(omitted, "omission", f"Removed character at index {idx}")

    for idx in range(len(label)):
        repeated = f"{label[:idx]}{label[idx]}{label[idx:]}"
        push(repeated, "repetition", f'Repeated character "{label[idx]}" at index {idx}')

    for idx in range(len(label) - 1):
        swapped = label[:idx] + label[idx + 1] + label[idx] + label[idx + 2 :]
        push(swapped, "character_swap", f"Swapped indices {idx} and {idx + 1}")

    for idx, char in enumerate(label):
        for replacement in KEYBOARD_NEIGHBORS.get(char, []):
            substituted = f"{label[:idx]}{replacement}{label[idx + 1:]}"
            push(
                substituted,
                "keyboard_adjacency",
                f"Keyboard-neighbor substitution {char}->{replacement} at index {idx}",
            )

    for idx in range(1, len(label)):
        if label[idx - 1] == "-" or label[idx] == "-":
            continue
        hyphenated = f"{label[:idx]}-{label[idx:]}"
        push(hyphenated, "hyphenation", f"Inserted hyphen at index {idx}")

    for tld in tld_pool:
        if tld == parts.tld:
            continue
        push(f"{prefix}{label}.{tld}", "tld_swap", f"Swapped TLD {parts.tld}->{tld}", absolute=True)

    variants: List[DomainVariant] = []
    for ascii_domain, technique, mutation in raw_candidates:
        dist, score, normalized_source, normalized_candidate = levenshtein_metrics(parts.registrableDomain, ascii_domain)
        variants.append(
            DomainVariant(
                sourceDomain=parts.registrableDomain,
                displayDomain=ascii_domain,
                asciiDomain=ascii_domain,
                technique=technique,  # type: ignore[arg-type]
                mutation=mutation,
                similarity=score,
                levenshteinDistance=dist,
                normalizedSource=normalized_source,
                normalizedCandidate=normalized_candidate,
            )
        )

    return variants[:max_variants]
