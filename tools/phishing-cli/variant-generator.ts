import { COMMON_TLDS, KEYBOARD_NEIGHBORS } from "./constants";
import type { DomainVariant } from "./types";
import {
  isValidAsciiDomain,
  levenshteinMetrics,
  parseDomainParts,
  toAsciiDomain,
} from "./utils";

interface VariantGenerationOptions {
  maxVariants?: number;
  tlds?: string[];
}

interface InternalMutation {
  displayDomain: string;
  technique: DomainVariant["technique"];
  mutation: string;
}

export function generateDomainVariants(
  inputDomain: string,
  options: VariantGenerationOptions = {},
): DomainVariant[] {
  const parts = parseDomainParts(inputDomain);
  const maxVariants = Math.min(1200, Math.max(1, options.maxVariants ?? 800));
  const tldPool = options.tlds ?? COMMON_TLDS;

  const prefix = parts.prefixLabels.length ? `${parts.prefixLabels.join(".")}.` : "";
  const seen = new Set<string>();
  const variants: InternalMutation[] = [];

  const pushVariant = (
    mutatedLabelOrDomain: string,
    technique: DomainVariant["technique"],
    mutation: string,
    isAbsolute = false,
  ): void => {
    if (variants.length >= maxVariants) {
      return;
    }

    const displayDomain = isAbsolute
      ? mutatedLabelOrDomain
      : `${prefix}${mutatedLabelOrDomain}.${parts.tld}`;
    const asciiDomain = toAsciiDomain(displayDomain);
    if (!asciiDomain || seen.has(asciiDomain) || !isValidAsciiDomain(asciiDomain)) {
      return;
    }

    seen.add(asciiDomain);
    variants.push({ displayDomain, technique, mutation });
  };

  const label = parts.baseLabel;

  for (let i = 0; i < label.length; i += 1) {
    const omitted = `${label.slice(0, i)}${label.slice(i + 1)}`;
    if (omitted.length >= 2) {
      pushVariant(omitted, "omission", `Removed character at index ${i}`);
    }
  }

  for (let i = 0; i < label.length; i += 1) {
    const repeated = `${label.slice(0, i)}${label[i]}${label.slice(i)}`;
    pushVariant(repeated, "repetition", `Repeated character "${label[i]}" at index ${i}`);
  }

  for (let i = 0; i < label.length - 1; i += 1) {
    const swapped = label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2);
    pushVariant(swapped, "character_swap", `Swapped indices ${i} and ${i + 1}`);
  }

  for (let i = 0; i < label.length; i += 1) {
    const char = label[i];
    const neighbors = KEYBOARD_NEIGHBORS[char] ?? [];
    for (const replacement of neighbors) {
      const substituted = `${label.slice(0, i)}${replacement}${label.slice(i + 1)}`;
      pushVariant(
        substituted,
        "keyboard_adjacency",
        `Keyboard-neighbor substitution ${char}->${replacement} at index ${i}`,
      );
    }
  }

  for (let i = 1; i < label.length; i += 1) {
    if (label[i - 1] === "-" || label[i] === "-") {
      continue;
    }
    const hyphenated = `${label.slice(0, i)}-${label.slice(i)}`;
    pushVariant(hyphenated, "hyphenation", `Inserted hyphen at index ${i}`);
  }

  for (const tld of tldPool) {
    if (tld === parts.tld) {
      continue;
    }
    const domain = `${prefix}${label}.${tld}`;
    pushVariant(domain, "tld_swap", `Swapped TLD ${parts.tld}->${tld}`, true);
  }

  return variants.map((entry) => {
    const asciiDomain = toAsciiDomain(entry.displayDomain);
    const metrics = levenshteinMetrics(parts.registrableDomain, asciiDomain);
    return {
      sourceDomain: parts.registrableDomain,
      displayDomain: entry.displayDomain,
      asciiDomain,
      technique: entry.technique,
      mutation: entry.mutation,
      similarity: metrics.score,
      levenshteinDistance: metrics.distance,
      normalizedSource: metrics.normalizedA,
      normalizedCandidate: metrics.normalizedB,
    };
  });
}
