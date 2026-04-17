import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { domainToASCII, domainToUnicode } from "node:url";

import { MULTI_PART_TLDS } from "./constants";
import type { DomainParts, RiskLevel } from "./types";

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function normalizeHostInput(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) {
    throw new Error("Domain input is empty.");
  }

  let urlLike = trimmed;
  if (!trimmed.includes("://")) {
    urlLike = `https://${trimmed}`;
  }

  const hostname = new URL(urlLike).hostname.toLowerCase();
  return hostname.endsWith(".") ? hostname.slice(0, -1) : hostname;
}

export function parseDomainParts(input: string): DomainParts {
  const hostname = normalizeHostInput(input);
  const labels = hostname.split(".").filter(Boolean);

  if (labels.length < 2) {
    throw new Error(`Cannot parse registrable domain from "${input}".`);
  }

  let tldLabelsCount = 1;
  const candidateMultipart = labels.slice(-2).join(".");
  if (labels.length >= 3 && MULTI_PART_TLDS.has(candidateMultipart)) {
    tldLabelsCount = 2;
  }

  const tld = labels.slice(-tldLabelsCount).join(".");
  const baseLabelIndex = labels.length - (tldLabelsCount + 1);
  if (baseLabelIndex < 0) {
    throw new Error(`Could not determine base label for "${input}".`);
  }

  const baseLabel = labels[baseLabelIndex];
  const prefixLabels = labels.slice(0, baseLabelIndex);
  const registrableDomain = `${baseLabel}.${tld}`;

  return {
    sourceInput: input,
    hostname,
    registrableDomain,
    baseLabel,
    tld,
    prefixLabels,
  };
}

export function isLikelyIpHost(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

export function isValidDomainLabel(label: string): boolean {
  return /^[a-z0-9-]{1,63}$/i.test(label) && !label.startsWith("-") && !label.endsWith("-");
}

export function isValidAsciiDomain(domain: string): boolean {
  const labels = domain.split(".");
  if (labels.length < 2) {
    return false;
  }
  return labels.every(isValidDomainLabel);
}

export function toAsciiDomain(domain: string): string {
  return domainToASCII(domain).toLowerCase();
}

export function toUnicodeDomain(domain: string): string {
  return domainToUnicode(domain);
}

export function levenshteinDistance(a: string, b: string): number {
  if (a === b) {
    return 0;
  }
  if (!a.length) {
    return b.length;
  }
  if (!b.length) {
    return a.length;
  }

  const matrix: number[][] = Array.from({ length: a.length + 1 }, () =>
    new Array<number>(b.length + 1).fill(0),
  );

  for (let i = 0; i <= a.length; i += 1) {
    matrix[i][0] = i;
  }
  for (let j = 0; j <= b.length; j += 1) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost,
      );
    }
  }

  return matrix[a.length][b.length];
}

export function similarityScore(a: string, b: string): number {
  return levenshteinMetrics(a, b).score;
}

export function levenshteinMetrics(a: string, b: string): {
  distance: number;
  score: number;
  normalizedA: string;
  normalizedB: string;
  maxLength: number;
} {
  const normalizedA = a.toLowerCase().replace(/[^a-z0-9]/g, "");
  const normalizedB = b.toLowerCase().replace(/[^a-z0-9]/g, "");

  if (!normalizedA.length || !normalizedB.length) {
    return {
      distance: Math.max(normalizedA.length, normalizedB.length),
      score: 0,
      normalizedA,
      normalizedB,
      maxLength: Math.max(normalizedA.length, normalizedB.length),
    };
  }

  const maxLen = Math.max(normalizedA.length, normalizedB.length);
  const distance = levenshteinDistance(normalizedA, normalizedB);
  const score = (1 - distance / maxLen) * 100;
  return {
    distance,
    score: Math.max(0, Math.min(100, Number(score.toFixed(2)))),
    normalizedA,
    normalizedB,
    maxLength: maxLen,
  };
}

export function toRiskLevel(score: number): RiskLevel {
  if (score >= 80) {
    return "critical";
  }
  if (score >= 60) {
    return "high";
  }
  if (score >= 35) {
    return "medium";
  }
  return "low";
}

export async function runWithConcurrency<TInput, TOutput>(
  inputs: TInput[],
  worker: (input: TInput, index: number) => Promise<TOutput>,
  concurrency: number,
  delayMs = 0,
): Promise<TOutput[]> {
  if (concurrency < 1) {
    throw new Error("Concurrency must be at least 1.");
  }

  const results: TOutput[] = new Array<TOutput>(inputs.length);
  let cursor = 0;

  const runners = Array.from({ length: Math.min(concurrency, inputs.length) }, async () => {
    while (true) {
      const index = cursor;
      cursor += 1;
      if (index >= inputs.length) {
        return;
      }

      results[index] = await worker(inputs[index], index);
      if (delayMs > 0) {
        await sleep(delayMs);
      }
    }
  });

  await Promise.all(runners);
  return results;
}

export async function ensureDirectory(path: string): Promise<void> {
  await mkdir(path, { recursive: true });
}

export async function loadJsonFile<T>(filePath: string, fallback: T): Promise<T> {
  try {
    const raw = await readFile(filePath, "utf8");
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

export async function saveJsonFile(filePath: string, payload: unknown): Promise<void> {
  await ensureDirectory(dirname(filePath));
  await writeFile(filePath, JSON.stringify(payload, null, 2), "utf8");
}

export function parseDurationToMs(raw: string): number {
  const value = raw.trim().toLowerCase();
  const match = value.match(/^(\d+)\s*(ms|s|m|h)?$/);
  if (!match) {
    throw new Error(`Invalid duration value "${raw}". Examples: 30s, 5m, 1h`);
  }

  const amount = Number(match[1]);
  const unit = match[2] ?? "ms";

  if (unit === "ms") {
    return amount;
  }
  if (unit === "s") {
    return amount * 1_000;
  }
  if (unit === "m") {
    return amount * 60_000;
  }
  return amount * 3_600_000;
}

export function parseDate(value?: string): Date | undefined {
  if (!value) {
    return undefined;
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return undefined;
  }
  return date;
}

export function daysBetween(date: Date, comparedWith = new Date()): number {
  const diffMs = comparedWith.getTime() - date.getTime();
  return Math.floor(diffMs / (24 * 60 * 60 * 1_000));
}
