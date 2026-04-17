import { resolve } from "node:dns/promises";

export type DnsLookupResult = {
  hostname: string;
  records: Record<string, string[]>;
  errors: string[];
};

function normalizeUrlInput(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) {
    throw new Error("URL is empty.");
  }
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

export function parseHostnameFromUrl(input: string): { normalizedUrl: string; hostname: string } {
  const normalizedUrl = normalizeUrlInput(input);
  const hostname = new URL(normalizedUrl).hostname.toLowerCase();
  return { normalizedUrl, hostname };
}

function mapRecord(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (value && typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

export async function resolveDomainDns(hostname: string): Promise<DnsLookupResult> {
  const rrTypes = ["A", "AAAA", "NS", "MX", "TXT", "CNAME"] as const;
  const records: Record<string, string[]> = {};
  const errors: string[] = [];

  await Promise.all(
    rrTypes.map(async (rrType) => {
      try {
        const result = (await resolve(hostname, rrType)) as unknown[];
        records[rrType] = result.map(mapRecord);
      } catch (error) {
        records[rrType] = [];
        const message = error instanceof Error ? error.message : "unknown error";
        errors.push(`${rrType}: ${message}`);
      }
    }),
  );

  return { hostname, records, errors };
}
