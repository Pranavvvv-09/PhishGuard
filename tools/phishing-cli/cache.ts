import type { RegistrationCheck, VirusTotalReputation } from "./types";
import { loadJsonFile, saveJsonFile } from "./utils";

interface CacheEntry<T> {
  timestamp: number;
  data: T;
}

interface CachePayload {
  registration: Record<string, CacheEntry<RegistrationCheck>>;
  threatHosts: CacheEntry<string[]> | null;
  virusTotal: Record<string, CacheEntry<VirusTotalReputation | null>>;
}

function normalizeRegistration(
  input: Partial<RegistrationCheck> | undefined,
): RegistrationCheck | undefined {
  if (!input) {
    return undefined;
  }

  return {
    isRegistered: Boolean(input.isRegistered),
    dnsRecordTypes: Array.isArray(input.dnsRecordTypes) ? input.dnsRecordTypes : [],
    dnsErrors: Array.isArray(input.dnsErrors) ? input.dnsErrors : [],
    whois: input.whois,
    certificateTransparencyHits:
      typeof input.certificateTransparencyHits === "number" && Number.isFinite(input.certificateTransparencyHits)
        ? input.certificateTransparencyHits
        : 0,
    certificateIssuers: Array.isArray(input.certificateIssuers) ? input.certificateIssuers : [],
  };
}

export class ToolCache {
  private readonly filePath: string;

  private payload: CachePayload = {
    registration: {},
    threatHosts: null,
    virusTotal: {},
  };

  constructor(filePath: string) {
    this.filePath = filePath;
  }

  async init(): Promise<void> {
    const loaded = await loadJsonFile<Partial<CachePayload>>(this.filePath, this.payload);
    this.payload = {
      registration: loaded.registration ?? {},
      threatHosts: loaded.threatHosts ?? null,
      virusTotal: loaded.virusTotal ?? {},
    };
  }

  async persist(): Promise<void> {
    await saveJsonFile(this.filePath, this.payload);
  }

  getRegistration(domain: string, ttlMs: number): RegistrationCheck | undefined {
    const hit = this.payload.registration[domain];
    if (!hit) {
      return undefined;
    }
    const age = Date.now() - hit.timestamp;
    if (age > ttlMs) {
      return undefined;
    }
    return normalizeRegistration(hit.data);
  }

  setRegistration(domain: string, result: RegistrationCheck): void {
    this.payload.registration[domain] = {
      timestamp: Date.now(),
      data: result,
    };
  }

  getThreatHosts(ttlMs: number): string[] | undefined {
    const hit = this.payload.threatHosts;
    if (!hit) {
      return undefined;
    }
    const age = Date.now() - hit.timestamp;
    if (age > ttlMs) {
      return undefined;
    }
    return hit.data;
  }

  setThreatHosts(hosts: string[]): void {
    this.payload.threatHosts = {
      timestamp: Date.now(),
      data: hosts,
    };
  }

  getVirusTotal(domain: string, ttlMs: number): VirusTotalReputation | null | undefined {
    const hit = this.payload.virusTotal[domain];
    if (!hit) {
      return undefined;
    }
    const age = Date.now() - hit.timestamp;
    if (age > ttlMs) {
      return undefined;
    }
    return hit.data;
  }

  setVirusTotal(domain: string, result: VirusTotalReputation | null): void {
    this.payload.virusTotal[domain] = {
      timestamp: Date.now(),
      data: result,
    };
  }
}
