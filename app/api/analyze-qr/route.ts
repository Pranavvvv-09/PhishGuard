import { NextResponse } from "next/server";

import { resolveDomainDns } from "../../lib/domain-dns";
import {
  analyzeQrUrl,
  decodeQrFromBuffer,
  normalizePotentialUrl,
} from "../../../tools/phishing-cli/qr-scanner";

export const runtime = "nodejs";

type QrFinding =
  | {
      payload: string;
      type: "url";
      risk: Awaited<ReturnType<typeof analyzeQrUrl>>;
      dns: Awaited<ReturnType<typeof resolveDomainDns>>;
    }
  | {
      payload: string;
      type: "text";
    };

export async function POST(request: Request) {
  try {
    const form = await request.formData();
    const file = form.get("qr");
    const directUrl = String(form.get("url") ?? "").trim();

    const findings: QrFinding[] = [];

    if (directUrl) {
      const normalizedDirect = normalizePotentialUrl(directUrl);
      if (normalizedDirect) {
        const risk = await analyzeQrUrl(normalizedDirect);
        const dnsHostname = new URL(risk.finalUrl ?? normalizedDirect).hostname.toLowerCase();
        const dns = await resolveDomainDns(dnsHostname);
        findings.push({ payload: normalizedDirect, type: "url", risk, dns });
      }
    }

    if (file && file instanceof File) {
      const bytes = Buffer.from(await file.arrayBuffer());
      const payloads = await decodeQrFromBuffer(bytes, file.name || "upload.png");
      for (const payload of payloads) {
        const normalizedPayload = normalizePotentialUrl(payload);
        if (normalizedPayload) {
          const risk = await analyzeQrUrl(normalizedPayload);
          const dnsHostname = new URL(risk.finalUrl ?? normalizedPayload).hostname.toLowerCase();
          const dns = await resolveDomainDns(dnsHostname);
          findings.push({ payload: normalizedPayload, type: "url", risk, dns });
        } else {
          findings.push({ payload, type: "text" });
        }
      }
    }

    if (findings.length === 0) {
      return NextResponse.json(
        { error: "Provide either a QR image file or URL input." },
        { status: 400 },
      );
    }

    return NextResponse.json({
      generatedAt: new Date().toISOString(),
      findings,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unexpected error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
