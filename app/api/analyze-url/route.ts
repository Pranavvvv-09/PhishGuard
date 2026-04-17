import { NextResponse } from "next/server";

import { resolveDomainDns } from "../../lib/domain-dns";
import { analyzeQrUrl, normalizePotentialUrl } from "../../../tools/phishing-cli/qr-scanner";

export const runtime = "nodejs";

type RequestBody = {
  url?: string;
};

export async function POST(request: Request) {
  try {
    const body = (await request.json()) as RequestBody;
    const url = body.url?.trim();
    if (!url) {
      return NextResponse.json({ error: "url is required" }, { status: 400 });
    }

    const normalizedUrl = normalizePotentialUrl(url);
    if (!normalizedUrl) {
      return NextResponse.json({ error: "Invalid URL/domain input." }, { status: 400 });
    }

    const risk = await analyzeQrUrl(normalizedUrl);
    const dnsHostname = new URL(risk.finalUrl ?? normalizedUrl).hostname.toLowerCase();
    const dns = await resolveDomainDns(dnsHostname);

    return NextResponse.json({
      inputUrl: url,
      normalizedUrl,
      hostname: dnsHostname,
      generatedAt: new Date().toISOString(),
      risk,
      dns,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unexpected error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
