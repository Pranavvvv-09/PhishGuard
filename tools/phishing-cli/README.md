# Phishing Domain & Quishing Scanner

A defensive security CLI for:

- Bounded typo-variant generation (omission, repetition, adjacent swap, keyboard adjacency, hyphenation, TLD swaps)
- Similarity detection using Levenshtein distance metrics
- Registration checks with DNS, WHOIS, and certificate transparency lookups
- Enrichment and risk scoring (domain age, threat feed match, optional website similarity, optional VirusTotal reputation for domain + QR destination hosts)
- QR phishing analysis ("quishing") from image files or direct payload URLs
- Reporting in JSON, CSV, and HTML

## Quick Start

```bash
npm run phishing:cli -- help
```

### Demo Flow 1: Domain Scan

```bash
npm run phishing:cli -- domain google.com --formats json,csv,html --out reports/google-scan
```

### Demo Flow 2: QR / Quishing Scan

```bash
npm run phishing:cli -- qr-scan ./samples/poster1.png https://bit.ly/demo --formats json,html
```

### Core Commands

- `domain <legitimate-domain>`: run typo-domain similarity + reputation analysis
- `qr-scan <input...>`: scan QR payloads and check destination risk

## Campaign Context (Defensive Learning Notes)

- 2023 Microsoft observed phishing campaigns that used QR codes in emails to bypass user suspicion and some secure-email filtering workflows.
- Multiple crypto-ecosystem attacks have used IDN homograph domains to visually mimic wallet or exchange brands.
- Typosquatting has repeatedly targeted package ecosystems like npm and PyPI to distribute malicious code through lookalike package names.

## Defensive Controls to Pair With This Tool

- DMARC/SPF/DKIM enforcement for inbound email trust and spoof resistance.
- Browser and endpoint policies for IDN display / punycode safety handling.
- URL expansion checks before opening shortened links.
- User training for QR hygiene: verify destination domain before sign-in or payment.
- Blocklists and threat-intel enrichment in secure web gateways or email gateways.

## Environment Variables (Optional)

- `OPENPHISH_FEED_URL`: Override threat feed URL for domain/QR checks.
- `VIRUSTOTAL_API_KEY`: Enable VirusTotal domain reputation enrichment (domain scan + QR destination checks).

## Notes

- This tool is designed for defensive research and awareness workflows.
- Network-dependent checks may fail in restricted environments; the CLI degrades gracefully and still reports available evidence.
