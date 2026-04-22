# PhishGuard

Defensive cybersecurity CLI for detecting phishing domains and suspicious URLs using typosquatting analysis, similarity scoring, heuristic detection, and explainable risk scoring.


## What This Tool Does

PhishGuard has three focused commands:

- `domain`: generate bounded typo variants for a target brand/domain and score risky lookalikes.
- `url`: analyze a suspicious URL with structural checks, intelligence enrichment, and rule-based overrides.
- `compare`: compute Levenshtein similarity between two hosts for quick lookalike checks.

This is a **defensive analysis tool** designed for security triage, demos, and training.

## Responsible Use

Use this project only for defensive cybersecurity, awareness, and detection.
Do not use it to facilitate phishing, impersonation, or malicious operations.

## Tech Stack

- **CLI & UX**
  - `typer` for command parsing
  - `rich` for hacker-style terminal tables/panels
- **Core Models**
  - `pydantic` for typed report/data models
- **Network & Intelligence**
  - `httpx` for HTTP calls (RDAP + VirusTotal + redirect handling)
  - `dnspython` for DNS record resolution (`A`, `AAAA`, `NS`, `MX`, `TXT`, `CNAME`)
- **Domain & Similarity**
  - `tldextract` for registrable-domain parsing
  - `python-Levenshtein` for distance/similarity
- **Reporting**
  - `jinja2` for HTML report templates
  - JSON/CSV via stdlib
- **Configuration**
  - `python-dotenv` for `.env` (VirusTotal API key)


## Algorithms In Detail

## 1) Domain Typosquatting Generation (`variant_generator.py`)

For input like `google.com`, the generator creates bounded candidate variants using:

- `omission`: remove one character (`gogle.com`)
- `repetition`: repeat one character (`gooogle.com`)
- `character_swap`: swap adjacent characters (`googel.com`)
- `keyboard_adjacency`: QWERTY neighbor substitution
- `hyphenation`: insert hyphen at safe positions
- `tld_swap`: swap to common TLDs (`.co`, `.net`, `.io`, etc.)

Safety and quality controls:

- strict domain label validation
- de-duplication with a set
- hard cap of `max_variants` (clamped to `1..25`)

Each candidate stores:

- technique
- mutation description
- Levenshtein distance
- normalized similarity score

## 2) Similarity Engine (`utils.py`)

Levenshtein computation is done on normalized alphanumeric strings:

- lowercase
- non-alphanumeric stripped

Similarity score formula:

- `score = (1 - distance / max_len) * 100`
- clamped to `0..100`

This normalized score is used in both domain findings and brand impersonation signals.

## 3) Keyword + Brand Impersonation (`domain_keywords.py`)

### Suspicious keyword matching

- substring matching against curated phishing keyword sets:
  - auth/login
  - urgency/threat
  - finance/payment
  - account recovery/actions
  - bait/scam terms
  - technical lure terms

### Brand impersonation logic

- tokenizes hostname labels/hyphen tokens
- applies leet normalization (`0->o`, `1->l`, `3->e`, etc.)
- checks:
  - direct leet brand equivalence
  - near-match with Levenshtein (`distance <= 2` or `similarity >= 78`)

Returns:

- impersonation signal text
- strength
- similarity

### Whitelist

Safe baseline domains reduce false positives:

- `google.com`
- `github.com`
- `microsoft.com`

Matching works on registrable domain and subdomains.

## 4) DNS + RDAP/WHOIS + VT Enrichment (`domain_intel.py`)

### DNS

Resolves record types:

- `A`, `AAAA`, `NS`, `MX`, `CNAME`, `TXT`

Returns:

- record map
- hit list
- resolver errors/timeouts

### RDAP / WHOIS

For domain and URL modes:

- registrar extraction (`vcardArray`)
- registration/update/expiry event parsing
- nameservers and port43

Domain age:

- parse registration timestamp
- compute age in days
- classify windows:
  - `0..14` very new
  - `15..30` new
  - `31..180` young
  - `180+` mature

### VirusTotal

Uses:

- `GET /api/v3/domains/{hostname}`

Extracts:

- `malicious`, `suspicious`, `harmless`, `undetected`, `reputation`

Result is cached in-process for performance.

## 5) URL Heuristic Detection (`domain_intel.py` + `scoring.py`)

URL analysis computes signals for:

- HTTP vs HTTPS
- raw IP host usage
- URL shortener host
- redirect chain depth
- mixed-script / IDN suspicion
- suspicious TLD (`.xyz`, `.top`, `.click`, `.shop`, `.buzz`, etc.)
- very long URL
- `@` symbol obfuscation
- subdomain depth
- uncommon ports (non-80/443)
- high query-parameter count
- encoded obfuscation tokens (`%40`, `%2f`, `%2e`, `%25`, `%3a`, `%3d`)
- suspicious keywords in host/path/query
- brand impersonation signal
- domain age (from RDAP)
- whitelist match

## 6) Scoring System (`scoring.py`)

All scores are additive with explicit breakdown lines, then clamped to `0..100`.

### URL score inputs (examples)

- HTTP: `+10`
- IP host: `+25`
- shortener: `+16`
- long redirects: `+14`
- mixed script: `+24`
- suspicious TLD: `+10`
- very long URL: up to `+10`
- `@` obfuscation: `+10`
- many subdomains/params: up to `+8`
- encoded obfuscation: up to `+10`
- host/path keywords: capped additions
- brand impersonation: dynamic base (`+25` + boosts)
- domain age:
  - `<=30 days`: `+20`
  - `<=90 days`: `+10`
- whitelist trust: `-25`

### VirusTotal logic (current)

Uses **ratio-based** malicious scoring:

```python
total = vt_malicious + vt_suspicious + vt_harmless
ratio = vt_malicious / total if total > 0 else 0
```

Thresholds:

- `vt_malicious >= 5` or `ratio > 0.2` -> `+25` and `VirusTotal strongly malicious`
- `vt_malicious >= 2` -> `+10` and `VirusTotal mildly suspicious`
- else -> ignored (noise filtering)

### Rule-based overrides

- brand impersonation + login-style keyword => force at least HIGH band
- IP host + no HTTPS => force at least HIGH band
- new domain (<=90d) + suspicious keywords => force at least HIGH band

### Risk bands

- `0..34` -> `LOW`
- `35..59` -> `MEDIUM`
- `60..79` -> `HIGH`
- `80..100` -> `CRITICAL`

## 7) Explainability Output

URL command prints:

1. Risk Summary
2. Reason
3. Score Breakdown
4. Indicators
5. DNS
6. Verdict

This makes the model behavior demo-friendly and auditable.

## Commands

## Install

gitclone https://github.com/Pranavvvv-09/PhishGuard

##create Virtual envirnment 
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

Optional `.env`:

```bash
VIRUSTOTAL_API_KEY="your_api_key_here"
```

## CLI Usage

```bash
python3 -m phishguard_py --help
```

Domain analysis:

```bash
python3 -m phishguard_py domain google.com --rdap --vt --max-variants 25 --top 5
```

URL analysis:

```bash
python3 -m phishguard_py url "http://g00gle-login.example" --dns --rdap --vt
```

Compare hosts:

```bash
python3 -m phishguard_py compare google.com g00gle.com
```

Report export:

```bash
python3 -m phishguard_py url "https://example.com" --out reports/url_report --formats json,csv,html
python3 -m phishguard_py domain google.com --out reports/domain_report --formats json,csv,html
```


