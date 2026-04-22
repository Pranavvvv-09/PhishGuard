# Contributing to PhishGuard

Thanks for your interest in contributing.

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run CLI help to verify setup:

```bash
python3 -m phishguard_py --help
```

## Contribution Scope

Good contribution areas:

- phishing detection heuristics and scoring improvements
- false-positive reduction logic
- report clarity and explainability
- docs and examples
- tests and reliability improvements

Out of scope:

- offensive payload generation
- exploit automation
- malicious abuse workflows

## Pull Request Guidelines

- Keep PRs focused and small.
- Explain why the change is needed.
- Include before/after behavior for scoring or detection changes.
- Update `README.md` if command behavior changes.
- Ensure the project still runs via CLI commands.

## Suggested Validation

```bash
python3 -m compileall phishguard_py
python3 -m phishguard_py domain google.com --no-vt --no-rdap
python3 -m phishguard_py url "http://example.com" --no-vt --no-rdap --dns
```
