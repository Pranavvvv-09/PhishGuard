from __future__ import annotations

import csv
from pathlib import Path
from typing import List, Sequence

from jinja2 import BaseLoader, Environment, select_autoescape
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .models import DomainAnalysisReport, UrlAnalysisReport
from .utils import ensure_parent_dir, safe_json_dumps


def _risk_color(level: str) -> str:
    mapping = {
        "low": "green",
        "medium": "yellow",
        "high": "orange3",
        "critical": "red",
    }
    return mapping.get(level.lower(), "white")


def render_domain_console(report: DomainAnalysisReport, top: int = 5, console: Console | None = None) -> None:
    console = console or Console()
    findings = report.findings
    avg_score = round(sum(item.score for item in findings) / len(findings), 2) if findings else 0.0

    summary_grid = Table.grid(expand=True)
    summary_grid.add_column(justify="left")
    summary_grid.add_column(justify="left")
    summary_grid.add_column(justify="left")
    summary_grid.add_column(justify="left")
    summary_grid.add_row(
        "[bold cyan]Target[/bold cyan]",
        report.legitimateDomain,
        "[bold cyan]Generated[/bold cyan]",
        str(report.candidatesGenerated),
    )
    summary_grid.add_row(
        "[bold cyan]Evaluated[/bold cyan]",
        str(report.candidatesEvaluated),
        "[bold cyan]Registered[/bold cyan]",
        str(report.registeredCandidates),
    )
    summary_grid.add_row(
        "[bold cyan]Average score[/bold cyan]",
        str(avg_score),
        "[bold cyan]Showing top[/bold cyan]",
        str(min(top, len(findings) if findings else top)),
    )
    console.print(Panel(summary_grid, title="Domain Threat Dashboard", border_style="bright_blue"))

    table = Table(title=f"Top Findings (Top {top})", header_style="bold cyan", box=box.SIMPLE_HEAVY)
    table.add_column("Rank", justify="right", width=5)
    table.add_column("Variant", overflow="fold")
    table.add_column("Technique", style="magenta")
    table.add_column("Similarity", justify="right")
    table.add_column("LevDist", justify="right")
    table.add_column("Score", justify="right")
    table.add_column("Risk", justify="center")
    table.add_column("DNS", justify="center")
    table.add_column("WHOIS", justify="center")
    table.add_column("Keyword Hits", overflow="fold")
    table.add_column("Brand Signal", overflow="fold")

    if not report.findings:
        table.add_row("-", "No suspicious registered variants found.", "-", "-", "-", "-", "-", "-", "-", "-", "-")
    else:
        for index, finding in enumerate(report.findings[:top], start=1):
            level = finding.level.upper()
            risk_style = _risk_color(finding.level)
            dns_status = "Found" if finding.registration.dnsRecordTypes else "Not Found"
            whois_status = "Found" if finding.registration.whois else "Not Found"
            table.add_row(
                str(index),
                finding.variant.displayDomain,
                finding.variant.technique,
                f"{finding.variant.similarity:.2f}%",
                str(finding.variant.levenshteinDistance),
                str(finding.score),
                f"[{risk_style}]{level}[/{risk_style}]",
                dns_status,
                whois_status,
                ", ".join(finding.intelligence.suspiciousKeywords) if finding.intelligence.suspiciousKeywords else "-",
                finding.intelligence.brandImpersonationSignal or "-",
            )

    console.print(table)

    if report.findings:
        top_finding = report.findings[0]
        color = _risk_color(top_finding.level)
        indicator_text = (
            "\n".join(f"[yellow][!][/yellow] {item}" for item in top_finding.indicators[:6])
            or "[cyan][*][/cyan] No indicators"
        )
        console.print(
            Panel(
                indicator_text,
                title=f"Highest Impact: {top_finding.variant.displayDomain} ({top_finding.level.upper()})",
                border_style=color,
            )
        )


def render_url_console(report: UrlAnalysisReport, console: Console | None = None) -> None:
    console = console or Console()
    color = _risk_color(report.level)

    summary = Table.grid(expand=True)
    summary.add_column(justify="left")
    summary.add_column(justify="left")
    summary.add_row("[bold]URL[/bold]", report.finalUrl)
    summary.add_row("[bold]Host[/bold]", report.hostname)
    summary.add_row("[bold]Score[/bold]", str(report.score))
    summary.add_row("[bold]Risk[/bold]", f"[{color}]{report.level.upper()}[/{color}]")
    console.print(Panel(summary, title="Risk Summary", border_style=color))

    reason_text = "\n".join(f"- {line}" for line in report.reasons) if report.reasons else "- No strong risk reason."
    console.print(Panel(reason_text, title="Reason", border_style="yellow"))

    breakdown_text = (
        "\n".join(f"- {line}" for line in report.scoreBreakdown)
        if report.scoreBreakdown
        else "- No score components available."
    )
    console.print(Panel(breakdown_text, title="Score Breakdown", border_style="magenta"))

    indicator_text = (
        "\n".join(f"- {line}" for line in report.indicators) if report.indicators else "- No indicators found."
    )
    console.print(Panel(indicator_text, title="Indicators", border_style="cyan"))

    if report.ruleOverrides:
        override_text = "\n".join(f"- {line}" for line in report.ruleOverrides)
        console.print(Panel(override_text, title="Rule Overrides", border_style="red"))

    dns_table = Table(box=box.SIMPLE, header_style="bold cyan")
    dns_table.add_column("Record")
    dns_table.add_column("Status")
    if report.dnsRecordTypes:
        for record_type in report.dnsRecordTypes:
            dns_table.add_row(record_type, "Found")
    else:
        dns_table.add_row("DNS", "Unavailable (skipped/not found)")
    if report.dnsErrors:
        dns_table.add_row("Errors", ", ".join(report.dnsErrors[:3]))
    console.print(Panel(dns_table, title="DNS", border_style="blue"))

    verdict = Table.grid(expand=True)
    verdict.add_column(justify="left")
    verdict.add_row(report.verdict)
    for tip in report.recommendations[:3]:
        verdict.add_row(f"- {tip}")
    console.print(Panel(verdict, title="Verdict", border_style=color))


def write_structured_report(
    report: DomainAnalysisReport | UrlAnalysisReport,
    kind: str,
    output_base: str,
    formats: Sequence[str],
) -> List[Path]:
    kind_norm = kind.lower()
    if kind_norm not in {"domain", "url"}:
        raise ValueError("Only 'domain' and 'url' report kinds are supported.")

    base_path = Path(output_base)
    if base_path.suffix:
        base_path = base_path.with_suffix("")

    written: List[Path] = []
    payload = report.model_dump(mode="json")
    env = Environment(loader=BaseLoader(), autoescape=select_autoescape(default=True))

    for fmt in formats:
        fmt_lower = fmt.lower()
        target = base_path.with_suffix(f".{fmt_lower}")
        ensure_parent_dir(target)

        if fmt_lower == "json":
            target.write_text(safe_json_dumps(payload), encoding="utf-8")
            written.append(target)
            continue

        if fmt_lower == "csv":
            if kind_norm == "domain" and isinstance(report, DomainAnalysisReport):
                _write_domain_csv(target, report)
            elif kind_norm == "url" and isinstance(report, UrlAnalysisReport):
                _write_url_csv(target, report)
            written.append(target)
            continue

        if fmt_lower == "html":
            if kind_norm == "domain" and isinstance(report, DomainAnalysisReport):
                _write_domain_html(target, report, env)
            elif kind_norm == "url" and isinstance(report, UrlAnalysisReport):
                _write_url_html(target, report, env)
            written.append(target)

    return written


def _write_domain_csv(path: Path, report: DomainAnalysisReport) -> None:
    rows = []
    for finding in report.findings:
        rows.append(
            {
                "variant": finding.variant.displayDomain,
                "technique": finding.variant.technique,
                "similarity": finding.variant.similarity,
                "levenshtein_distance": finding.variant.levenshteinDistance,
                "score": finding.score,
                "risk_level": finding.level,
                "is_registered": finding.registration.isRegistered,
                "keyword_hits": ",".join(finding.intelligence.suspiciousKeywords),
                "brand_signal": finding.intelligence.brandImpersonationSignal or "",
                "registrar": finding.intelligence.registrar or "",
                "registration_date": finding.intelligence.registrationDate or "",
                "network_provider": finding.intelligence.networkProvider or "",
                "indicators": " | ".join(finding.indicators),
            }
        )

    headers = [
        "variant",
        "technique",
        "similarity",
        "levenshtein_distance",
        "score",
        "risk_level",
        "is_registered",
        "keyword_hits",
        "brand_signal",
        "registrar",
        "registration_date",
        "network_provider",
        "indicators",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def _write_url_csv(path: Path, report: UrlAnalysisReport) -> None:
    headers = [
        "input_url",
        "final_url",
        "hostname",
        "score",
        "risk_level",
        "is_https",
        "is_ip_host",
        "domain_age_days",
        "whitelist_matched",
        "redirect_hops",
        "dns_records",
        "reasons",
        "indicators",
        "score_breakdown",
        "rule_overrides",
        "verdict",
    ]
    row = {
        "input_url": report.inputUrl,
        "final_url": report.finalUrl,
        "hostname": report.hostname,
        "score": report.score,
        "risk_level": report.level,
        "is_https": report.isHttps,
        "is_ip_host": report.isIpHost,
        "domain_age_days": report.domainAgeDays if report.domainAgeDays is not None else "",
        "whitelist_matched": report.whitelistMatched,
        "redirect_hops": report.redirectHops,
        "dns_records": ",".join(report.dnsRecordTypes),
        "reasons": " | ".join(report.reasons),
        "indicators": " | ".join(report.indicators),
        "score_breakdown": " | ".join(report.scoreBreakdown),
        "rule_overrides": " | ".join(report.ruleOverrides),
        "verdict": report.verdict,
    }
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerow(row)


def _write_domain_html(path: Path, report: DomainAnalysisReport, env: Environment) -> None:
    template = env.from_string(
        """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>PhishGuard Domain Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; background: #0f172a; color: #e2e8f0; }
    h1 { margin-bottom: 8px; }
    .meta { color: #94a3b8; margin-bottom: 16px; }
    table { border-collapse: collapse; width: 100%; background: #111827; }
    th, td { border: 1px solid #334155; padding: 8px; text-align: left; vertical-align: top; }
    th { background: #1e293b; }
  </style>
</head>
<body>
  <h1>PhishGuard Domain Report</h1>
  <div class="meta">Domain: {{ report.legitimateDomain }} | Generated: {{ report.candidatesGenerated }} | Registered: {{ report.registeredCandidates }}</div>
  <table>
    <thead>
      <tr>
        <th>Variant</th><th>Technique</th><th>Similarity</th><th>Levenshtein Distance</th><th>Score</th><th>Risk</th><th>Keyword Hits</th><th>Brand Signal</th><th>Registrar</th><th>Registered At</th><th>Indicators</th>
      </tr>
    </thead>
    <tbody>
    {% for f in report.findings %}
      <tr>
        <td>{{ f.variant.displayDomain }}</td>
        <td>{{ f.variant.technique }}</td>
        <td>{{ '%.2f'|format(f.variant.similarity) }}%</td>
        <td>{{ f.variant.levenshteinDistance }}</td>
        <td>{{ f.score }}</td>
        <td>{{ f.level }}</td>
        <td>{{ f.intelligence.suspiciousKeywords|join(',') if f.intelligence.suspiciousKeywords else '-' }}</td>
        <td>{{ f.intelligence.brandImpersonationSignal or '-' }}</td>
        <td>{{ f.intelligence.registrar or '-' }}</td>
        <td>{{ f.intelligence.registrationDate or '-' }}</td>
        <td>{{ f.indicators|join(' | ') }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
</body>
</html>
        """
    )
    path.write_text(template.render(report=report), encoding="utf-8")


def _write_url_html(path: Path, report: UrlAnalysisReport, env: Environment) -> None:
    template = env.from_string(
        """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>PhishGuard URL Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; background: #0f172a; color: #e2e8f0; }
    h1 { margin-bottom: 8px; }
    .meta { color: #94a3b8; margin-bottom: 16px; }
    ul { line-height: 1.5; }
  </style>
</head>
<body>
  <h1>PhishGuard URL Report</h1>
  <div class="meta">Input: {{ report.inputUrl }} | Final: {{ report.finalUrl }} | Host: {{ report.hostname }}</div>
  <p><strong>Score:</strong> {{ report.score }} | <strong>Risk:</strong> {{ report.level.upper() }}</p>
  <p><strong>Domain Age Days:</strong> {{ report.domainAgeDays if report.domainAgeDays is not none else 'Unavailable' }}</p>
  <p><strong>Whitelist Matched:</strong> {{ report.whitelistMatched }}</p>
  <p><strong>Verdict:</strong> {{ report.verdict }}</p>
  <h3>Reasons</h3>
  <ul>{% for r in report.reasons %}<li>{{ r }}</li>{% endfor %}</ul>
  <h3>Indicators</h3>
  <ul>{% for i in report.indicators %}<li>{{ i }}</li>{% endfor %}</ul>
  <h3>Score Breakdown</h3>
  <ul>{% for s in report.scoreBreakdown %}<li>{{ s }}</li>{% endfor %}</ul>
  {% if report.ruleOverrides %}
  <h3>Rule Overrides</h3>
  <ul>{% for o in report.ruleOverrides %}<li>{{ o }}</li>{% endfor %}</ul>
  {% endif %}
</body>
</html>
        """
    )
    path.write_text(template.render(report=report), encoding="utf-8")
