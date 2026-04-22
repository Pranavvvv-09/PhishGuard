from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Optional

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .domain_keywords import DEFAULT_BRANDS, DEFAULT_SUSPICIOUS_KEYWORDS, load_indicator_list
from .domain_intel import analyze_domain_variants, analyze_suspicious_url
from .reporting import render_domain_console, render_url_console, write_structured_report
from .utils import levenshtein_metrics, normalize_host_input, parse_domain_parts, parse_formats
from .variant_generator import generate_domain_variants

app = typer.Typer(
    name="phishguard-py",
    add_completion=False,
    no_args_is_help=True,
    help="PhishGuard Python CLI: domain typosquatting and URL phishing analysis.",
)
console = Console()

ASCII_BANNER = r"""
 ____  _   _ ___ ____  _   _  ____ _   _   _    ____  ____  
|  _ \| | | |_ _/ ___|| | | |/ ___| | | | / \  |  _ \|  _ \ 
| |_) | |_| || |\___ \| |_| | |  _| | | |/ _ \ | |_) | | | |
|  __/|  _  || | ___) |  _  | |_| | |_| / ___ \|  _ <| |_| |
|_|   |_| |_|___|____/|_| |_|\____|\___/_/   \_\_| \_\____/ 
"""


@app.callback()
def app_callback() -> None:
    """PhishGuard command group."""


def _risk_style(level: str) -> str:
    mapping = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "orange3", "CRITICAL": "red"}
    return mapping.get(level.upper(), "cyan")


def _log_info(message: str) -> None:
    console.print(f"[cyan][*][/cyan] {message}")


def _log_success(message: str) -> None:
    console.print(f"[green][+][/green] {message}")


def _log_critical(message: str) -> None:
    console.print(f"[red][x][/red] {message}")


def _render_banner(mode: str) -> None:
    colors = ["bright_cyan", "cyan", "deep_sky_blue1", "blue", "bright_blue"]
    for idx, line in enumerate(ASCII_BANNER.strip("\n").splitlines()):
        color = colors[idx % len(colors)]
        console.print(f"[{color}]{line}[/{color}]")

    meta = Table.grid(expand=True)
    meta.add_column(justify="left")
    meta.add_column(justify="right")
    meta.add_row("[bold]Domain & URL Phishing Detection[/bold]", f"[bold]v{__version__}[/bold]")
    meta.add_row("[dim]Mode[/dim]", f"[bold cyan]{mode}[/bold cyan]")
    console.print(Panel(meta, border_style="bright_blue", padding=(0, 1)))


def _render_features(vt_enabled: bool, vt_key_present: bool, rdap_enabled: bool, dns_enabled: bool) -> None:
    table = Table.grid(expand=True)
    table.add_column(justify="left")
    table.add_column(justify="left")
    vt_state = "ON (.env)" if vt_enabled and vt_key_present else ("OFF (missing .env key)" if vt_enabled else "OFF")
    vt_style = "green" if vt_enabled and vt_key_present else "yellow"
    rdap_style = "green" if rdap_enabled else "yellow"
    dns_style = "green" if dns_enabled else "yellow"

    table.add_row(f"[bold]VirusTotal[/bold]: [{vt_style}]{vt_state}[/{vt_style}]")
    table.add_row(f"[bold]RDAP/WHOIS[/bold]: [{rdap_style}]{'ON' if rdap_enabled else 'OFF'}[/{rdap_style}]")
    table.add_row(f"[bold]DNS[/bold]: [{dns_style}]{'ON' if dns_enabled else 'OFF'}[/{dns_style}]")
    table.add_row("[bold]Levenshtein Similarity[/bold]: [green]ON[/green]")
    table.add_row("[bold]Keyword/Brand Logic[/bold]: [green]ON[/green]")
    console.print(Panel(table, title="Features", border_style="cyan"))


def _print_error(message: str) -> None:
    _log_critical(message)
    console.print(Panel.fit(f"[red]{message}[/red]", title="Error", border_style="red"))


def _print_completion(score: int | None = None, level: str | None = None) -> None:
    if score is None or level is None:
        _log_success("Scan complete")
        return
    style = _risk_style(level)
    console.print(
        Panel.fit(
            f"[bold]Risk:[/bold] [{style}]{level.upper()}[/{style}]   [bold]Score:[/bold] {score}/100",
            title="Result",
            border_style=style,
        )
    )


@app.command("domain")
def domain_command(
    target: str = typer.Argument(..., help="Legitimate domain or URL to analyze."),
    max_variants: int = typer.Option(
        25,
        "--max-variants",
        min=20,
        max=25,
        help="Bounded typo variant generation cap (20-25).",
    ),
    top: int = typer.Option(5, "--top", min=3, max=5, help="Show top dangerous findings."),
    rdap: bool = typer.Option(True, "--rdap/--no-rdap", help="Enable RDAP/WHOIS enrichment."),
    vt: bool = typer.Option(True, "--vt/--no-vt", help="Enable VirusTotal enrichment (if API key set)."),
    keywords_file: Optional[Path] = typer.Option(
        None,
        "--keywords-file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Optional suspicious keywords file (one keyword per line).",
    ),
    brands_file: Optional[Path] = typer.Option(
        None,
        "--brands-file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Optional brand keywords file (one brand per line).",
    ),
    out: Optional[str] = typer.Option(None, "--out", help="Output base path for report export."),
    formats: str = typer.Option("json", "--formats", help="Comma list: json,csv,html"),
    concurrency: int = typer.Option(10, "--concurrency", min=1, max=30, help="Concurrent lookup workers."),
) -> None:
    """Analyze bounded typo variants for a target domain."""
    load_dotenv()
    vt_key_present = bool(os.getenv("VIRUSTOTAL_API_KEY"))
    vt_effective = vt and vt_key_present
    suspicious_keywords = load_indicator_list(keywords_file, list(DEFAULT_SUSPICIOUS_KEYWORDS))
    brand_keywords = load_indicator_list(brands_file, list(DEFAULT_BRANDS))

    try:
        normalized = parse_domain_parts(target).registrableDomain
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    _render_banner("CLI / DOMAIN")
    _render_features(vt_effective, vt_key_present, rdap, True)
    console.rule("[bold cyan]Scan Pipeline")
    _log_info("Running analysis...")

    try:
        with console.status("[cyan]Running analysis...[/cyan]", spinner="dots"):
            variants = generate_domain_variants(normalized, max_variants=max_variants)
            report = asyncio.run(
                analyze_domain_variants(
                    normalized,
                    variants,
                    include_rdap=rdap,
                    include_virustotal=vt_effective,
                    suspicious_keywords=suspicious_keywords,
                    brand_keywords=brand_keywords,
                    registered_only=True,
                    concurrency=concurrency,
                )
            )
        _log_success("Scan complete")

        console.rule("[bold cyan]Threat Dashboard")
        render_domain_console(report, top=top, console=console)
        if report.findings:
            highest = report.findings[0]
            _print_completion(highest.score, highest.level)
        else:
            _print_completion()

        if out:
            selected_formats = parse_formats(formats)
            written = write_structured_report(report, "domain", out, selected_formats)
            saved = "\n".join(f"- {path}" for path in written)
            console.print(Panel.fit(f"[green]Saved reports:[/green]\n{saved}", border_style="green"))
    except Exception as exc:
        _print_error(f"Domain scan failed: {exc}")
        raise typer.Exit(code=1) from exc


@app.command("url")
def url_command(
    target: str = typer.Argument(..., help="Suspicious URL to analyze."),
    rdap: bool = typer.Option(True, "--rdap/--no-rdap", help="Enable RDAP/WHOIS enrichment."),
    dns: bool = typer.Option(True, "--dns/--no-dns", help="Enable DNS enrichment."),
    vt: bool = typer.Option(True, "--vt/--no-vt", help="Enable VirusTotal enrichment (if API key set)."),
    keywords_file: Optional[Path] = typer.Option(
        None,
        "--keywords-file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Optional suspicious keywords file (one keyword per line).",
    ),
    brands_file: Optional[Path] = typer.Option(
        None,
        "--brands-file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Optional brand keywords file (one brand per line).",
    ),
    out: Optional[str] = typer.Option(None, "--out", help="Output base path for report export."),
    formats: str = typer.Option("json", "--formats", help="Comma list: json,csv,html"),
) -> None:
    """Analyze a single URL for phishing indicators."""
    load_dotenv()
    vt_key_present = bool(os.getenv("VIRUSTOTAL_API_KEY"))
    vt_effective = vt and vt_key_present
    suspicious_keywords = load_indicator_list(keywords_file, list(DEFAULT_SUSPICIOUS_KEYWORDS))
    brand_keywords = load_indicator_list(brands_file, list(DEFAULT_BRANDS))

    _render_banner("CLI / URL")
    _render_features(vt_effective, vt_key_present, rdap, dns)
    console.rule("[bold cyan]Scan Pipeline")
    _log_info("Running analysis...")

    try:
        with console.status("[cyan]Running analysis...[/cyan]", spinner="dots"):
            report = asyncio.run(
                analyze_suspicious_url(
                    target,
                    include_dns=dns,
                    include_rdap=rdap,
                    include_virustotal=vt_effective,
                    suspicious_keywords=suspicious_keywords,
                    brand_keywords=brand_keywords,
                )
            )
        _log_success("Scan complete")

        console.rule("[bold cyan]Threat Dashboard")
        render_url_console(report, console=console)
        _print_completion(report.score, report.level)

        if out:
            selected_formats = parse_formats(formats)
            written = write_structured_report(report, "url", out, selected_formats)
            saved = "\n".join(f"- {path}" for path in written)
            console.print(Panel.fit(f"[green]Saved reports:[/green]\n{saved}", border_style="green"))
    except Exception as exc:
        _print_error(f"URL scan failed: {exc}")
        raise typer.Exit(code=1) from exc


@app.command("compare")
def compare_command(
    a: str = typer.Argument(..., help="First domain or URL."),
    b: str = typer.Argument(..., help="Second domain or URL."),
) -> None:
    """Compare two hosts using Levenshtein-based similarity."""
    try:
        host_a = normalize_host_input(a)
        host_b = normalize_host_input(b)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    distance, similarity, normalized_a, normalized_b = levenshtein_metrics(host_a, host_b)
    suspicious_hint = "Possible lookalike / impersonation pattern" if distance <= 2 or similarity >= 78 else "Low lookalike confidence"

    table = Table(title="Compare Result", header_style="bold cyan")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("A", host_a)
    table.add_row("B", host_b)
    table.add_row("Normalized A", normalized_a)
    table.add_row("Normalized B", normalized_b)
    table.add_row("Levenshtein Distance", str(distance))
    table.add_row("Similarity", f"{similarity}%")
    table.add_row("Hint", suspicious_hint)
    console.print(table)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
