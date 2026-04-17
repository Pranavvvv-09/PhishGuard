#!/usr/bin/env tsx

import { readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import chalk from "chalk";

import { analyzeDomainVariants } from "./domain-intelligence";
import { scanQrInputs } from "./qr-scanner";
import {
  writeDomainCsvReport,
  writeDomainHtmlReport,
  writeJsonReport,
  writeQrCsvReport,
  writeQrHtmlReport,
} from "./reporting";
import type { DomainAnalysisReport } from "./types";
import { ensureDirectory, parseDurationToMs, sleep } from "./utils";
import { generateDomainVariants } from "./variant-generator";
import {
  divider,
  logMessage,
  renderDomainOutput,
  renderQrOutput,
  runSpinnerStep,
  section,
  showBanner,
} from "./ui";

type ParsedArgs = {
  positionals: string[];
  flags: Record<string, string | boolean>;
};

function parseArgs(argv: string[]): ParsedArgs {
  const positionals: string[] = [];
  const flags: Record<string, string | boolean> = {};

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--")) {
      positionals.push(token);
      continue;
    }

    const key = token.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith("--")) {
      flags[key] = true;
      continue;
    }

    flags[key] = next;
    i += 1;
  }

  return { positionals, flags };
}

function parseNumberFlag(
  flags: Record<string, string | boolean>,
  key: string,
  fallback: number,
): number {
  const raw = flags[key];
  if (typeof raw !== "string") {
    return fallback;
  }
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parseFormats(
  flags: Record<string, string | boolean>,
  fallback: string[],
): string[] {
  const raw = flags.formats;
  if (typeof raw !== "string") {
    return fallback;
  }

  return raw
    .split(",")
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
}

function resolveMode(flags: Record<string, string | boolean>): "CLI" | "DEMO" {
  const rawFlag = flags.mode;
  if (typeof rawFlag === "string" && rawFlag.toLowerCase() === "demo") {
    return "DEMO";
  }
  if (Boolean(flags.demo)) {
    return "DEMO";
  }
  if (process.env.PHISHGUARD_MODE?.toLowerCase() === "demo") {
    return "DEMO";
  }
  return "CLI";
}

async function writeRawText(path: string, content: string): Promise<void> {
  await ensureDirectory(dirname(path));
  await writeFile(path, content, "utf8");
}

function printHelp(): void {
  section("Usage");
  console.log(chalk.white("tsx tools/phishing-cli/index.ts <command> [options]"));

  section("Commands");
  console.log(chalk.cyan("domain <legitimate-domain>"));
  console.log("  Scan typo-domain variants with Levenshtein similarity and reputation checks.");
  console.log("");
  console.log(chalk.cyan("qr-scan <input...>"));
  console.log("  Analyze URL/QR payloads for phishing patterns.");
  console.log("");
  console.log(chalk.cyan("batch <domains-file>"));
  console.log("  Analyze multiple domains from file (1 domain per line).");

  section("Options");
  console.log(chalk.white("--out <base-path>") + "     Output path (default: reports/<command>-report)");
  console.log(chalk.white("--formats <list>") + "      csv,json,html (default: json)");
  console.log(chalk.white("--demo") + "                Display DEMO mode in banner");

  section("Examples");
  console.log(chalk.white("tsx tools/phishing-cli/index.ts domain google.com --formats json,csv,html"));
  console.log(chalk.white("tsx tools/phishing-cli/index.ts qr-scan sample.png https://bit.ly/demo"));
  divider();
}

async function writeDomainReports(
  baseOutputPath: string,
  formats: string[],
  report: DomainAnalysisReport,
): Promise<void> {
  for (const format of formats) {
    const filePath = `${baseOutputPath}.${format}`;
    if (format === "json") {
      await writeJsonReport(filePath, report);
      continue;
    }
    if (format === "csv") {
      await writeDomainCsvReport(filePath, report);
      continue;
    }
    if (format === "html") {
      await writeDomainHtmlReport(filePath, report);
      continue;
    }
    logMessage("warning", `Unsupported format "${format}" skipped.`);
  }
}

async function writeQrReports(
  baseOutputPath: string,
  formats: string[],
  report: Awaited<ReturnType<typeof scanQrInputs>>,
): Promise<void> {
  for (const format of formats) {
    const filePath = `${baseOutputPath}.${format}`;
    if (format === "json") {
      await writeJsonReport(filePath, report);
      continue;
    }
    if (format === "csv") {
      await writeQrCsvReport(filePath, report);
      continue;
    }
    if (format === "html") {
      await writeQrHtmlReport(filePath, report);
      continue;
    }
    logMessage("warning", `Unsupported format "${format}" skipped.`);
  }
}

async function executeDomainAnalysis(
  legitimateDomain: string,
  flags: Record<string, string | boolean>,
): Promise<DomainAnalysisReport> {
  const maxVariants = parseNumberFlag(flags, "max-variants", 800);
  const concurrency = parseNumberFlag(flags, "concurrency", 10);
  const delayMs = parseNumberFlag(flags, "delay-ms", 40);
  const includeAll = Boolean(flags.all);

  await runSpinnerStep("Initializing scan engine...");

  const variants = (await runSpinnerStep("Generating domain variants...", async () =>
    generateDomainVariants(legitimateDomain, { maxVariants }),
  ))!;

  await runSpinnerStep("Checking DNS records...");
  await runSpinnerStep("Running similarity analysis...");

  const report = (await runSpinnerStep("Checking threat intelligence...", async () =>
    analyzeDomainVariants(legitimateDomain, variants, {
      registeredOnly: !includeAll,
      includeThreatFeeds: true,
      includeContentSimilarity: true,
      includeVirusTotal: !Boolean(flags["no-vt"]),
      concurrency,
      delayMs,
    }),
  ))!;

  await runSpinnerStep("Finalizing results...");
  return report;
}

async function runDomainCommand(parsed: ParsedArgs): Promise<void> {
  const legitimateDomain = parsed.positionals[0];
  if (!legitimateDomain) {
    throw new Error("Missing domain input. Example: domain google.com");
  }

  const formats = parseFormats(parsed.flags, ["json"]);
  const outBase = typeof parsed.flags.out === "string" ? parsed.flags.out : "reports/domain-report";
  const watchMode = Boolean(parsed.flags.watch);
  const intervalRaw = typeof parsed.flags.interval === "string" ? parsed.flags.interval : "15m";
  const intervalMs = parseDurationToMs(intervalRaw);

  const runOnce = async (): Promise<void> => {
    logMessage("info", `Target acquired: ${legitimateDomain}`);
    const report = await executeDomainAnalysis(legitimateDomain, parsed.flags);
    await writeDomainReports(outBase, formats, report);
    renderDomainOutput(report, outBase, formats);
  };

  if (!watchMode) {
    await runOnce();
    return;
  }

  while (true) {
    logMessage("info", `[watch] Starting scan at ${new Date().toISOString()}`);
    await runOnce();
    logMessage("info", `[watch] Sleeping ${intervalRaw}...`);
    await sleep(intervalMs);
  }
}

async function runBatchCommand(parsed: ParsedArgs): Promise<void> {
  const domainFile = parsed.positionals[0];
  if (!domainFile) {
    throw new Error("Missing domains file path. Example: batch domains.txt");
  }

  const formats = parseFormats(parsed.flags, ["json"]);
  const outBase = typeof parsed.flags.out === "string" ? parsed.flags.out : "reports/batch-domain-report";

  const file = await readFile(domainFile, "utf8");
  const domains = file
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));

  if (domains.length === 0) {
    throw new Error("No domains found in batch file.");
  }

  section("Batch Scan");
  logMessage("info", `Loaded ${domains.length} domains from ${domainFile}`);

  const reports: DomainAnalysisReport[] = [];
  for (const domain of domains) {
    logMessage("info", `Analyzing ${domain}`);
    const report = await executeDomainAnalysis(domain, parsed.flags);
    reports.push(report);
  }

  const merged = {
    analyzedAt: new Date().toISOString(),
    totalDomains: domains.length,
    reports,
  };

  for (const format of formats) {
    const filePath = `${outBase}.${format}`;
    if (format === "json") {
      await writeJsonReport(filePath, merged);
      continue;
    }
    if (format === "csv") {
      const header = "legitimate_domain,registered_variants,top_risk_score,top_variant";
      const rows = reports.map((entry) => {
        const top = entry.findings[0];
        return [
          entry.legitimateDomain,
          entry.registeredCandidates,
          top?.score ?? 0,
          top?.variant.asciiDomain ?? "",
        ].join(",");
      });
      await writeRawText(filePath, [header, ...rows].join("\n"));
      continue;
    }
    if (format === "html") {
      const blocks = reports
        .map((entry) => {
          const top = entry.findings[0];
          return `<tr><td>${entry.legitimateDomain}</td><td>${entry.registeredCandidates}</td><td>${top?.score ?? 0}</td><td>${top?.variant.asciiDomain ?? "-"}</td></tr>`;
        })
        .join("\n");
      const html = `<!doctype html><html><head><meta charset="utf-8"/><title>Batch Domain Report</title></head><body><h1>Batch Domain Report</h1><table border="1" cellspacing="0" cellpadding="6"><tr><th>Domain</th><th>Registered Variants</th><th>Top Score</th><th>Top Variant</th></tr>${blocks}</table></body></html>`;
      await writeRawText(filePath, html);
      continue;
    }
    logMessage("warning", `Unsupported format "${format}" skipped.`);
  }

  logMessage("success", `Batch report written: ${outBase}.{${formats.join(",")}}`);
  divider();
}

async function runQrScanCommand(parsed: ParsedArgs): Promise<void> {
  const formats = parseFormats(parsed.flags, ["json"]);
  const outBase = typeof parsed.flags.out === "string" ? parsed.flags.out : "reports/qr-scan-report";
  const inputFile = typeof parsed.flags["input-file"] === "string" ? parsed.flags["input-file"] : undefined;

  let inputs = [...parsed.positionals];
  if (inputFile) {
    const extra = await readFile(inputFile, "utf8");
    inputs = inputs.concat(
      extra
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean),
    );
  }

  if (inputs.length === 0) {
    throw new Error("No QR inputs provided. Pass image paths, URLs, or --input-file.");
  }

  logMessage("info", `Payload queue length: ${inputs.length}`);
  await runSpinnerStep("Initializing scan engine...");
  await runSpinnerStep("Generating domain variants...");
  await runSpinnerStep("Checking DNS records...");
  await runSpinnerStep("Running similarity analysis...");
  const report = (await runSpinnerStep("Checking threat intelligence...", async () =>
    scanQrInputs(inputs),
  ))!;
  await runSpinnerStep("Finalizing results...");

  await writeQrReports(outBase, formats, report);
  await renderQrOutput(report, outBase, formats);
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const command = argv[0];
  const parsed = parseArgs(argv.slice(1));
  const mode = resolveMode(parsed.flags);
  const version = process.env.npm_package_version ?? "0.1.0";

  await showBanner(version, mode);

  if (!command || command === "help" || command === "--help" || command === "-h") {
    printHelp();
    return;
  }

  if (command === "domain") {
    await runDomainCommand(parsed);
    return;
  }

  if (command === "batch") {
    await runBatchCommand(parsed);
    return;
  }

  if (command === "qr-scan") {
    await runQrScanCommand(parsed);
    return;
  }

  throw new Error(`Unknown command "${command}". Run with --help for usage.`);
}

main().catch((error) => {
  logMessage("critical", error instanceof Error ? error.message : "Unknown error");
  divider();
  process.exitCode = 1;
});
