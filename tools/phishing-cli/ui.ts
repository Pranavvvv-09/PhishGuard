import { resolve } from "node:dns/promises";

import boxen from "boxen";
import chalk from "chalk";
import Table from "cli-table3";
import figlet from "figlet";
import gradient from "gradient-string";
import ora from "ora";

import type {
  DomainAnalysisReport,
  DomainFinding,
  QrScanReport,
  QuishingUrlAnalysis,
  RiskLevel,
} from "./types";
import { sleep } from "./utils";

const DIVIDER = chalk.gray("=".repeat(78));
const DNS_TABLE_TYPES = ["A", "MX", "NS", "TXT", "CNAME"] as const;

type LogLevel = "info" | "success" | "warning" | "critical";

function randomDelay(minMs = 200, maxMs = 600): number {
  return Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
}

function levelColor(level: RiskLevel) {
  if (level === "low") {
    return chalk.green;
  }
  if (level === "medium") {
    return chalk.yellow;
  }
  if (level === "high") {
    return chalk.hex("#ff9f1a");
  }
  return chalk.redBright;
}

function levelTag(level: RiskLevel): string {
  return level.toUpperCase();
}

function boxColor(level: RiskLevel): "green" | "yellow" | "red" | "cyan" {
  if (level === "low") {
    return "green";
  }
  if (level === "medium" || level === "high") {
    return "yellow";
  }
  if (level === "critical") {
    return "red";
  }
  return "cyan";
}

export function divider(): void {
  console.log(DIVIDER);
}

export function section(title: string): void {
  console.log("");
  console.log(chalk.bold.cyan(`[ ${title} ]`));
  console.log(chalk.gray("-".repeat(Math.max(22, title.length + 8))));
}

export function logMessage(level: LogLevel, message: string): void {
  if (level === "info") {
    console.log(chalk.cyan(`[*] ${message}`));
    return;
  }
  if (level === "success") {
    console.log(chalk.green(`[+] ${message}`));
    return;
  }
  if (level === "warning") {
    console.log(chalk.yellow(`[!] ${message}`));
    return;
  }
  console.log(chalk.red(`[x] ${message}`));
}

export async function showBanner(version: string, mode: "CLI" | "DEMO"): Promise<void> {
  const banner = figlet.textSync("PHISHGUARD", {
    horizontalLayout: "full",
    verticalLayout: "default",
  });

  console.log("");
  console.log(gradient(["#00f5d4", "#00bbf9", "#9b5de5"]).multiline(banner));
  console.log(chalk.bold.white("Domain & QR Phishing Detection Tool"));
  console.log(
    `${chalk.gray("Version:")} ${chalk.white(version)}   ${chalk.gray("Mode:")} ${chalk.bold.cyan(mode)}`,
  );
  divider();
  await sleep(150);
}

export async function runSpinnerStep<T>(label: string, task?: () => Promise<T>): Promise<T | undefined> {
  const spinner = ora({
    text: chalk.cyan(label),
    color: "cyan",
  }).start();

  try {
    await sleep(randomDelay());
    const result = task ? await task() : undefined;
    spinner.succeed(chalk.green(label.replace("...", "")));
    return result;
  } catch (error) {
    spinner.fail(chalk.red(label.replace("...", "")));
    throw error;
  }
}

function shortExplanation(indicators: string[]): string {
  if (indicators.length === 0) {
    return "No explicit phishing indicators were detected by current checks.";
  }
  return indicators.slice(0, 2).join(" | ");
}

function renderSummaryBox(target: string, level: RiskLevel, score: number, explanation: string): void {
  const color = levelColor(level);
  const body = [
    `${chalk.gray("Target:")} ${chalk.white(target)}`,
    `${chalk.gray("Risk:")} ${color.bold(levelTag(level))}`,
    `${chalk.gray("Score:")} ${color.bold(`${score}/100`)}`,
    `${chalk.gray("Why:")} ${color(explanation)}`,
  ].join("\n");

  console.log(
    boxen(body, {
      padding: 1,
      borderStyle: "round",
      borderColor: boxColor(level),
      title: "Risk Summary",
      titleAlignment: "left",
    }),
  );
}

function renderIndicators(indicators: string[]): void {
  section("Indicators");
  if (indicators.length === 0) {
    logMessage("success", "No suspicious indicators detected.");
    return;
  }

  for (const indicator of indicators) {
    console.log(`${chalk.yellow("⚠")} ${chalk.white(indicator)}`);
  }
}

function renderDnsTableFromFinding(finding: DomainFinding): void {
  section("DNS Table");
  const found = new Set(finding.registration.dnsRecordTypes.map((item) => item.toUpperCase()));

  const table = new Table({
    head: [chalk.cyan("Record"), chalk.cyan("Value")],
    colWidths: [14, 44],
    style: { head: [], border: [] },
  });

  for (const recordType of DNS_TABLE_TYPES) {
    if (recordType === "TXT") {
      table.push([recordType, chalk.gray("Unavailable")]);
      continue;
    }
    table.push([recordType, found.has(recordType) ? chalk.green("Found") : chalk.red("Not found")]);
  }

  console.log(table.toString());
}

async function renderDnsTableForHostname(hostname: string): Promise<void> {
  section("DNS Table");
  const table = new Table({
    head: [chalk.cyan("Record"), chalk.cyan("Value")],
    colWidths: [14, 44],
    style: { head: [], border: [] },
  });

  for (const recordType of DNS_TABLE_TYPES) {
    try {
      const results = (await resolve(hostname, recordType)) as unknown[];
      table.push([
        recordType,
        results.length > 0 ? chalk.green("Found") : chalk.red("Not found"),
      ]);
    } catch {
      if (recordType === "TXT") {
        table.push([recordType, chalk.gray("Unavailable")]);
      } else {
        table.push([recordType, chalk.red("Not found")]);
      }
    }
  }

  console.log(table.toString());
}

export function renderDomainOutput(report: DomainAnalysisReport, outBase: string, formats: string[]): void {
  section("Scan Summary");
  logMessage("success", `Generated variants: ${report.candidatesGenerated}`);
  logMessage("success", `Evaluated variants: ${report.candidatesEvaluated}`);
  logMessage("success", `Registered variants: ${report.registeredCandidates}`);

  const top = report.findings[0];
  if (!top) {
    logMessage("warning", "No suspicious registered variants found in this scan.");
    logMessage("info", `Reports written: ${outBase}.{${formats.join(",")}}`);
    divider();
    return;
  }

  const explanation = shortExplanation(top.indicators);
  console.log("");
  renderSummaryBox(top.variant.asciiDomain, top.level, top.score, explanation);
  renderIndicators(top.indicators);
  renderDnsTableFromFinding(top);

  section("Top Findings");
  const table = new Table({
    head: [chalk.cyan("Variant"), chalk.cyan("Technique"), chalk.cyan("Score"), chalk.cyan("Risk")],
    colWidths: [35, 18, 10, 12],
    style: { head: [], border: [] },
  });

  for (const finding of report.findings.slice(0, 8)) {
    table.push([
      finding.variant.asciiDomain,
      finding.variant.technique,
      String(finding.score),
      levelColor(finding.level)(levelTag(finding.level)),
    ]);
  }
  console.log(table.toString());
  logMessage("info", `Reports written: ${outBase}.{${formats.join(",")}}`);
  divider();
}

function pickTopQrAnalysis(report: QrScanReport): { source: string; analysis: QuishingUrlAnalysis } | undefined {
  const scored = report.findings
    .filter((entry) => entry.analysis)
    .map((entry) => ({
      source: entry.decodedPayload || entry.source,
      analysis: entry.analysis as QuishingUrlAnalysis,
    }))
    .sort((a, b) => b.analysis.score - a.analysis.score);
  return scored[0];
}

export async function renderQrOutput(
  report: QrScanReport,
  outBase: string,
  formats: string[],
): Promise<void> {
  section("Scan Summary");
  logMessage("success", `Inputs scanned: ${report.totalInputs}`);
  logMessage("success", `Payloads decoded: ${report.decodedCount}`);
  const flagged = report.findings.filter((entry) => (entry.analysis?.score ?? 0) >= 35).length;
  if (flagged > 0) {
    logMessage("warning", `Potentially suspicious payloads: ${flagged}`);
  } else {
    logMessage("success", "No suspicious payload crossed risk threshold.");
  }

  const top = pickTopQrAnalysis(report);
  if (!top) {
    logMessage("warning", "No URL payload was available for threat scoring.");
    logMessage("info", `Reports written: ${outBase}.{${formats.join(",")}}`);
    divider();
    return;
  }

  console.log("");
  renderSummaryBox(
    top.analysis.finalUrl ?? top.source,
    top.analysis.level,
    top.analysis.score,
    shortExplanation(top.analysis.suspiciousIndicators),
  );
  renderIndicators(top.analysis.suspiciousIndicators);

  try {
    const host = new URL(top.analysis.finalUrl ?? top.source).hostname.toLowerCase();
    await renderDnsTableForHostname(host);
    logMessage("success", "DNS lookup complete");
  } catch {
    logMessage("warning", "DNS table unavailable for top payload.");
  }

  section("Top Payloads");
  const table = new Table({
    head: [chalk.cyan("Payload"), chalk.cyan("Score"), chalk.cyan("Risk")],
    colWidths: [58, 10, 12],
    style: { head: [], border: [] },
  });

  const ranked = report.findings
    .filter((entry) => entry.analysis)
    .sort((a, b) => (b.analysis?.score ?? 0) - (a.analysis?.score ?? 0))
    .slice(0, 8);

  for (const finding of ranked) {
    const analysis = finding.analysis as QuishingUrlAnalysis;
    table.push([
      (analysis.finalUrl ?? finding.decodedPayload ?? finding.source).slice(0, 55),
      String(analysis.score),
      levelColor(analysis.level)(levelTag(analysis.level)),
    ]);
  }

  console.log(table.toString());
  logMessage("info", `Reports written: ${outBase}.{${formats.join(",")}}`);
  divider();
}
