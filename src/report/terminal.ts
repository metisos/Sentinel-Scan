import chalk from "chalk";
import { Severity, severityLabel, type ScanResult, type Finding } from "../core/models.js";

const severityColor: Record<Severity, (s: string) => string> = {
  [Severity.CRITICAL]: chalk.bgRed.white.bold,
  [Severity.HIGH]: chalk.red.bold,
  [Severity.MEDIUM]: chalk.yellow.bold,
  [Severity.LOW]: chalk.blue,
  [Severity.INFO]: chalk.gray,
};

function severityTag(severity: Severity): string {
  const label = severityLabel[severity].padEnd(8);
  return severityColor[severity](`[${label}]`);
}

export function renderTerminal(result: ScanResult): string {
  const lines: string[] = [];

  lines.push("");
  lines.push(
    chalk.bold(`Sentinel Security Scan — ${new Date(result.timestamp).toUTCString()}`)
  );
  lines.push(
    chalk.dim(`Server: ${result.ip} (${result.os}) | Host: ${result.hostname}`)
  );
  lines.push(chalk.dim(`Scan duration: ${(result.durationMs / 1000).toFixed(1)}s`));
  lines.push("");

  if (result.findings.length === 0) {
    lines.push(chalk.green.bold("  No security issues found."));
    lines.push("");
  } else {
    const sorted = [...result.findings].sort(
      (a, b) => b.severity - a.severity
    );

    for (const finding of sorted) {
      lines.push(`  ${severityTag(finding.severity)} ${finding.title}`);
      if (finding.description) {
        lines.push(chalk.dim(`             ${finding.description}`));
      }
    }
    lines.push("");
  }

  // Summary line
  const { summary } = result;
  let statusColor: (s: string) => string;
  switch (summary.status) {
    case "COMPROMISED":
      statusColor = chalk.bgRed.white.bold;
      break;
    case "THREATS_FOUND":
      statusColor = chalk.red.bold;
      break;
    case "WARNINGS":
      statusColor = chalk.yellow.bold;
      break;
    case "INFORMATIONAL":
      statusColor = chalk.blue;
      break;
    default:
      statusColor = chalk.green.bold;
  }

  const parts: string[] = [];
  if (summary.critical > 0) parts.push(chalk.red(`${summary.critical} critical`));
  if (summary.high > 0) parts.push(chalk.red(`${summary.high} high`));
  if (summary.medium > 0) parts.push(chalk.yellow(`${summary.medium} medium`));
  if (summary.low > 0) parts.push(chalk.blue(`${summary.low} low`));
  if (summary.info > 0) parts.push(chalk.gray(`${summary.info} info`));

  lines.push(
    `Status: ${statusColor(summary.status)}` +
      (parts.length > 0 ? ` — ${parts.join(", ")}` : "")
  );

  // Module errors
  const errors = result.modules.filter((m) => m.error);
  if (errors.length > 0) {
    lines.push("");
    lines.push(chalk.yellow("Module errors:"));
    for (const m of errors) {
      lines.push(chalk.dim(`  ${m.module}: ${m.error}`));
    }
  }

  lines.push("");
  return lines.join("\n");
}
