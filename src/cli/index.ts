#!/usr/bin/env node

import { Command } from "commander";
import { Severity, ALL_MODULES, type ModuleName, type OutputFormat } from "../core/models.js";
import { ScanContext } from "../core/context.js";
import { Scanner } from "../core/scanner.js";
import { renderReport } from "../report/index.js";
import { printBanner } from "./banner.js";
import { createProgressCallbacks } from "./display.js";

const program = new Command();

program
  .name("sentinel")
  .description("Server security scanner — detect malware, backdoors, rootkits, and misconfigurations")
  .version("0.1.0");

program
  .command("scan", { isDefault: true })
  .description("Run a security scan")
  .option("-f, --format <format>", "Output format: terminal, json, markdown", "terminal")
  .option("-m, --modules <modules>", "Comma-separated list of modules to run")
  .option("--no-banner", "Suppress the ASCII banner")
  .option("--ai", "Enable AI-powered analysis (coming soon)")
  .option("--local-only", "Never send data to external APIs")
  .action(async (opts) => {
    const format = opts.format as OutputFormat;
    const isInteractive = format === "terminal" && process.stdout.isTTY === true;

    // Parse modules
    let modules: ModuleName[] = [...ALL_MODULES];
    if (opts.modules) {
      modules = (opts.modules as string).split(",").map((m: string) => m.trim()) as ModuleName[];
      const invalid = modules.filter((m) => !ALL_MODULES.includes(m));
      if (invalid.length > 0) {
        console.error(`Unknown modules: ${invalid.join(", ")}`);
        console.error(`Available: ${ALL_MODULES.join(", ")}`);
        process.exit(1);
      }
    }

    // Banner
    if (isInteractive && opts.banner !== false) {
      printBanner();
    }

    // Progress callbacks
    const callbacks = isInteractive ? createProgressCallbacks() : {};

    const ctx = new ScanContext({
      modules,
      format,
      noBanner: opts.banner === false,
      callbacks,
    });

    const scanner = new Scanner();
    const result = await scanner.run(ctx);

    // Render output
    const output = renderReport(result, format);

    if (format === "terminal") {
      console.log(output);
    } else {
      // JSON/markdown go to stdout clean
      process.stdout.write(output + "\n");
    }

    // Exit code based on severity
    const exitCode = severityToExitCode(result.summary.maxSeverity);
    process.exit(exitCode);
  });

function severityToExitCode(severity: Severity): number {
  switch (severity) {
    case Severity.CRITICAL:
    case Severity.HIGH:
      return 3;
    case Severity.MEDIUM:
      return 2;
    case Severity.LOW:
    case Severity.INFO:
      return 1;
    default:
      return 0;
  }
}

program.parse();
