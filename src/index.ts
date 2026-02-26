/**
 * Sentinel Scan — Server Security Scanner
 *
 * Programmatic API for use by AI agents and automation tools.
 *
 * @example
 * ```typescript
 * import { scan } from 'sentinel-scan';
 *
 * const result = await scan();
 * console.log(result.summary.status); // "CLEAN" | "COMPROMISED" | etc.
 *
 * // Run specific modules only
 * const result2 = await scan({ modules: ['processes', 'network', 'rootkit'] });
 *
 * // Get JSON string
 * import { scan, formatResult } from 'sentinel-scan';
 * const json = formatResult(result, 'json');
 * ```
 */

import { type ScanResult, type ScanOptions, type ModuleName, type OutputFormat, ALL_MODULES, Severity, severityLabel } from "./core/models.js";
import { ScanContext } from "./core/context.js";
import { Scanner } from "./core/scanner.js";
import { renderReport } from "./report/index.js";

export async function scan(options: ScanOptions = {}): Promise<ScanResult> {
  const ctx = new ScanContext({
    modules: options.modules ?? [...ALL_MODULES],
    format: "json",
    noBanner: true,
  });

  const scanner = new Scanner();
  return scanner.run(ctx);
}

export function formatResult(result: ScanResult, format: OutputFormat): string {
  return renderReport(result, format);
}

export function getExitCode(result: ScanResult): number {
  switch (result.summary.maxSeverity) {
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

// Re-export types for consumers
export {
  type ScanResult,
  type ScanOptions,
  type ModuleName,
  type OutputFormat,
  type Finding,
  type ModuleResult,
  Severity,
  severityLabel,
  ALL_MODULES,
} from "./core/models.js";
