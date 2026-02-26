import {
  Severity,
  type Finding,
  type ModuleResult,
  type ScanResult,
  type ModuleName,
} from "./models.js";
import { ScanContext } from "./context.js";
import { ThreatDB } from "../threats/index.js";
import { getPlatformInfo } from "../utils/platform.js";
import { COLLECTOR_REGISTRY } from "../collectors/index.js";
import { ANALYZER_REGISTRY } from "../analyzers/index.js";

export class Scanner {
  private threatDB: ThreatDB;

  constructor() {
    this.threatDB = new ThreatDB();
  }

  async run(ctx: ScanContext): Promise<ScanResult> {
    const startTime = Date.now();
    const platform = getPlatformInfo();
    const moduleResults: ModuleResult[] = [];
    const allFindings: Finding[] = [];

    for (const moduleName of ctx.modules) {
      ctx.callbacks.onModuleStart?.(moduleName);

      const moduleStart = Date.now();
      let findings: Finding[] = [];
      let rawData: Record<string, unknown> = {};
      let error: string | undefined;

      try {
        const collector = COLLECTOR_REGISTRY[moduleName];
        const analyzer = ANALYZER_REGISTRY[moduleName];

        if (!collector || !analyzer) {
          error = `Module "${moduleName}" not found in registry`;
        } else {
          const collectorResult = await collector.collect();
          rawData = collectorResult.data;
          findings = analyzer.analyze(collectorResult, this.threatDB);
        }
      } catch (err) {
        error = err instanceof Error ? err.message : String(err);
      }

      const durationMs = Date.now() - moduleStart;
      ctx.callbacks.onModuleComplete?.(moduleName, durationMs);

      moduleResults.push({
        module: moduleName,
        findings,
        rawData,
        durationMs,
        error,
      });

      allFindings.push(...findings);
    }

    const totalDuration = Date.now() - startTime;
    const summary = buildSummary(allFindings);

    return {
      version: "0.1.0",
      timestamp: new Date().toISOString(),
      hostname: platform.hostname,
      os: platform.os,
      ip: platform.ip,
      modules: moduleResults,
      findings: allFindings,
      summary,
      durationMs: totalDuration,
    };
  }
}

function buildSummary(findings: Finding[]): ScanResult["summary"] {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let maxSeverity = Severity.INFO;

  for (const f of findings) {
    if (f.severity === Severity.CRITICAL) counts.critical++;
    else if (f.severity === Severity.HIGH) counts.high++;
    else if (f.severity === Severity.MEDIUM) counts.medium++;
    else if (f.severity === Severity.LOW) counts.low++;
    else counts.info++;

    if (f.severity > maxSeverity) maxSeverity = f.severity;
  }

  let status: ScanResult["summary"]["status"];
  if (counts.critical > 0) status = "COMPROMISED";
  else if (counts.high > 0) status = "THREATS_FOUND";
  else if (counts.medium > 0) status = "WARNINGS";
  else if (counts.low > 0 || counts.info > 0) status = "INFORMATIONAL";
  else status = "CLEAN";

  return {
    total: findings.length,
    ...counts,
    status,
    maxSeverity,
  };
}
