import { severityLabel, type ScanResult } from "../core/models.js";

export function renderJSON(result: ScanResult): string {
  const output = {
    ...result,
    findings: result.findings.map((f) => ({
      ...f,
      severity: severityLabel[f.severity],
    })),
    modules: result.modules.map((m) => ({
      ...m,
      findings: m.findings.map((f) => ({
        ...f,
        severity: severityLabel[f.severity],
      })),
    })),
    summary: {
      ...result.summary,
      maxSeverity: severityLabel[result.summary.maxSeverity],
    },
  };

  return JSON.stringify(output, null, 2);
}
