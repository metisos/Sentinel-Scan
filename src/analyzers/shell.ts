import { Severity, type Finding } from "../core/models.js";
import type { CollectorResult } from "../collectors/base.js";
import type { ThreatDB } from "../threats/index.js";
import { BaseAnalyzer } from "./base.js";

interface SuspiciousEntry {
  file: string;
  line: string;
  lineNumber: number;
  matchedPattern: string;
}

/** Patterns that indicate active exploitation or reverse shells. */
const HIGH_SEVERITY_PATTERNS = new Set([
  "wget",
  "curl",
  "nc",
  "ncat",
  "eval",
  "/dev/tcp",
  "/dev/udp",
  ".onion",
]);

/** Patterns that indicate obfuscation or indirect execution. */
const MEDIUM_SEVERITY_PATTERNS = new Set([
  "base64",
  "exec",
  "python.*http",
]);

export class ShellAnalyzer extends BaseAnalyzer {
  readonly module = "shell" as const;

  analyze(data: CollectorResult, _threatDB: ThreatDB): Finding[] {
    const findings: Finding[] = [];
    const suspiciousEntries = (data.data.suspiciousEntries ?? []) as SuspiciousEntry[];
    let counter = 0;

    const nextId = (): string => {
      counter++;
      return `SHELL-${String(counter).padStart(3, "0")}`;
    };

    for (const entry of suspiciousEntries) {
      const severity = this.classifySeverity(entry.matchedPattern);
      const category = this.describePattern(entry.matchedPattern);

      findings.push({
        id: nextId(),
        module: this.module,
        severity,
        title: `Suspicious pattern in shell profile: ${entry.matchedPattern}`,
        description: `File "${entry.file}" line ${entry.lineNumber} contains a ${category} pattern ("${entry.matchedPattern}"): "${this.truncate(entry.line.trim(), 150)}". Shell profile files run on every login and are a common persistence mechanism for malware.`,
        details: {
          file: entry.file,
          lineNumber: entry.lineNumber,
          line: entry.line,
          matchedPattern: entry.matchedPattern,
        },
        remediation: `Review line ${entry.lineNumber} of "${entry.file}". If the entry is not expected, remove it and investigate how it was added. Check recent modification times with "stat ${entry.file}".`,
      });
    }

    return findings;
  }

  /** Classify the severity based on the matched pattern. */
  private classifySeverity(pattern: string): Severity {
    const lower = pattern.toLowerCase();
    if (HIGH_SEVERITY_PATTERNS.has(lower)) return Severity.HIGH;
    if (MEDIUM_SEVERITY_PATTERNS.has(lower)) return Severity.MEDIUM;

    // Check partial matches for regex-style patterns like "python.*http"
    for (const p of MEDIUM_SEVERITY_PATTERNS) {
      if (lower.includes(p) || p.includes(lower)) return Severity.MEDIUM;
    }

    return Severity.HIGH;
  }

  /** Return a human-readable category for the pattern. */
  private describePattern(pattern: string): string {
    const lower = pattern.toLowerCase();
    if (lower === "wget" || lower === "curl") return "download tool";
    if (lower === "nc" || lower === "ncat") return "network utility (potential reverse shell)";
    if (lower === "eval" || lower === "exec") return "dynamic code execution";
    if (lower === "base64") return "encoding/obfuscation";
    if (lower.includes("/dev/tcp") || lower.includes("/dev/udp")) return "bash network redirection";
    if (lower.includes(".onion")) return "Tor hidden service reference";
    if (lower.includes("python") && lower.includes("http")) return "Python HTTP server/client";
    return "suspicious command";
  }

  private truncate(s: string, max: number): string {
    return s.length > max ? s.slice(0, max) + "..." : s;
  }
}
