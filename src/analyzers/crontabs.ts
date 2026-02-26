import { Severity, type Finding } from "../core/models.js";
import type { CollectorResult } from "../collectors/base.js";
import type { ThreatDB } from "../threats/index.js";
import { BaseAnalyzer } from "./base.js";

interface UserCrontab {
  user: string;
  content: string;
}

interface CronDirEntry {
  name: string;
  content: string;
}

/**
 * Pattern that matches wget/curl piped to a shell interpreter.
 * Covers common variants: curl URL | bash, wget -O- URL | sh, etc.
 */
const DOWNLOAD_PIPE_RE = /(?:wget|curl)\b.*\|\s*(?:bash|sh|zsh|dash)\b/i;

/** Pattern that matches base64 -d or base64 --decode usage (obfuscated commands). */
const BASE64_RE = /base64\s+(?:-d|--decode)/i;

/** Pattern that matches execution from /tmp or hidden directories. */
const TMP_EXEC_RE = /(?:\/tmp\/|\/var\/tmp\/|\/dev\/shm\/)\S+/;
const HIDDEN_DIR_EXEC_RE = /\/\.[^/]+\/\S+/;

export class CrontabAnalyzer extends BaseAnalyzer {
  readonly module = "crontabs" as const;

  analyze(data: CollectorResult, threatDB: ThreatDB): Finding[] {
    const findings: Finding[] = [];
    let counter = 0;

    const nextId = (): string => {
      counter++;
      return `CRON-${String(counter).padStart(3, "0")}`;
    };

    // Collect all crontab sources into a unified list for analysis
    const sources: Array<{ label: string; content: string }> = [];

    const rootCrontab = (data.data.rootCrontab ?? "") as string;
    if (rootCrontab) {
      sources.push({ label: "root crontab", content: rootCrontab });
    }

    const systemCrontab = (data.data.systemCrontab ?? "") as string;
    if (systemCrontab) {
      sources.push({ label: "/etc/crontab", content: systemCrontab });
    }

    const cronDirs = (data.data.cronDirs ?? []) as CronDirEntry[];
    for (const entry of cronDirs) {
      sources.push({ label: `/etc/cron.d/${entry.name}`, content: entry.content });
    }

    const userCrontabs = (data.data.userCrontabs ?? []) as UserCrontab[];
    for (const entry of userCrontabs) {
      sources.push({ label: `crontab (user: ${entry.user})`, content: entry.content });
    }

    // Analyze each source
    for (const source of sources) {
      const lines = source.content.split("\n");

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        // Skip empty lines, comments, and variable assignments
        if (!line || line.startsWith("#") || /^\w+=/.test(line)) continue;

        // 1. wget/curl piped to shell
        if (DOWNLOAD_PIPE_RE.test(line)) {
          findings.push({
            id: nextId(),
            module: this.module,
            severity: Severity.CRITICAL,
            title: `Crontab downloads and executes remote code`,
            description: `Entry in ${source.label} (line ${i + 1}) pipes a download command directly to a shell interpreter: "${this.truncate(line, 120)}". This is the most common malware persistence technique via cron.`,
            details: { source: source.label, lineNumber: i + 1, line },
            remediation: `Remove the crontab entry immediately. Investigate the URL being fetched and check for additional compromise indicators.`,
          });
        }

        // 2. base64-encoded commands
        if (BASE64_RE.test(line)) {
          findings.push({
            id: nextId(),
            module: this.module,
            severity: Severity.HIGH,
            title: `Crontab contains base64-encoded command`,
            description: `Entry in ${source.label} (line ${i + 1}) uses base64 decoding: "${this.truncate(line, 120)}". Attackers encode payloads in base64 to evade simple pattern matching.`,
            details: { source: source.label, lineNumber: i + 1, line },
            remediation: `Decode and inspect the base64 payload. Remove the crontab entry if it is malicious.`,
          });
        }

        // 3. Execution from /tmp or hidden directories
        const tmpMatch = TMP_EXEC_RE.exec(line);
        if (tmpMatch) {
          findings.push({
            id: nextId(),
            module: this.module,
            severity: Severity.HIGH,
            title: `Crontab runs binary from temporary directory`,
            description: `Entry in ${source.label} (line ${i + 1}) references a path in a temporary directory: "${tmpMatch[0]}". Legitimate cron jobs should not execute from /tmp, /var/tmp, or /dev/shm.`,
            details: { source: source.label, lineNumber: i + 1, line, path: tmpMatch[0] },
            remediation: `Remove the crontab entry. Investigate and delete the binary at "${tmpMatch[0]}".`,
          });
        }

        const hiddenMatch = HIDDEN_DIR_EXEC_RE.exec(line);
        if (hiddenMatch && !tmpMatch) {
          findings.push({
            id: nextId(),
            module: this.module,
            severity: Severity.HIGH,
            title: `Crontab runs binary from hidden directory`,
            description: `Entry in ${source.label} (line ${i + 1}) references a hidden directory path: "${hiddenMatch[0]}". Malware frequently hides in dot-prefixed directories.`,
            details: { source: source.label, lineNumber: i + 1, line, path: hiddenMatch[0] },
            remediation: `Remove the crontab entry. Investigate the hidden directory and remove any malicious files.`,
          });
        }
      }
    }

    return findings;
  }

  private truncate(s: string, max: number): string {
    return s.length > max ? s.slice(0, max) + "..." : s;
  }
}
