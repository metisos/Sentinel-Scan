import { Severity, type Finding } from "../core/models.js";
import type { CollectorResult } from "../collectors/base.js";
import type { ThreatDB } from "../threats/index.js";
import { BaseAnalyzer } from "./base.js";

interface ProcessInfo {
  user: string;
  pid: number;
  cpu: number;
  mem: number;
  vsz: number;
  rss: number;
  tty: string;
  stat: string;
  start: string;
  time: string;
  command: string;
}

function toSeverity(s: string): Severity {
  const map: Record<string, Severity> = {
    critical: Severity.CRITICAL,
    high: Severity.HIGH,
    medium: Severity.MEDIUM,
    low: Severity.LOW,
    info: Severity.INFO,
  };
  return map[s] ?? Severity.MEDIUM;
}

/** Suspicious temporary / volatile paths where legitimate binaries should never run from. */
const SUSPICIOUS_PATHS = ["/tmp/", "/var/tmp/", "/dev/shm/"];

/** Regex that detects execution from a hidden directory (e.g. /home/user/.hidden/bin). */
const HIDDEN_DIR_RE = /\/\.[^/]+\//;

/** Hidden directories that are safe/expected and should not trigger alerts. */
const SAFE_HIDDEN_DIRS = new Set([
  ".vscode-server", ".vscode", ".cursor-server",
  ".ssh", ".config", ".local", ".cache",
  ".npm", ".nvm", ".yarn", ".bun", ".pnpm",
  ".docker", ".gnupg", ".pm2",
  ".cargo", ".rustup", ".pyenv", ".rbenv", ".goenv",
  ".claude",
]);

export class ProcessAnalyzer extends BaseAnalyzer {
  readonly module = "processes" as const;

  analyze(data: CollectorResult, threatDB: ThreatDB): Finding[] {
    const findings: Finding[] = [];
    const processes = (data.data.processes ?? []) as ProcessInfo[];
    let counter = 0;

    const nextId = (): string => {
      counter++;
      return `PROC-${String(counter).padStart(3, "0")}`;
    };

    for (const proc of processes) {
      const name = proc.command.split(/\s+/)[0] ?? proc.command;
      const cmdline = proc.command;

      // 1. Match against threat database
      const threat = threatDB.matchProcess(name, cmdline);
      if (threat) {
        findings.push({
          id: nextId(),
          module: this.module,
          severity: toSeverity(threat.severity),
          title: `Known malicious process: ${threat.name}`,
          description: `Process "${cmdline}" (PID ${proc.pid}, user ${proc.user}) matches threat database entry "${threat.name}" (family: ${threat.family}).`,
          details: { pid: proc.pid, user: proc.user, command: cmdline, threat },
          remediation: `Kill the process with "kill -9 ${proc.pid}", investigate how it was installed, and remove the underlying binary.`,
        });
      }

      // 2. Flag processes running from suspicious paths
      const binaryPath = this.extractBinaryPath(cmdline);
      const suspiciousDir = SUSPICIOUS_PATHS.find((p) => binaryPath.startsWith(p));
      if (suspiciousDir) {
        findings.push({
          id: nextId(),
          module: this.module,
          severity: Severity.HIGH,
          title: `Process running from temporary directory`,
          description: `Process "${cmdline}" (PID ${proc.pid}) is executing from "${suspiciousDir}". Legitimate software should not run from temporary directories.`,
          details: { pid: proc.pid, user: proc.user, command: cmdline, binaryPath },
          remediation: `Investigate the binary at "${binaryPath}". Kill the process and remove the file if it is not expected.`,
        });
      }

      // 3. Flag processes running from hidden directories (skip safe ones)
      const hiddenMatch = HIDDEN_DIR_RE.exec(binaryPath);
      const hiddenDirName = hiddenMatch ? hiddenMatch[0].replace(/\//g, "") : "";
      if (hiddenMatch && !suspiciousDir && !SAFE_HIDDEN_DIRS.has(hiddenDirName)) {
        findings.push({
          id: nextId(),
          module: this.module,
          severity: Severity.HIGH,
          title: `Process running from hidden directory`,
          description: `Process "${cmdline}" (PID ${proc.pid}) is executing from a hidden directory. This is a common technique used by malware to avoid detection.`,
          details: { pid: proc.pid, user: proc.user, command: cmdline, binaryPath },
          remediation: `Investigate the binary at "${binaryPath}". Kill the process and remove the hidden directory if it is not legitimate.`,
        });
      }

      // 4. Flag high CPU usage (potential cryptominer)
      if (proc.cpu > 80) {
        findings.push({
          id: nextId(),
          module: this.module,
          severity: Severity.MEDIUM,
          title: `Process with abnormally high CPU usage`,
          description: `Process "${cmdline}" (PID ${proc.pid}, user ${proc.user}) is consuming ${proc.cpu}% CPU. This could indicate a cryptominer or other resource-abusing malware.`,
          details: { pid: proc.pid, user: proc.user, command: cmdline, cpu: proc.cpu, mem: proc.mem },
          remediation: `Verify whether PID ${proc.pid} is a legitimate workload. If unexpected, kill it with "kill -9 ${proc.pid}" and investigate the binary.`,
        });
      }
    }

    return findings;
  }

  /** Extract the first path-like token from a command line. */
  private extractBinaryPath(cmdline: string): string {
    // Strip leading tree-drawing characters from ps auxf output (e.g. " \_ ")
    const cleaned = cmdline.replace(/^[\s\\|`_-]+/, "");
    const token = cleaned.split(/\s+/)[0] ?? "";
    return token;
  }
}
