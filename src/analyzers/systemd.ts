import { Severity, type Finding } from "../core/models.js";
import type { CollectorResult } from "../collectors/base.js";
import type { ThreatDB } from "../threats/index.js";
import { BaseAnalyzer } from "./base.js";

interface EnabledService {
  name: string;
  state: string;
}

interface ServiceFileInfo {
  name: string;
  path: string;
  content: string;
  execStart: string;
  restart: string;
  restartSec: string;
  standardOutput: string;
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

/** Directories from which a systemd ExecStart should never point to. */
const SUSPICIOUS_EXEC_PATHS = ["/tmp/", "/var/tmp/", "/etc/data/", "/dev/shm/"];

/** Regex for hidden directory components in a path. */
const HIDDEN_DIR_RE = /\/\.[^/]+\//;

/** Standard system paths where legitimate service binaries reside. */
const STANDARD_EXEC_PREFIXES = [
  "/usr/bin/",
  "/usr/sbin/",
  "/usr/local/bin/",
  "/usr/local/sbin/",
  "/bin/",
  "/sbin/",
  "/lib/systemd/",
  "/usr/lib/systemd/",
  "/snap/",
];

export class SystemdAnalyzer extends BaseAnalyzer {
  readonly module = "systemd" as const;

  analyze(data: CollectorResult, threatDB: ThreatDB): Finding[] {
    const findings: Finding[] = [];
    const enabledServices = (data.data.enabledServices ?? []) as EnabledService[];
    const serviceFiles = (data.data.serviceFiles ?? []) as ServiceFileInfo[];
    let counter = 0;

    const nextId = (): string => {
      counter++;
      return `SVC-${String(counter).padStart(3, "0")}`;
    };

    // 1. Match each enabled service against threat database
    for (const svc of enabledServices) {
      // Strip the .service suffix for matching
      const baseName = svc.name.replace(/\.service$/, "");
      const threat = threatDB.matchService(baseName) ?? threatDB.matchService(svc.name);
      if (threat) {
        findings.push({
          id: nextId(),
          module: this.module,
          severity: toSeverity(threat.severity),
          title: `Known malicious service: ${threat.name}`,
          description: `Enabled service "${svc.name}" matches threat database entry "${threat.name}": ${threat.description}.`,
          details: { service: svc.name, threat },
          remediation: `Disable and stop the service: "systemctl disable --now ${svc.name}". Remove the service unit file and investigate how it was installed.`,
        });
      }
    }

    // 2. Inspect service files in detail
    for (const sf of serviceFiles) {
      const execBinary = this.extractExecBinary(sf.execStart);

      // 2a. ExecStart pointing to suspicious paths
      const suspiciousPath = SUSPICIOUS_EXEC_PATHS.find((p) => execBinary.startsWith(p));
      if (suspiciousPath) {
        findings.push({
          id: nextId(),
          module: this.module,
          severity: Severity.HIGH,
          title: `Service ExecStart points to suspicious path`,
          description: `Service "${sf.name}" has ExecStart="${sf.execStart}" which points to "${suspiciousPath}". Malware commonly persists as systemd services running from temporary or data directories.`,
          details: { service: sf.name, execStart: sf.execStart, path: sf.path },
          remediation: `Inspect the binary at "${execBinary}". Disable the service with "systemctl disable --now ${sf.name}" and remove the unit file at "${sf.path}".`,
        });
      }

      // 2b. ExecStart pointing to hidden directories
      if (HIDDEN_DIR_RE.test(execBinary)) {
        findings.push({
          id: nextId(),
          module: this.module,
          severity: Severity.HIGH,
          title: `Service ExecStart points to hidden directory`,
          description: `Service "${sf.name}" has ExecStart="${sf.execStart}" which references a hidden directory. This is a common persistence technique for malware.`,
          details: { service: sf.name, execStart: sf.execStart, path: sf.path },
          remediation: `Investigate the binary at "${execBinary}". Disable the service and remove both the unit file and the hidden binary.`,
        });
      }

      // 3. Restart=always + RestartSec < 30 + non-standard binary path => aggressive restart
      const isNonStandard = !STANDARD_EXEC_PREFIXES.some((prefix) =>
        execBinary.startsWith(prefix),
      );
      const restartSec = parseFloat(sf.restartSec) || 0;

      if (
        sf.restart.toLowerCase() === "always" &&
        restartSec < 30 &&
        isNonStandard &&
        execBinary.length > 0
      ) {
        findings.push({
          id: nextId(),
          module: this.module,
          severity: Severity.MEDIUM,
          title: `Service with aggressive restart from non-standard path`,
          description: `Service "${sf.name}" is configured with Restart=always and RestartSec=${restartSec || "0"}, running a non-standard binary at "${execBinary}". Malware services often use aggressive restart policies to maintain persistence.`,
          details: {
            service: sf.name,
            execStart: sf.execStart,
            restart: sf.restart,
            restartSec: sf.restartSec,
            path: sf.path,
          },
          remediation: `Verify that "${sf.name}" is a legitimate service. If not expected, disable it with "systemctl disable --now ${sf.name}" and remove the unit file.`,
        });
      }

      // 4. StandardOutput=null — silencing all output is suspicious
      if (sf.standardOutput.toLowerCase() === "null") {
        findings.push({
          id: nextId(),
          module: this.module,
          severity: Severity.MEDIUM,
          title: `Service suppresses all output`,
          description: `Service "${sf.name}" has StandardOutput=null, which suppresses all logging. Malware uses this to avoid leaving traces in the journal.`,
          details: { service: sf.name, standardOutput: sf.standardOutput, path: sf.path },
          remediation: `Review the service unit file at "${sf.path}". If the service is legitimate, configure proper logging. Otherwise disable and remove it.`,
        });
      }
    }

    return findings;
  }

  /** Extract the actual binary path from an ExecStart value, stripping prefixes like "-" or "+" and arguments. */
  private extractExecBinary(execStart: string): string {
    if (!execStart) return "";
    // systemd allows prefixes like -, +, !, @
    let cleaned = execStart.replace(/^[-+!@]+/, "").trim();
    // Take only the first token (the binary path)
    cleaned = cleaned.split(/\s+/)[0] ?? "";
    return cleaned;
  }
}
