import { Severity, type Finding } from "../core/models.js";
import type { CollectorResult } from "../collectors/base.js";
import type { ThreatDB } from "../threats/index.js";
import { BaseAnalyzer } from "./base.js";

interface SuspiciousExecutable {
  path: string;
  size: string;
}

interface SuidBinary {
  path: string;
  packaged: boolean;
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

/** Standard hidden directories that are expected in /root. */
const STANDARD_ROOT_HIDDEN_DIRS = new Set([
  // shell
  ".ssh", ".gnupg", ".bash_history", ".profile", ".bashrc",
  ".wget-hsts", ".lesshst", ".selected_editor",
  // system
  ".config", ".local", ".cache", ".docker", ".pki",
  // editors/IDEs
  ".vscode", ".vscode-server", ".cursor-server", ".windsurf-server",
  ".codeium", ".codex", ".gemini", ".arc",
  // dev tools
  ".npm", ".nvm", ".yarn", ".bun", ".pnpm",
  ".cargo", ".rustup", ".pyenv", ".rbenv", ".goenv",
  ".pm2", ".claude", ".jupyter", ".ipython", ".dotnet",
  // project dirs (common in home)
  ".git", ".github", ".next", ".venv", ".pytest_cache",
  ".rosetta", ".gsutil",
]);

export class FilesystemAnalyzer extends BaseAnalyzer {
  readonly module = "filesystem" as const;

  analyze(data: CollectorResult, threatDB: ThreatDB): Finding[] {
    const findings: Finding[] = [];
    let counter = 0;

    const nextId = (): string => {
      counter++;
      return `FS-${String(counter).padStart(3, "0")}`;
    };

    const suspiciousExecutables = (data.data.suspiciousExecutables ?? []) as SuspiciousExecutable[];
    const hiddenDirs = (data.data.hiddenDirs ?? []) as string[];
    const worldWritable = (data.data.worldWritable ?? []) as string[];
    const suidBinaries = (data.data.suidBinaries ?? []) as SuidBinary[];

    // 1. Executables in /tmp, /var/tmp, /dev/shm
    for (const exe of suspiciousExecutables) {
      const isTemp =
        exe.path.startsWith("/tmp/") ||
        exe.path.startsWith("/var/tmp/") ||
        exe.path.startsWith("/dev/shm/");

      if (!isTemp) continue;

      // Check against threat database for known malware
      const threat = threatDB.matchPath(exe.path);
      if (threat) {
        findings.push({
          id: nextId(),
          module: this.module,
          severity: toSeverity(threat.severity),
          title: `Known malicious file: ${threat.name}`,
          description: `Executable at "${exe.path}" (${this.formatSize(exe.size)}) matches threat database entry "${threat.name}".`,
          details: { path: exe.path, size: exe.size, threat },
          remediation: `Remove the file immediately: "rm -f ${exe.path}". Check for associated processes and persistence mechanisms.`,
        });
      } else {
        findings.push({
          id: nextId(),
          module: this.module,
          severity: Severity.HIGH,
          title: `Executable found in temporary directory`,
          description: `Executable file at "${exe.path}" (${this.formatSize(exe.size)}). Legitimate software should not be stored or executed from temporary directories.`,
          details: { path: exe.path, size: exe.size },
          remediation: `Investigate the file with "file ${exe.path}" and "sha256sum ${exe.path}". Remove it if it is not part of a known, running application.`,
        });
      }
    }

    // Also check non-temp executables against threat database
    for (const exe of suspiciousExecutables) {
      if (
        exe.path.startsWith("/tmp/") ||
        exe.path.startsWith("/var/tmp/") ||
        exe.path.startsWith("/dev/shm/")
      ) {
        continue; // Already handled above
      }

      const threat = threatDB.matchPath(exe.path);
      if (threat) {
        findings.push({
          id: nextId(),
          module: this.module,
          severity: toSeverity(threat.severity),
          title: `Known malicious file: ${threat.name}`,
          description: `Executable at "${exe.path}" (${this.formatSize(exe.size)}) matches threat database entry "${threat.name}".`,
          details: { path: exe.path, size: exe.size, threat },
          remediation: `Remove the file immediately: "rm -f ${exe.path}". Check for associated processes and persistence mechanisms.`,
        });
      }
    }

    // 2. Hidden directories directly under /root or / (not nested inside projects)
    for (const dir of hiddenDirs) {
      // Only check top-level hidden dirs: /root/.something or /.something
      const cleaned = dir.replace(/\/$/, "");
      const isDirectChild =
        /^\/root\/\.[^/]+$/.test(cleaned) || /^\/\.[^/]+$/.test(cleaned);
      if (!isDirectChild) continue;

      // Extract the directory name
      const parts = cleaned.split("/");
      const dirName = parts[parts.length - 1];
      if (!dirName || !dirName.startsWith(".")) continue;

      if (!STANDARD_ROOT_HIDDEN_DIRS.has(dirName)) {
        findings.push({
          id: nextId(),
          module: this.module,
          severity: Severity.MEDIUM,
          title: `Non-standard hidden directory in /root`,
          description: `Hidden directory "${dir}" is not a recognized standard directory. Malware often creates hidden directories (e.g., .configrc, .X11-unix, .ICE-unix) to store payloads.`,
          details: { path: dir, dirName },
          remediation: `Inspect the contents of "${dir}" with "ls -la ${dir}". Remove it if it does not belong to a legitimate application.`,
        });
      }
    }

    // 3. Unpackaged SUID binaries
    for (const suid of suidBinaries) {
      if (!suid.packaged) {
        findings.push({
          id: nextId(),
          module: this.module,
          severity: Severity.HIGH,
          title: `Unpackaged SUID binary detected`,
          description: `SUID binary at "${suid.path}" is not owned by any installed package. SUID binaries run with elevated privileges and unpackaged ones may indicate privilege escalation backdoors.`,
          details: { path: suid.path, packaged: suid.packaged },
          remediation: `Inspect the binary with "file ${suid.path}" and "strings ${suid.path}". Remove the SUID bit with "chmod u-s ${suid.path}" if it is not needed, or remove the file entirely.`,
        });
      }
    }

    // 4. World-writable system files
    for (const filePath of worldWritable) {
      if (!filePath.trim()) continue;

      findings.push({
        id: nextId(),
        module: this.module,
        severity: Severity.MEDIUM,
        title: `World-writable system file`,
        description: `System file "${filePath}" is world-writable. Any user can modify this file, which could allow privilege escalation or system configuration tampering.`,
        details: { path: filePath },
        remediation: `Fix permissions with "chmod o-w ${filePath}". Investigate whether the file has been tampered with by comparing to package defaults: "dpkg -V" or "rpm -V".`,
      });
    }

    return findings;
  }

  /** Format a byte size string into a human-readable form. */
  private formatSize(sizeStr: string): string {
    const bytes = parseInt(sizeStr, 10);
    if (isNaN(bytes)) return sizeStr;
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }
}
