import { Severity, type Finding } from "../core/models.js";
import type { CollectorResult } from "../collectors/base.js";
import type { ThreatDB } from "../threats/index.js";
import { BaseAnalyzer } from "./base.js";

export class RootkitAnalyzer extends BaseAnalyzer {
  readonly module = "rootkit" as const;

  analyze(data: CollectorResult, _threatDB: ThreatDB): Finding[] {
    const findings: Finding[] = [];
    let counter = 0;

    const nextId = (): string => {
      counter++;
      return `RK-${String(counter).padStart(3, "0")}`;
    };

    const ldPreload = (data.data.ldPreload ?? "") as string;
    const suspiciousSoFiles = (data.data.suspiciousSoFiles ?? []) as string[];
    const etcDataExists = (data.data.etcDataExists ?? false) as boolean;
    const etcDataFiles = (data.data.etcDataFiles ?? []) as string[];

    // 1. Any content in /etc/ld.so.preload = CRITICAL
    const preloadContent = ldPreload.trim();
    if (preloadContent.length > 0) {
      // Extract referenced library paths (non-empty, non-comment lines)
      const preloadEntries = preloadContent
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.length > 0 && !l.startsWith("#"));

      findings.push({
        id: nextId(),
        module: this.module,
        severity: Severity.CRITICAL,
        title: `LD_PRELOAD rootkit detected`,
        description: `/etc/ld.so.preload contains entries: ${preloadEntries.join(", ")}. This file forces shared libraries to be loaded into every process, which is the primary mechanism for userland rootkits (e.g., Jynx, Azazel, libprocesshider).`,
        details: { file: "/etc/ld.so.preload", entries: preloadEntries, rawContent: preloadContent },
        remediation: `This is a strong indicator of active compromise. 1) Record the preloaded library paths. 2) Remove or empty /etc/ld.so.preload. 3) Delete the malicious .so files. 4) Restart sshd and critical services. 5) Audit the system for additional persistence mechanisms.`,
      });
    }

    // 2. Suspicious .so files in /etc, /tmp, /var/tmp, /dev/shm
    for (const soFile of suspiciousSoFiles) {
      findings.push({
        id: nextId(),
        module: this.module,
        severity: Severity.HIGH,
        title: `Suspicious shared library in non-standard location`,
        description: `Found .so file at "${soFile}". Shared libraries outside of standard library paths (/usr/lib, /lib) are often rootkit components or injected libraries.`,
        details: { path: soFile },
        remediation: `Inspect the shared library with "file ${soFile}" and "strings ${soFile}". Check if it is referenced in /etc/ld.so.preload or LD_PRELOAD. Remove it if it is not legitimate.`,
      });
    }

    // 3. /etc/data directory exists = CRITICAL (Kinsing malware)
    if (etcDataExists) {
      findings.push({
        id: nextId(),
        module: this.module,
        severity: Severity.CRITICAL,
        title: `Known malware directory /etc/data detected (Kinsing)`,
        description: `The directory /etc/data exists with ${etcDataFiles.length} entries. This is a well-known indicator of the Kinsing cryptomining malware, which stores its payloads and configuration in this directory.`,
        details: { path: "/etc/data", files: etcDataFiles },
        remediation: `1) Kill any Kinsing-related processes (kdevtmpfsi, kinsing). 2) Remove /etc/data and its contents. 3) Check crontabs and systemd for persistence entries. 4) Patch the vulnerability that allowed initial access (commonly Docker API, Redis, or Log4j).`,
      });
    }

    return findings;
  }
}
