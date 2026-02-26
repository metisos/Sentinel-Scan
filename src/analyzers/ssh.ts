import { Severity, type Finding } from "../core/models.js";
import type { CollectorResult } from "../collectors/base.js";
import type { ThreatDB } from "../threats/index.js";
import { BaseAnalyzer } from "./base.js";

interface SshdConfig {
  permitRootLogin: string;
  passwordAuth: string;
  pubkeyAuth: string;
  permitEmptyPasswords: string;
}

interface AuthorizedKeyFile {
  path: string;
  keys: string[];
}

export class SSHAnalyzer extends BaseAnalyzer {
  readonly module = "ssh" as const;

  analyze(data: CollectorResult, _threatDB: ThreatDB): Finding[] {
    const findings: Finding[] = [];
    let counter = 0;

    const nextId = (): string => {
      counter++;
      return `SSH-${String(counter).padStart(3, "0")}`;
    };

    const sshdConfig = (data.data.sshdConfig ?? {}) as Partial<SshdConfig>;
    const activeSessions = (data.data.activeSessions ?? []) as string[];
    const authorizedKeys = (data.data.authorizedKeys ?? []) as AuthorizedKeyFile[];

    // 1. PasswordAuthentication yes = HIGH
    if (sshdConfig.passwordAuth?.toLowerCase() === "yes") {
      findings.push({
        id: nextId(),
        module: this.module,
        severity: Severity.HIGH,
        title: `SSH password authentication is enabled`,
        description: `PasswordAuthentication is set to "yes" in sshd_config. This exposes the server to brute-force attacks. Key-based authentication is significantly more secure.`,
        details: { directive: "PasswordAuthentication", value: sshdConfig.passwordAuth },
        remediation: `Set "PasswordAuthentication no" in /etc/ssh/sshd_config and restart sshd. Ensure all users have SSH keys configured before making this change.`,
      });
    }

    // 2. PermitRootLogin yes = MEDIUM
    if (sshdConfig.permitRootLogin?.toLowerCase() === "yes") {
      findings.push({
        id: nextId(),
        module: this.module,
        severity: Severity.MEDIUM,
        title: `SSH root login is permitted`,
        description: `PermitRootLogin is set to "yes" in sshd_config. Direct root login should be disabled in favor of using sudo from a regular user account for audit trail purposes.`,
        details: { directive: "PermitRootLogin", value: sshdConfig.permitRootLogin },
        remediation: `Set "PermitRootLogin no" (or "prohibit-password" if root key access is needed) in /etc/ssh/sshd_config and restart sshd.`,
      });
    }

    // 3. PermitEmptyPasswords yes = CRITICAL
    if (sshdConfig.permitEmptyPasswords?.toLowerCase() === "yes") {
      findings.push({
        id: nextId(),
        module: this.module,
        severity: Severity.CRITICAL,
        title: `SSH allows empty passwords`,
        description: `PermitEmptyPasswords is set to "yes" in sshd_config. This allows any account with an empty password to log in via SSH, which is a severe security vulnerability.`,
        details: { directive: "PermitEmptyPasswords", value: sshdConfig.permitEmptyPasswords },
        remediation: `Set "PermitEmptyPasswords no" in /etc/ssh/sshd_config immediately and restart sshd. Audit all user accounts for empty passwords with "awk -F: '($2 == \"\") {print $1}' /etc/shadow".`,
      });
    }

    // 4. Multiple active sessions = INFO
    if (activeSessions.length > 1) {
      findings.push({
        id: nextId(),
        module: this.module,
        severity: Severity.INFO,
        title: `Multiple active SSH sessions detected`,
        description: `There are ${activeSessions.length} active login sessions. While this may be normal for a multi-admin server, unexpected sessions could indicate unauthorized access.`,
        details: { count: activeSessions.length, sessions: activeSessions },
        remediation: `Review the active sessions and verify each is expected. Use "who" or "w" to see session details. Terminate unexpected sessions with "pkill -u <username>".`,
      });
    }

    // 5. Report authorized keys count = INFO
    let totalKeys = 0;
    for (const akf of authorizedKeys) {
      totalKeys += akf.keys.length;
    }

    if (totalKeys > 0) {
      const fileSummary = authorizedKeys
        .filter((akf) => akf.keys.length > 0)
        .map((akf) => `${akf.path} (${akf.keys.length} key${akf.keys.length === 1 ? "" : "s"})`)
        .join(", ");

      findings.push({
        id: nextId(),
        module: this.module,
        severity: Severity.INFO,
        title: `Authorized SSH keys found`,
        description: `Found ${totalKeys} authorized SSH key${totalKeys === 1 ? "" : "s"} across ${authorizedKeys.length} file${authorizedKeys.length === 1 ? "" : "s"}: ${fileSummary}. Review these keys to ensure no unauthorized access has been configured.`,
        details: {
          totalKeys,
          files: authorizedKeys.map((akf) => ({
            path: akf.path,
            keyCount: akf.keys.length,
          })),
        },
        remediation: `Audit each authorized_keys file to ensure all keys belong to known and authorized users. Remove any unrecognized keys.`,
      });
    }

    return findings;
  }
}
