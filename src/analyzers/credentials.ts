import { Severity, type Finding } from "../core/models.js";
import type { CollectorResult } from "../collectors/base.js";
import type { ThreatDB } from "../threats/index.js";
import { BaseAnalyzer } from "./base.js";

interface EnvFile {
  path: string;
  size: string;
}

export class CredentialAnalyzer extends BaseAnalyzer {
  readonly module = "credentials" as const;

  analyze(data: CollectorResult, _threatDB: ThreatDB): Finding[] {
    const findings: Finding[] = [];
    let counter = 0;

    const nextId = (): string => {
      counter++;
      return `CRED-${String(counter).padStart(3, "0")}`;
    };

    const envFiles = (data.data.envFiles ?? []) as EnvFile[];
    const serviceAccountKeys = (data.data.serviceAccountKeys ?? []) as string[];
    const gitCredentials = data.data.gitCredentials as string | null;
    const sshPrivateKeys = (data.data.sshPrivateKeys ?? []) as string[];

    // 1. .env files on disk
    for (const envFile of envFiles) {
      findings.push({
        id: nextId(),
        module: this.module,
        severity: Severity.MEDIUM,
        title: `Environment file with potential secrets`,
        description: `Found .env file at "${envFile.path}" (${this.formatSize(envFile.size)}). Environment files commonly contain API keys, database passwords, and other secrets that should not be stored on disk in production.`,
        details: { path: envFile.path, size: envFile.size },
        remediation: `Review the contents of "${envFile.path}" for secrets. Migrate secrets to a vault solution (e.g., HashiCorp Vault, AWS Secrets Manager) or encrypted environment variables. Remove the file from disk if it is not actively needed.`,
      });
    }

    // 2. Service account keys on disk
    for (const keyPath of serviceAccountKeys) {
      if (!keyPath.trim()) continue;

      findings.push({
        id: nextId(),
        module: this.module,
        severity: Severity.HIGH,
        title: `Service account key file on disk`,
        description: `Found service account / credentials JSON file at "${keyPath}". Service account keys grant programmatic access to cloud resources and are high-value targets for attackers.`,
        details: { path: keyPath },
        remediation: `Rotate the service account key immediately via the cloud provider console. Use workload identity, instance metadata, or a secrets manager instead of key files on disk. Remove the file after rotation.`,
      });
    }

    // 3. Git credentials stored in plaintext
    if (gitCredentials) {
      // Count the number of credential entries (non-empty lines)
      const credCount = gitCredentials
        .split("\n")
        .filter((l) => l.trim().length > 0).length;

      findings.push({
        id: nextId(),
        module: this.module,
        severity: Severity.MEDIUM,
        title: `Git credentials stored in plaintext`,
        description: `Found ${credCount} credential${credCount === 1 ? "" : "s"} in /root/.git-credentials. These are stored in plaintext and grant access to Git repositories (potentially including private source code and infrastructure-as-code).`,
        details: { path: "/root/.git-credentials", credentialCount: credCount },
        remediation: `Switch to a credential helper that uses the system keychain ("git config --global credential.helper store" is insecure). Use SSH keys or personal access tokens with minimal scopes instead.`,
      });
    }

    // 4. SSH private keys (informational)
    if (sshPrivateKeys.length > 0) {
      findings.push({
        id: nextId(),
        module: this.module,
        severity: Severity.INFO,
        title: `SSH private keys found on disk`,
        description: `Found ${sshPrivateKeys.length} SSH private key${sshPrivateKeys.length === 1 ? "" : "s"}: ${sshPrivateKeys.join(", ")}. While SSH keys are a normal authentication mechanism, their presence should be tracked and their permissions verified.`,
        details: { count: sshPrivateKeys.length, paths: sshPrivateKeys },
        remediation: `Ensure all private keys have permissions set to 600 ("chmod 600 <key>"). Remove any keys that are no longer needed. Consider using an SSH agent or hardware security key for additional protection.`,
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
