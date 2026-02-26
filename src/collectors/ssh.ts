import { exec, execLines } from "../utils/shell.js";
import { BaseCollector, type CollectorResult } from "./base.js";

interface AuthorizedKeyFile {
  path: string;
  keys: string[];
}

interface SshdConfig {
  permitRootLogin: string;
  passwordAuth: string;
  pubkeyAuth: string;
  permitEmptyPasswords: string;
}

export class SshCollector extends BaseCollector {
  readonly module = "ssh" as const;

  async collect(): Promise<CollectorResult> {
    const rawParts: string[] = [];

    // --- Authorized keys ---
    const authKeyPaths = execLines(
      'find / -name "authorized_keys" -not -path "*/proc/*" 2>/dev/null',
      60_000,
    );
    rawParts.push("# authorized_keys paths\n" + authKeyPaths.join("\n"));

    const authorizedKeys: AuthorizedKeyFile[] = [];
    for (const filePath of authKeyPaths) {
      const readResult = exec(`cat "${filePath}" 2>/dev/null`);
      const keys = readResult.stdout
        ? readResult.stdout.split("\n").filter((l) => l.trim().length > 0 && !l.trim().startsWith("#"))
        : [];
      authorizedKeys.push({ path: filePath, keys });
      rawParts.push(`# ${filePath}\n${readResult.stdout}`);
    }

    // --- sshd_config ---
    const sshdResult = exec("cat /etc/ssh/sshd_config 2>/dev/null");
    rawParts.push("# sshd_config\n" + sshdResult.stdout);

    const sshdConfig: SshdConfig = {
      permitRootLogin: this.parseSshdValue(sshdResult.stdout, "PermitRootLogin"),
      passwordAuth: this.parseSshdValue(sshdResult.stdout, "PasswordAuthentication"),
      pubkeyAuth: this.parseSshdValue(sshdResult.stdout, "PubkeyAuthentication"),
      permitEmptyPasswords: this.parseSshdValue(sshdResult.stdout, "PermitEmptyPasswords"),
    };

    // --- Active sessions ---
    const whoResult = exec("who 2>/dev/null");
    rawParts.push("# who\n" + whoResult.stdout);

    const activeSessions = whoResult.stdout
      ? whoResult.stdout.split("\n").filter((l) => l.trim().length > 0)
      : [];

    // --- SSH connections ---
    const ssResult = exec("ss -tnp | grep :22 2>/dev/null");
    rawParts.push("# ss :22\n" + ssResult.stdout);

    const sshConnections = ssResult.stdout
      ? ssResult.stdout.split("\n").filter((l) => l.trim().length > 0)
      : [];

    return {
      module: this.module,
      data: {
        authorizedKeys,
        sshdConfig,
        activeSessions,
        sshConnections,
      },
      raw: rawParts.join("\n\n"),
    };
  }

  private parseSshdValue(config: string, key: string): string {
    if (!config) return "unknown";
    const lines = config.split("\n");
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith("#") || trimmed.length === 0) continue;
      const lower = trimmed.toLowerCase();
      if (lower.startsWith(key.toLowerCase())) {
        const parts = trimmed.split(/\s+/);
        return parts.length > 1 ? parts[1] : "unknown";
      }
    }
    return "unknown";
  }
}
