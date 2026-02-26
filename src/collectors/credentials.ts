import { exec, execLines } from "../utils/shell.js";
import { BaseCollector, type CollectorResult } from "./base.js";

interface EnvFile {
  path: string;
  size: string;
}

export class CredentialsCollector extends BaseCollector {
  readonly module = "credentials" as const;

  async collect(): Promise<CollectorResult> {
    const rawParts: string[] = [];

    // --- .env files (excluding node_modules and venv) ---
    const envFileNames = [".env", ".env.local", ".env.production", ".env.backup"];
    const nameArgs = envFileNames.map((n) => `-name "${n}"`).join(" -o ");
    const envFilePaths = execLines(
      `find / \\( ${nameArgs} \\) -not -path "*/node_modules/*" -not -path "*/venv/*" -not -path "*/proc/*" -printf '%p\\t%s\\n' 2>/dev/null`,
      60_000,
    );
    rawParts.push("# env files\n" + envFilePaths.join("\n"));

    const envFiles: EnvFile[] = [];
    for (const line of envFilePaths) {
      const [path, size] = line.split("\t");
      if (path) {
        envFiles.push({ path, size: size || "0" });
      }
    }

    // --- Firebase / GCP service account key files ---
    const serviceAccountKeys = execLines(
      'find / -type f \\( -name "*service-account*.json" -o -name "*serviceaccount*.json" -o -name "*firebase*adminsdk*.json" -o -name "*gcp-key*.json" \\) -not -path "*/node_modules/*" -not -path "*/venv/*" -not -path "*/proc/*" -not -path "*/google-cloud-sdk/*" -not -path "*/test_data/*" -not -path "*/test/*" -not -path "*/.cache/*" 2>/dev/null',
      60_000,
    );
    rawParts.push("# service account keys\n" + serviceAccountKeys.join("\n"));

    // --- Git credentials ---
    const gitCredResult = exec("cat /root/.git-credentials 2>/dev/null");
    rawParts.push("# git-credentials\n" + gitCredResult.stdout);

    const gitCredentials =
      gitCredResult.success && gitCredResult.stdout.length > 0
        ? gitCredResult.stdout
        : null;

    // --- SSH private keys ---
    const sshPrivateKeys = execLines(
      'find / -type f \\( -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" -o -name "id_dsa" -o -name "*.pem" \\) -not -path "*/proc/*" 2>/dev/null',
      60_000,
    );

    // Filter .pem files to only include those that actually contain private keys
    const confirmedKeys: string[] = [];
    for (const keyPath of sshPrivateKeys) {
      if (!keyPath.endsWith(".pem")) {
        confirmedKeys.push(keyPath);
        continue;
      }
      const headResult = exec(`head -1 "${keyPath}" 2>/dev/null`);
      if (headResult.stdout && headResult.stdout.includes("PRIVATE KEY")) {
        confirmedKeys.push(keyPath);
      }
    }
    rawParts.push("# SSH private keys\n" + confirmedKeys.join("\n"));

    return {
      module: this.module,
      data: {
        envFiles,
        serviceAccountKeys,
        gitCredentials,
        sshPrivateKeys: confirmedKeys,
      },
      raw: rawParts.join("\n\n"),
    };
  }
}
