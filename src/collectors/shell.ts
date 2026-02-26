import { exec, execLines } from "../utils/shell.js";
import { BaseCollector, type CollectorResult } from "./base.js";

interface SuspiciousEntry {
  file: string;
  line: string;
  lineNumber: number;
  matchedPattern: string;
}

// Patterns with word boundaries to avoid false positives on substring matches
const DANGEROUS_PATTERNS = [
  "wget",
  "curl",
  "\\bncat\\b",
  "\\bnc\\s",
  "python.*http",
  "base64",
  "\\beval\\b",
  "/dev/tcp",
  "/dev/udp",
  "\\.onion",
];

const PROFILE_FILES = [
  "/etc/profile",
  "/etc/bash.bashrc",
  "/etc/environment",
  "/etc/rc.local",
];

const HOME_PROFILE_NAMES = [".bashrc", ".profile", ".bash_profile"];

export class ShellCollector extends BaseCollector {
  readonly module = "shell" as const;

  async collect(): Promise<CollectorResult> {
    const rawParts: string[] = [];
    const suspiciousEntries: SuspiciousEntry[] = [];

    // Build list of all files to scan
    const filesToScan: string[] = [...PROFILE_FILES];

    // Find home directories from /etc/passwd
    const homeLines = execLines("awk -F: '{print $6}' /etc/passwd 2>/dev/null | sort -u");
    for (const homeDir of homeLines) {
      for (const name of HOME_PROFILE_NAMES) {
        filesToScan.push(`${homeDir}/${name}`);
      }
    }

    // Add /etc/profile.d/* scripts
    const profileDFiles = execLines("ls /etc/profile.d/*.sh 2>/dev/null");
    filesToScan.push(...profileDFiles);

    // Build grep pattern (use extended regex for word boundaries)
    const grepPattern = "wget|curl|\\bncat\\b|\\bnc\\s|python.*http|base64|\\beval\\b|/dev/tcp|/dev/udp|\\.onion";

    // Scan each file
    for (const filePath of filesToScan) {
      const grepResult = exec(
        `grep -n -iE '${grepPattern}' "${filePath}" 2>/dev/null`,
      );
      if (!grepResult.stdout) continue;

      rawParts.push(`# ${filePath}\n${grepResult.stdout}`);

      const lines = grepResult.stdout.split("\n").filter((l) => l.length > 0);
      for (const hit of lines) {
        const colonIdx = hit.indexOf(":");
        if (colonIdx === -1) continue;

        const lineNumber = parseInt(hit.substring(0, colonIdx), 10);
        const lineText = hit.substring(colonIdx + 1);

        // Skip comment lines
        if (lineText.trim().startsWith("#")) continue;

        // Determine which pattern matched
        let matchedPattern = "unknown";
        for (const pattern of DANGEROUS_PATTERNS) {
          const regex = new RegExp(pattern, "i");
          if (regex.test(lineText)) {
            matchedPattern = pattern;
            break;
          }
        }

        suspiciousEntries.push({
          file: filePath,
          line: lineText,
          lineNumber,
          matchedPattern,
        });
      }
    }

    // Read /etc/environment
    const envResult = exec("cat /etc/environment 2>/dev/null");
    rawParts.push("# /etc/environment\n" + envResult.stdout);
    const etcEnvironment = envResult.stdout || "";

    // Read /etc/rc.local
    const rcResult = exec("cat /etc/rc.local 2>/dev/null");
    rawParts.push("# /etc/rc.local\n" + rcResult.stdout);
    const rcLocal = rcResult.stdout || "";

    return {
      module: this.module,
      data: {
        suspiciousEntries,
        etcEnvironment,
        rcLocal,
      },
      raw: rawParts.join("\n\n"),
    };
  }
}
