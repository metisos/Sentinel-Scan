import { exec, execLines } from "../utils/shell.js";
import { BaseCollector, type CollectorResult } from "./base.js";

interface UserCrontab {
  user: string;
  content: string;
}

export class CrontabCollector extends BaseCollector {
  readonly module = "crontabs" as const;

  async collect(): Promise<CollectorResult> {
    const rawParts: string[] = [];

    // 1. Root crontab
    const rootCrontabResult = exec("crontab -l 2>/dev/null");
    const rootCrontab = rootCrontabResult.stdout || "";
    rawParts.push("=== root crontab ===\n" + rootCrontab);

    // 2. System crontab (/etc/crontab)
    const systemCrontabResult = exec("cat /etc/crontab 2>/dev/null");
    const systemCrontab = systemCrontabResult.stdout || "";
    rawParts.push("=== /etc/crontab ===\n" + systemCrontab);

    // 3. All files in /etc/cron.d/
    const cronDirs = this.readCronDir();
    for (const entry of cronDirs) {
      rawParts.push(`=== /etc/cron.d/${entry.name} ===\n${entry.content}`);
    }

    // 4. All user crontabs
    const userCrontabs = this.readUserCrontabs();
    for (const entry of userCrontabs) {
      rawParts.push(`=== crontab for ${entry.user} ===\n${entry.content}`);
    }

    return {
      module: this.module,
      data: {
        rootCrontab,
        systemCrontab,
        cronDirs,
        userCrontabs,
      },
      raw: rawParts.join("\n"),
    };
  }

  private readCronDir(): Array<{ name: string; content: string }> {
    const entries: Array<{ name: string; content: string }> = [];

    const fileList = execLines("ls /etc/cron.d/ 2>/dev/null");
    for (const filename of fileList) {
      if (!filename.trim()) continue;
      const catResult = exec(`cat /etc/cron.d/${filename} 2>/dev/null`);
      if (catResult.stdout) {
        entries.push({
          name: filename.trim(),
          content: catResult.stdout,
        });
      }
    }

    return entries;
  }

  private readUserCrontabs(): UserCrontab[] {
    const crontabs: UserCrontab[] = [];

    // Get list of users with login shells from /etc/passwd
    const passwdLines = execLines("cat /etc/passwd 2>/dev/null");
    const users: string[] = [];

    for (const line of passwdLines) {
      const fields = line.split(":");
      if (fields.length < 7) continue;
      const username = fields[0];
      const shell = fields[6];

      // Skip system users with nologin/false shells, but include root
      // (root crontab is already captured separately)
      if (username === "root") continue;
      if (shell.endsWith("/nologin") || shell.endsWith("/false")) continue;

      users.push(username);
    }

    // Also check the crontab spool directory directly for any user crontabs
    const spoolFiles = execLines("ls /var/spool/cron/crontabs/ 2>/dev/null");
    for (const file of spoolFiles) {
      const username = file.trim();
      if (!username || username === "root") continue;
      if (!users.includes(username)) {
        users.push(username);
      }
    }

    for (const user of users) {
      const result = exec(`crontab -u ${user} -l 2>/dev/null`);
      if (result.success && result.stdout) {
        crontabs.push({
          user,
          content: result.stdout,
        });
      }
    }

    return crontabs;
  }
}
