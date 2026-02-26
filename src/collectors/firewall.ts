import { exec, execLines } from "../utils/shell.js";
import { BaseCollector, type CollectorResult } from "./base.js";

export class FirewallCollector extends BaseCollector {
  readonly module = "firewall" as const;

  async collect(): Promise<CollectorResult> {
    const rawParts: string[] = [];

    // --- UFW ---
    const ufwResult = exec("ufw status verbose 2>/dev/null");
    rawParts.push("# ufw status verbose\n" + ufwResult.stdout);

    const ufwActive =
      ufwResult.success && ufwResult.stdout.toLowerCase().includes("status: active");
    const ufw = {
      active: ufwActive,
      rules: ufwResult.stdout || "",
    };

    // --- Fail2ban ---
    const f2bStatusResult = exec("fail2ban-client status 2>/dev/null");
    rawParts.push("# fail2ban-client status\n" + f2bStatusResult.stdout);

    const f2bRunning = f2bStatusResult.success && f2bStatusResult.stdout.length > 0;

    // Parse jail list from fail2ban-client status output
    const jails: string[] = [];
    if (f2bRunning && f2bStatusResult.stdout) {
      const lines = f2bStatusResult.stdout.split("\n");
      for (const line of lines) {
        const match = line.match(/Jail list:\s*(.+)/i);
        if (match) {
          const jailNames = match[1].split(",").map((j) => j.trim()).filter((j) => j.length > 0);
          jails.push(...jailNames);
          break;
        }
      }
    }

    const f2bSshdResult = exec("fail2ban-client status sshd 2>/dev/null");
    rawParts.push("# fail2ban-client status sshd\n" + f2bSshdResult.stdout);

    const fail2ban = {
      running: f2bRunning,
      jails,
      sshdStatus: f2bSshdResult.stdout || "",
    };

    // --- iptables ---
    const iptablesResult = exec("iptables -L -n --line-numbers 2>/dev/null");
    rawParts.push("# iptables -L -n --line-numbers\n" + iptablesResult.stdout);

    const iptables = iptablesResult.stdout || "";

    return {
      module: this.module,
      data: {
        ufw,
        fail2ban,
        iptables,
      },
      raw: rawParts.join("\n\n"),
    };
  }
}
