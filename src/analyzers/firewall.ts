import { Severity, type Finding } from "../core/models.js";
import type { CollectorResult } from "../collectors/base.js";
import type { ThreatDB } from "../threats/index.js";
import { BaseAnalyzer } from "./base.js";

interface UfwData {
  active: boolean;
  rules: string;
}

interface Fail2banData {
  running: boolean;
  jails: string[];
  sshdStatus: string;
}

export class FirewallAnalyzer extends BaseAnalyzer {
  readonly module = "firewall" as const;

  analyze(data: CollectorResult, _threatDB: ThreatDB): Finding[] {
    const findings: Finding[] = [];
    let counter = 0;

    const nextId = (): string => {
      counter++;
      return `FW-${String(counter).padStart(3, "0")}`;
    };

    const ufw = (data.data.ufw ?? { active: false, rules: "" }) as UfwData;
    const fail2ban = (data.data.fail2ban ?? { running: false, jails: [], sshdStatus: "" }) as Fail2banData;
    const iptables = (data.data.iptables ?? "") as string;

    // 1. UFW not active
    if (!ufw.active) {
      findings.push({
        id: nextId(),
        module: this.module,
        severity: Severity.HIGH,
        title: `UFW firewall is not active`,
        description: `The Uncomplicated Firewall (UFW) is not active. Without a host firewall, all listening services are exposed to the network. This significantly increases the attack surface.`,
        details: { ufwActive: false },
        remediation: `Enable UFW with sensible defaults: "ufw default deny incoming && ufw default allow outgoing && ufw allow ssh && ufw --force enable". Adjust rules based on required services.`,
      });
    }

    // 2. No fail2ban
    if (!fail2ban.running) {
      findings.push({
        id: nextId(),
        module: this.module,
        severity: Severity.MEDIUM,
        title: `Fail2ban is not running`,
        description: `Fail2ban is not installed or not running. Without fail2ban, the server has no automated brute-force protection for SSH and other services.`,
        details: { fail2banRunning: false },
        remediation: `Install and configure fail2ban: "apt install fail2ban -y". Enable at minimum the sshd jail by creating /etc/fail2ban/jail.local with "[sshd]\\nenabled = true".`,
      });
    } else {
      // fail2ban is running but check if sshd jail is active
      const hasSshdJail = fail2ban.jails.some(
        (j) => j.toLowerCase() === "sshd" || j.toLowerCase() === "ssh",
      );
      if (!hasSshdJail) {
        findings.push({
          id: nextId(),
          module: this.module,
          severity: Severity.MEDIUM,
          title: `Fail2ban sshd jail is not active`,
          description: `Fail2ban is running but the sshd jail is not active. SSH brute-force attacks will not be automatically blocked.`,
          details: { jails: fail2ban.jails },
          remediation: `Enable the sshd jail in /etc/fail2ban/jail.local: "[sshd]\\nenabled = true" and restart fail2ban.`,
        });
      }
    }

    // 3. SSH not restricted (open to 0.0.0.0)
    if (this.isSshOpenToAll(ufw, iptables)) {
      findings.push({
        id: nextId(),
        module: this.module,
        severity: Severity.MEDIUM,
        title: `SSH is not restricted by firewall`,
        description: `SSH (port 22) appears to be accessible from any source address (0.0.0.0/0). Restricting SSH access to known IP ranges reduces exposure to brute-force attacks and zero-day exploits.`,
        details: { sshRestricted: false },
        remediation: `Restrict SSH access to specific IP addresses or ranges: "ufw delete allow ssh && ufw allow from <trusted-ip>/32 to any port 22". Consider using a VPN or bastion host for remote access.`,
      });
    }

    return findings;
  }

  /** Determine if SSH is open to all addresses based on firewall rules. */
  private isSshOpenToAll(ufw: UfwData, iptables: string): boolean {
    // If UFW is active, check its rules for SSH restrictions
    if (ufw.active && ufw.rules) {
      const lines = ufw.rules.split("\n");
      for (const line of lines) {
        // Look for SSH/22 rules
        if (!/\b22\b/.test(line) && !/\bssh\b/i.test(line)) continue;

        // If the rule has ALLOW IN and has "Anywhere" as the source, SSH is open
        if (/ALLOW\s+IN/i.test(line) && /Anywhere/i.test(line)) {
          return true;
        }
      }
      // UFW is active but no open SSH rule found — SSH is restricted or blocked
      return false;
    }

    // If UFW is not active, check iptables for SSH restrictions
    if (iptables) {
      const lines = iptables.split("\n");
      let inInputChain = false;

      for (const line of lines) {
        if (line.startsWith("Chain INPUT")) {
          inInputChain = true;
          continue;
        }
        if (line.startsWith("Chain")) {
          inInputChain = false;
          continue;
        }

        if (!inInputChain) continue;

        // Look for rules accepting traffic on port 22 from 0.0.0.0/0
        if (/dpt:22/.test(line) && /0\.0\.0\.0\/0/.test(line) && /ACCEPT/.test(line)) {
          return true;
        }
      }

      // If iptables INPUT default policy is ACCEPT and no specific SSH rule, SSH is open
      if (/Chain INPUT.*policy ACCEPT/i.test(iptables)) {
        return true;
      }
    }

    // No firewall data — assume SSH is open if UFW is not active
    if (!ufw.active) {
      return true;
    }

    return false;
  }
}
