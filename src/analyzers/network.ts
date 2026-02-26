import { Severity, type Finding } from "../core/models.js";
import type { CollectorResult } from "../collectors/base.js";
import type { ThreatDB } from "../threats/index.js";
import { BaseAnalyzer } from "./base.js";

interface ListeningPort {
  proto: string;
  localAddr: string;
  localPort: number;
  process: string;
}

interface ActiveConnection {
  localAddr: string;
  localPort: number;
  remoteAddr: string;
  remotePort: number;
  process: string;
  state: string;
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

/** Remote ports commonly associated with botnet scanning activity. */
const BOTNET_SCAN_PORTS = new Set([23, 2323, 37215]);

export class NetworkAnalyzer extends BaseAnalyzer {
  readonly module = "network" as const;

  analyze(data: CollectorResult, threatDB: ThreatDB): Finding[] {
    const findings: Finding[] = [];
    const listening = (data.data.listening ?? []) as ListeningPort[];
    const connections = (data.data.connections ?? []) as ActiveConnection[];
    let counter = 0;

    const nextId = (): string => {
      counter++;
      return `NET-${String(counter).padStart(3, "0")}`;
    };

    // --- Analyze active outbound connections ---
    for (const conn of connections) {
      // 1. Check remote IP against threat database
      const ipThreat = threatDB.lookupIP(conn.remoteAddr);
      if (ipThreat) {
        findings.push({
          id: nextId(),
          module: this.module,
          severity: toSeverity(ipThreat.severity),
          title: `Connection to known malicious IP: ${conn.remoteAddr}`,
          description: `Outbound connection from ${conn.localAddr}:${conn.localPort} to ${conn.remoteAddr}:${conn.remotePort} (process: "${conn.process}"). Threat: "${ipThreat.name}" (type: ${ipThreat.type}).`,
          details: { connection: conn, threat: ipThreat },
          remediation: `Block the IP ${conn.remoteAddr} at the firewall level. Kill the responsible process and investigate how the connection was initiated.`,
        });
      }

      // 2. Check outbound port against threat database
      const portThreat = threatDB.matchPort(conn.remotePort, "outbound");
      if (portThreat) {
        findings.push({
          id: nextId(),
          module: this.module,
          severity: toSeverity(portThreat.severity),
          title: `Outbound connection to suspicious port ${conn.remotePort}`,
          description: `Connection to ${conn.remoteAddr}:${conn.remotePort} (process: "${conn.process}") matches threat database port entry "${portThreat.name}".`,
          details: { connection: conn, threat: portThreat },
          remediation: `Investigate process "${conn.process}" and the remote endpoint. Block port ${conn.remotePort} outbound if not required.`,
        });
      }

      // 3. Flag botnet scanning ports
      if (BOTNET_SCAN_PORTS.has(conn.remotePort)) {
        findings.push({
          id: nextId(),
          module: this.module,
          severity: Severity.HIGH,
          title: `Outbound connection to botnet-associated port ${conn.remotePort}`,
          description: `Process "${conn.process}" is connecting to ${conn.remoteAddr}:${conn.remotePort}. Ports 23, 2323, and 37215 are commonly used for Telnet-based botnet scanning (Mirai, Hajime).`,
          details: { connection: conn, port: conn.remotePort },
          remediation: `Immediately investigate process "${conn.process}". Block outbound traffic to port ${conn.remotePort}. Check for IoT botnet malware.`,
        });
      }
    }

    // --- Analyze listening ports ---
    for (const lp of listening) {
      // 4. Check listening port against threat database
      const portThreat = threatDB.matchPort(lp.localPort, "listening");
      if (portThreat) {
        findings.push({
          id: nextId(),
          module: this.module,
          severity: toSeverity(portThreat.severity),
          title: `Suspicious listening port ${lp.localPort}`,
          description: `Port ${lp.localPort} is listening on ${lp.localAddr} (process: "${lp.process}"). Matches threat database entry "${portThreat.name}".`,
          details: { listening: lp, threat: portThreat },
          remediation: `Investigate process "${lp.process}" listening on port ${lp.localPort}. Stop the service if it is not expected.`,
        });
      }

      // 5. Flag any high port (> 1024) listening on all interfaces
      if (
        lp.localPort > 1024 &&
        (lp.localAddr === "0.0.0.0" || lp.localAddr === "*" || lp.localAddr === "::")
      ) {
        findings.push({
          id: nextId(),
          module: this.module,
          severity: Severity.INFO,
          title: `High port ${lp.localPort} listening on all interfaces`,
          description: `Port ${lp.localPort} is listening on ${lp.localAddr} (process: "${lp.process}"). Non-standard ports exposed on all interfaces should be reviewed.`,
          details: { listening: lp },
          remediation: `Verify that port ${lp.localPort} is intentionally exposed. If not needed externally, bind it to 127.0.0.1 or restrict with a firewall rule.`,
        });
      }
    }

    return findings;
  }
}
