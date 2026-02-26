import { exec } from "../utils/shell.js";
import { BaseCollector, type CollectorResult } from "./base.js";

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

export class NetworkCollector extends BaseCollector {
  readonly module = "network" as const;

  async collect(): Promise<CollectorResult> {
    const listeningResult = exec("ss -tlnp");
    const connectionsResult = exec("ss -tnp");

    const rawParts: string[] = [];
    if (listeningResult.stdout) rawParts.push(listeningResult.stdout);
    if (connectionsResult.stdout) rawParts.push(connectionsResult.stdout);
    const raw = rawParts.join("\n---\n");

    const listening = this.parseListening(listeningResult.stdout);
    const connections = this.parseConnections(connectionsResult.stdout);

    return {
      module: this.module,
      data: { listening, connections },
      raw,
    };
  }

  private parseListening(output: string): ListeningPort[] {
    const results: ListeningPort[] = [];
    if (!output) return results;

    const lines = output.split("\n");
    for (const line of lines) {
      // Skip header and empty lines
      if (!line.trim() || line.startsWith("State") || line.startsWith("Netid")) continue;

      const parts = line.trim().split(/\s+/);
      // ss -tlnp output: State Recv-Q Send-Q Local-Address:Port Peer-Address:Port Process
      if (parts.length < 5) continue;

      const localField = parts[3];
      const { addr, port } = this.parseAddrPort(localField);
      if (port < 0) continue;

      const process = this.extractProcess(line);

      results.push({
        proto: "tcp",
        localAddr: addr,
        localPort: port,
        process,
      });
    }

    return results;
  }

  private parseConnections(output: string): ActiveConnection[] {
    const results: ActiveConnection[] = [];
    if (!output) return results;

    const lines = output.split("\n");
    for (const line of lines) {
      // Skip header and empty lines
      if (!line.trim() || line.startsWith("State") || line.startsWith("Netid")) continue;

      const parts = line.trim().split(/\s+/);
      // ss -tnp output: State Recv-Q Send-Q Local-Address:Port Peer-Address:Port Process
      if (parts.length < 5) continue;

      const state = parts[0];
      const localField = parts[3];
      const remoteField = parts[4];

      const local = this.parseAddrPort(localField);
      const remote = this.parseAddrPort(remoteField);
      if (local.port < 0 || remote.port < 0) continue;

      // Exclude localhost connections
      if (this.isLocalhost(remote.addr)) continue;

      const process = this.extractProcess(line);

      results.push({
        localAddr: local.addr,
        localPort: local.port,
        remoteAddr: remote.addr,
        remotePort: remote.port,
        process,
        state,
      });
    }

    return results;
  }

  private parseAddrPort(field: string): { addr: string; port: number } {
    // Handle IPv6 format like [::1]:22 or [::]:80
    const ipv6Match = field.match(/^\[(.+)\]:(\d+)$/);
    if (ipv6Match) {
      return { addr: ipv6Match[1], port: parseInt(ipv6Match[2], 10) };
    }

    // Handle IPv4 format or *:port — last colon separates addr from port
    const lastColon = field.lastIndexOf(":");
    if (lastColon === -1) return { addr: field, port: -1 };

    const addr = field.substring(0, lastColon);
    const port = parseInt(field.substring(lastColon + 1), 10);
    return { addr, port: isNaN(port) ? -1 : port };
  }

  private extractProcess(line: string): string {
    // Process info is in the format: users:(("name",pid=123,fd=4))
    const match = line.match(/users:\(\((.+?)\)\)/);
    if (!match) return "";
    // Extract the process name from "name",pid=...,fd=...
    const nameMatch = match[1].match(/"([^"]+)"/);
    return nameMatch ? nameMatch[1] : match[1];
  }

  private isLocalhost(addr: string): boolean {
    return (
      addr === "127.0.0.1" ||
      addr === "::1" ||
      addr === "localhost" ||
      addr.startsWith("127.")
    );
  }
}
