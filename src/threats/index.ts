import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadJSON<T>(filename: string): T {
  const raw = readFileSync(join(__dirname, filename), "utf-8");
  return JSON.parse(raw) as T;
}

interface HashEntry {
  name: string;
  family: string;
  severity: string;
}

interface IPEntry {
  name: string;
  type: string;
  severity: string;
}

interface ProcessEntry {
  pattern: string;
  name: string;
  severity: string;
  family: string;
  regex?: boolean;
}

interface PathEntry {
  path: string;
  name: string;
  severity: string;
}

interface ServiceEntry {
  name: string;
  description: string;
  severity: string;
}

interface PortEntry {
  port: number;
  name: string;
  severity: string;
  direction: string;
}

export class ThreatDB {
  private hashes: Record<string, HashEntry>;
  private ips: Record<string, IPEntry>;
  private processes: ProcessEntry[];
  private paths: PathEntry[];
  private services: ServiceEntry[];
  private ports: PortEntry[];

  constructor() {
    const hashData = loadJSON<{ entries: Record<string, HashEntry> }>("known_hashes.json");
    this.hashes = hashData.entries;

    const ipData = loadJSON<{ entries: Record<string, IPEntry> }>("known_ips.json");
    this.ips = ipData.entries;

    const procData = loadJSON<{ entries: ProcessEntry[] }>("known_processes.json");
    this.processes = procData.entries;

    const pathData = loadJSON<{ entries: PathEntry[] }>("known_paths.json");
    this.paths = pathData.entries;

    const svcData = loadJSON<{ entries: ServiceEntry[] }>("known_services.json");
    this.services = svcData.entries;

    const portData = loadJSON<{ entries: PortEntry[] }>("known_ports.json");
    this.ports = portData.entries;
  }

  lookupHash(hash: string): HashEntry | null {
    return this.hashes[hash.toLowerCase()] ?? null;
  }

  lookupIP(ip: string): IPEntry | null {
    return this.ips[ip] ?? null;
  }

  matchProcess(name: string, cmdline: string): ProcessEntry | null {
    const combined = `${name} ${cmdline}`.toLowerCase();
    for (const entry of this.processes) {
      if (entry.regex) {
        if (new RegExp(entry.pattern, "i").test(combined)) return entry;
      } else {
        if (combined.includes(entry.pattern.toLowerCase())) return entry;
      }
    }
    return null;
  }

  matchPath(filePath: string): PathEntry | null {
    for (const entry of this.paths) {
      if (filePath.startsWith(entry.path) || filePath === entry.path.replace(/\/$/, "")) {
        return entry;
      }
    }
    return null;
  }

  matchService(serviceName: string): ServiceEntry | null {
    for (const entry of this.services) {
      if (serviceName === entry.name) return entry;
    }
    return null;
  }

  matchPort(port: number, direction: "listening" | "outbound"): PortEntry | null {
    const dir = direction === "listening" ? "listening" : "outbound";
    for (const entry of this.ports) {
      if (entry.port === port && (entry.direction === dir || entry.direction === "outbound")) {
        return entry;
      }
    }
    return null;
  }

  getAllPaths(): PathEntry[] {
    return this.paths;
  }
}
