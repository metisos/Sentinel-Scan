export enum Severity {
  INFO = 0,
  LOW = 1,
  MEDIUM = 2,
  HIGH = 3,
  CRITICAL = 4,
}

export const severityLabel: Record<Severity, string> = {
  [Severity.INFO]: "INFO",
  [Severity.LOW]: "LOW",
  [Severity.MEDIUM]: "MEDIUM",
  [Severity.HIGH]: "HIGH",
  [Severity.CRITICAL]: "CRITICAL",
};

export interface Finding {
  id: string;
  module: string;
  severity: Severity;
  title: string;
  description: string;
  details?: Record<string, unknown>;
  remediation?: string;
}

export interface ModuleResult {
  module: string;
  findings: Finding[];
  rawData: Record<string, unknown>;
  durationMs: number;
  error?: string;
}

export interface ScanResult {
  version: string;
  timestamp: string;
  hostname: string;
  os: string;
  ip: string;
  modules: ModuleResult[];
  findings: Finding[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    status: "CLEAN" | "INFORMATIONAL" | "WARNINGS" | "THREATS_FOUND" | "COMPROMISED";
    maxSeverity: Severity;
  };
  durationMs: number;
}

export type ModuleName =
  | "processes"
  | "network"
  | "systemd"
  | "crontabs"
  | "rootkit"
  | "ssh"
  | "shell"
  | "filesystem"
  | "firewall"
  | "credentials";

export const ALL_MODULES: ModuleName[] = [
  "processes",
  "network",
  "systemd",
  "crontabs",
  "rootkit",
  "ssh",
  "shell",
  "filesystem",
  "firewall",
  "credentials",
];

export type OutputFormat = "terminal" | "json" | "markdown";

export interface ScanOptions {
  modules?: ModuleName[];
  format?: OutputFormat;
  noBanner?: boolean;
  ai?: boolean;
  localOnly?: boolean;
}
