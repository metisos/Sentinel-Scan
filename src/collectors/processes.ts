import { exec } from "../utils/shell.js";
import { BaseCollector, type CollectorResult } from "./base.js";

interface ProcessInfo {
  user: string;
  pid: number;
  cpu: number;
  mem: number;
  vsz: number;
  rss: number;
  tty: string;
  stat: string;
  start: string;
  time: string;
  command: string;
}

export class ProcessCollector extends BaseCollector {
  readonly module = "processes" as const;

  async collect(): Promise<CollectorResult> {
    const result = exec("ps auxf");
    const raw = result.stdout;
    const processes: ProcessInfo[] = [];

    if (raw) {
      const lines = raw.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // Skip header line
        if (i === 0 && line.startsWith("USER")) continue;
        // Skip empty lines
        if (!line.trim()) continue;
        // Skip kernel threads (lines with [bracketed] commands)
        if (/\[.*\]$/.test(line.trim())) continue;

        const parsed = this.parseLine(line);
        if (parsed) {
          processes.push(parsed);
        }
      }
    }

    return {
      module: this.module,
      data: { processes },
      raw,
    };
  }

  private parseLine(line: string): ProcessInfo | null {
    // ps auxf columns are fixed-width. The first 10 fields are whitespace-delimited;
    // the 11th (COMMAND) is the rest of the line and may contain spaces.
    const match = line.match(
      /^(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$/,
    );
    if (!match) return null;

    return {
      user: match[1],
      pid: parseInt(match[2], 10),
      cpu: parseFloat(match[3]),
      mem: parseFloat(match[4]),
      vsz: parseInt(match[5], 10),
      rss: parseInt(match[6], 10),
      tty: match[7],
      stat: match[8],
      start: match[9],
      time: match[10],
      command: match[11].trim(),
    };
  }
}
