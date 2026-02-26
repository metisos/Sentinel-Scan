import { execSync } from "node:child_process";

export interface ShellResult {
  stdout: string;
  success: boolean;
  exitCode: number;
}

export function exec(command: string, timeoutMs = 30_000): ShellResult {
  try {
    const stdout = execSync(command, {
      timeout: timeoutMs,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
      maxBuffer: 10 * 1024 * 1024,
    });
    return { stdout: stdout.trim(), success: true, exitCode: 0 };
  } catch (err: unknown) {
    const e = err as { stdout?: string; status?: number };
    return {
      stdout: typeof e.stdout === "string" ? e.stdout.trim() : "",
      success: false,
      exitCode: typeof e.status === "number" ? e.status : 1,
    };
  }
}

export function execLines(command: string, timeoutMs = 30_000): string[] {
  const result = exec(command, timeoutMs);
  if (!result.stdout) return [];
  return result.stdout.split("\n").filter((l) => l.length > 0);
}
