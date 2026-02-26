import ora, { type Ora } from "ora";
import chalk from "chalk";
import type { ModuleName } from "../core/models.js";
import type { ScanCallbacks } from "../core/context.js";

const MODULE_LABELS: Record<ModuleName, string> = {
  processes: "Scanning processes",
  network: "Checking network connections",
  systemd: "Inspecting systemd services",
  crontabs: "Checking crontabs",
  rootkit: "Checking for rootkits",
  ssh: "Auditing SSH configuration",
  shell: "Checking shell profiles",
  filesystem: "Sweeping filesystem",
  firewall: "Checking firewall status",
  credentials: "Scanning for exposed credentials",
};

export function createProgressCallbacks(): ScanCallbacks {
  let spinner: Ora | null = null;
  let completedCount = 0;
  let totalModules = 0;

  return {
    onModuleStart(module: ModuleName) {
      totalModules = Math.max(totalModules, completedCount + 1);
      const label = MODULE_LABELS[module] ?? module;
      if (spinner) {
        spinner.text = chalk.dim(`[${completedCount + 1}/${totalModules}] `) + label;
      } else {
        spinner = ora({
          text: chalk.dim(`[${completedCount + 1}/${totalModules}] `) + label,
          stream: process.stderr,
        }).start();
      }
    },
    onModuleComplete(module: ModuleName, durationMs: number) {
      completedCount++;
      const label = MODULE_LABELS[module] ?? module;
      if (spinner) {
        spinner.succeed(
          `${label} ${chalk.dim(`(${durationMs}ms)`)}`
        );
        spinner = null;
      }
    },
  };
}
