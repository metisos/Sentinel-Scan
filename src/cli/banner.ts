import chalk from "chalk";
import { getPlatformInfo } from "../utils/platform.js";
import { isRoot } from "../utils/permissions.js";

const ASCII_ART = `
  ██████ ▓█████  ███▄    █ ▄▄▄█████▓ ██▓ ███▄    █ ▓█████  ██▓
▒██    ▒ ▓█   ▀  ██ ▀█   █ ▓  ██▒ ▓▒▓██▒ ██ ▀█   █ ▓█   ▀ ▓██▒
░ ▓██▄   ▒███   ▓██  ▀█ ██▒▒ ▓██░ ▒░▒██▒▓██  ▀█ ██▒▒███   ▒██░
  ▒   ██▒▒▓█  ▄ ▓██▒  ▐▌██▒░ ▓██▓ ░ ░██░▓██▒  ▐▌██▒▒▓█  ▄ ▒██░
▒██████▒▒░▒████▒▒██░   ▓██░  ▒██▒ ░ ░██░▒██░   ▓██░░▒████▒░██████▒
▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ▒░   ▒ ▒   ▒ ░░   ░▓  ░ ▒░   ▒ ▒ ░░ ▒░ ░░ ▒░▓  ░
░ ░▒  ░ ░ ░ ░  ░░ ░░   ░ ▒░    ░     ▒ ░░ ░░   ░ ▒░ ░ ░  ░░ ░ ▒  ░
░  ░  ░     ░      ░   ░ ░   ░       ▒ ░   ░   ░ ░    ░     ░ ░
      ░     ░  ░         ░           ░           ░    ░  ░    ░  ░`;

export function printBanner(): void {
  const platform = getPlatformInfo();

  console.log(chalk.red(ASCII_ART));
  console.log("");
  console.log(
    chalk.bold("  Sentinel") +
      chalk.dim(" — Server Security Scanner v0.1.0")
  );
  console.log(
    chalk.dim(
      `  ${platform.hostname} | ${platform.os} | ${platform.ip}`
    )
  );

  if (!isRoot()) {
    console.log(
      chalk.yellow(
        "\n  Warning: Not running as root. Some checks may be incomplete."
      )
    );
  }

  console.log("");
}
