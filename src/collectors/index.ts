import type { ModuleName } from "../core/models.js";
import type { BaseCollector } from "./base.js";
import { ProcessCollector } from "./processes.js";
import { NetworkCollector } from "./network.js";
import { SystemdCollector } from "./systemd.js";
import { CrontabCollector } from "./crontabs.js";
import { RootkitCollector } from "./rootkit.js";
import { SshCollector } from "./ssh.js";
import { ShellCollector } from "./shell.js";
import { FilesystemCollector } from "./filesystem.js";
import { FirewallCollector } from "./firewall.js";
import { CredentialsCollector } from "./credentials.js";

export const COLLECTOR_REGISTRY: Record<ModuleName, BaseCollector> = {
  processes: new ProcessCollector(),
  network: new NetworkCollector(),
  systemd: new SystemdCollector(),
  crontabs: new CrontabCollector(),
  rootkit: new RootkitCollector(),
  ssh: new SshCollector(),
  shell: new ShellCollector(),
  filesystem: new FilesystemCollector(),
  firewall: new FirewallCollector(),
  credentials: new CredentialsCollector(),
};
