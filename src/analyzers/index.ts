import type { ModuleName } from "../core/models.js";
import type { BaseAnalyzer } from "./base.js";
import { ProcessAnalyzer } from "./processes.js";
import { NetworkAnalyzer } from "./network.js";
import { SystemdAnalyzer } from "./systemd.js";
import { CrontabAnalyzer } from "./crontabs.js";
import { RootkitAnalyzer } from "./rootkit.js";
import { SSHAnalyzer } from "./ssh.js";
import { ShellAnalyzer } from "./shell.js";
import { FilesystemAnalyzer } from "./filesystem.js";
import { FirewallAnalyzer } from "./firewall.js";
import { CredentialAnalyzer } from "./credentials.js";

export const ANALYZER_REGISTRY: Record<ModuleName, BaseAnalyzer> = {
  processes: new ProcessAnalyzer(),
  network: new NetworkAnalyzer(),
  systemd: new SystemdAnalyzer(),
  crontabs: new CrontabAnalyzer(),
  rootkit: new RootkitAnalyzer(),
  ssh: new SSHAnalyzer(),
  shell: new ShellAnalyzer(),
  filesystem: new FilesystemAnalyzer(),
  firewall: new FirewallAnalyzer(),
  credentials: new CredentialAnalyzer(),
};
