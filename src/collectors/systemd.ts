import { exec } from "../utils/shell.js";
import { BaseCollector, type CollectorResult } from "./base.js";

interface EnabledService {
  name: string;
  state: string;
}

interface ServiceFileInfo {
  name: string;
  path: string;
  content: string;
  execStart: string;
  restart: string;
  restartSec: string;
  standardOutput: string;
}

/** Common Ubuntu/systemd services that are considered standard. */
const STANDARD_SERVICES = new Set([
  "acpid.service",
  "apparmor.service",
  "apport.service",
  "atd.service",
  "blk-availability.service",
  "chrony.service",
  "cloud-config.service",
  "cloud-final.service",
  "cloud-init-local.service",
  "cloud-init.service",
  "console-setup.service",
  "cron.service",
  "dbus-org.freedesktop.login1.service",
  "dbus-org.freedesktop.resolve1.service",
  "dbus-org.freedesktop.thermald.service",
  "dbus-org.freedesktop.timesync1.service",
  "dbus-org.freedesktop.timedate1.service",
  "dbus.service",
  "e2scrub_reap.service",
  "emergency.service",
  "friendly-recovery.service",
  "fstrim.service",
  "fwupd.service",
  "getty@.service",
  "grub-common.service",
  "grub-initrd-fallback.service",
  "irqbalance.service",
  "keyboard-setup.service",
  "kmod-static-nodes.service",
  "lvm2-monitor.service",
  "ModemManager.service",
  "multipathd.service",
  "networkd-dispatcher.service",
  "NetworkManager.service",
  "networking.service",
  "open-iscsi.service",
  "open-vm-tools.service",
  "packagekit.service",
  "plymouth-quit-wait.service",
  "plymouth-quit.service",
  "plymouth-read-write.service",
  "polkit.service",
  "pollinate.service",
  "qemu-guest-agent.service",
  "rescue.service",
  "rsync.service",
  "rsyslog.service",
  "serial-getty@.service",
  "setvtrgb.service",
  "snapd.apparmor.service",
  "snapd.autoimport.service",
  "snapd.core-fixup.service",
  "snapd.recovery-chooser-trigger.service",
  "snapd.seeded.service",
  "snapd.service",
  "snapd.system-shutdown.service",
  "ssh.service",
  "sshd.service",
  "openssh-server.service",
  "sudo.service",
  "systemd-ask-password-console.service",
  "systemd-ask-password-wall.service",
  "systemd-fsck-root.service",
  "systemd-fsck@.service",
  "systemd-initctl.service",
  "systemd-journal-flush.service",
  "systemd-journald.service",
  "systemd-logind.service",
  "systemd-machine-id-commit.service",
  "systemd-modules-load.service",
  "systemd-networkd-wait-online.service",
  "systemd-networkd.service",
  "systemd-pstore.service",
  "systemd-random-seed.service",
  "systemd-remount-fs.service",
  "systemd-resolved.service",
  "systemd-sysctl.service",
  "systemd-sysusers.service",
  "systemd-timesyncd.service",
  "systemd-tmpfiles-clean.service",
  "systemd-tmpfiles-setup-dev.service",
  "systemd-tmpfiles-setup.service",
  "systemd-udev-trigger.service",
  "systemd-udevd.service",
  "systemd-update-utmp-runlevel.service",
  "systemd-update-utmp.service",
  "systemd-user-sessions.service",
  "thermald.service",
  "ua-reboot-cmds.service",
  "ubuntu-advantage.service",
  "udev.service",
  "udisks2.service",
  "ufw.service",
  "unattended-upgrades.service",
  "upower.service",
]);

export class SystemdCollector extends BaseCollector {
  readonly module = "systemd" as const;

  async collect(): Promise<CollectorResult> {
    const rawParts: string[] = [];

    // Get enabled services
    const listResult = exec(
      "systemctl list-unit-files --type=service --state=enabled --no-pager",
    );
    rawParts.push(listResult.stdout);

    const enabledServices = this.parseEnabledServices(listResult.stdout);

    // For each non-standard service, read the service file
    const serviceFiles: ServiceFileInfo[] = [];
    for (const svc of enabledServices) {
      if (STANDARD_SERVICES.has(svc.name)) continue;

      const fileInfo = this.readServiceFile(svc.name);
      if (fileInfo) {
        serviceFiles.push(fileInfo);
        rawParts.push(`--- ${fileInfo.path} ---\n${fileInfo.content}`);
      }
    }

    return {
      module: this.module,
      data: { enabledServices, serviceFiles },
      raw: rawParts.join("\n"),
    };
  }

  private parseEnabledServices(output: string): EnabledService[] {
    const services: EnabledService[] = [];
    if (!output) return services;

    const lines = output.split("\n");
    for (const line of lines) {
      const trimmed = line.trim();
      // Skip empty lines, header lines, and the summary footer
      if (!trimmed) continue;
      if (trimmed.startsWith("UNIT FILE")) continue;
      if (/^\d+ unit files? listed/.test(trimmed)) continue;

      const parts = trimmed.split(/\s+/);
      if (parts.length >= 2) {
        services.push({
          name: parts[0],
          state: parts[1],
        });
      }
    }

    return services;
  }

  private readServiceFile(serviceName: string): ServiceFileInfo | null {
    // Locate the unit file path via systemctl
    const showResult = exec(
      `systemctl show -p FragmentPath ${serviceName} 2>/dev/null`,
    );
    let path = "";
    if (showResult.success && showResult.stdout) {
      const match = showResult.stdout.match(/^FragmentPath=(.+)$/m);
      if (match && match[1]) {
        path = match[1];
      }
    }

    // Fallback common paths
    if (!path) {
      const candidates = [
        `/etc/systemd/system/${serviceName}`,
        `/lib/systemd/system/${serviceName}`,
        `/usr/lib/systemd/system/${serviceName}`,
      ];
      for (const candidate of candidates) {
        const testResult = exec(`test -f ${candidate} && echo exists`);
        if (testResult.stdout.includes("exists")) {
          path = candidate;
          break;
        }
      }
    }

    if (!path) return null;

    const catResult = exec(`cat ${path} 2>/dev/null`);
    const content = catResult.success ? catResult.stdout : "";

    return {
      name: serviceName,
      path,
      content,
      execStart: this.extractDirective(content, "ExecStart"),
      restart: this.extractDirective(content, "Restart"),
      restartSec: this.extractDirective(content, "RestartSec"),
      standardOutput: this.extractDirective(content, "StandardOutput"),
    };
  }

  private extractDirective(content: string, directive: string): string {
    const regex = new RegExp(`^${directive}=(.+)$`, "m");
    const match = content.match(regex);
    return match ? match[1].trim() : "";
  }
}
