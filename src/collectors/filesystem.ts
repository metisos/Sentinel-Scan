import { exec, execLines } from "../utils/shell.js";
import { BaseCollector, type CollectorResult } from "./base.js";

interface SuspiciousExecutable {
  path: string;
  size: string;
}

interface SuidBinary {
  path: string;
  packaged: boolean;
}

export class FilesystemCollector extends BaseCollector {
  readonly module = "filesystem" as const;

  async collect(): Promise<CollectorResult> {
    const rawParts: string[] = [];

    // --- Executable files in temp / volatile directories ---
    const tempDirs = ["/tmp", "/var/tmp", "/dev/shm"];
    const suspiciousExecutables: SuspiciousExecutable[] = [];

    for (const dir of tempDirs) {
      const lines = execLines(
        `find "${dir}" -type f -executable -printf '%p\\t%s\\n' 2>/dev/null`,
      );
      rawParts.push(`# executables in ${dir}\n` + lines.join("\n"));
      for (const line of lines) {
        const [path, size] = line.split("\t");
        if (path) {
          suspiciousExecutables.push({ path, size: size || "0" });
        }
      }
    }

    // /var with maxdepth 2
    const varLines = execLines(
      "find /var -maxdepth 2 -type f -executable -printf '%p\\t%s\\n' 2>/dev/null",
    );
    rawParts.push("# executables in /var (maxdepth 2)\n" + varLines.join("\n"));
    for (const line of varLines) {
      const [path, size] = line.split("\t");
      if (path) {
        suspiciousExecutables.push({ path, size: size || "0" });
      }
    }

    // --- Hidden directories ---
    const hiddenDirLines = execLines(
      'find / -maxdepth 2 -type d -name ".*" -not -name "." -not -name ".." 2>/dev/null',
    );
    const hiddenDirRootLines = execLines(
      'find /root -maxdepth 2 -type d -name ".*" -not -name "." -not -name ".." 2>/dev/null',
    );
    const hiddenDirSet = new Set([...hiddenDirLines, ...hiddenDirRootLines]);
    const hiddenDirs = Array.from(hiddenDirSet);
    rawParts.push("# hidden directories\n" + hiddenDirs.join("\n"));

    // --- World-writable files in system paths ---
    const systemPaths = ["/usr/bin", "/usr/sbin", "/etc"];
    const worldWritable: string[] = [];
    for (const sysPath of systemPaths) {
      const wwLines = execLines(
        `find "${sysPath}" -type f -perm -o+w 2>/dev/null`,
      );
      worldWritable.push(...wwLines);
    }
    rawParts.push("# world-writable files\n" + worldWritable.join("\n"));

    // --- SUID binaries ---
    const suidLines = execLines(
      "find / -type f -perm -4000 2>/dev/null",
      60_000,
    );
    rawParts.push("# SUID binaries\n" + suidLines.join("\n"));

    const suidBinaries: SuidBinary[] = [];
    for (const binPath of suidLines) {
      const packaged = this.isPackaged(binPath);
      suidBinaries.push({ path: binPath, packaged });
    }

    // --- Recently modified system binaries (last 30 days) ---
    const recentlyModified = execLines(
      "find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -mtime -30 2>/dev/null",
    );
    rawParts.push("# recently modified binaries\n" + recentlyModified.join("\n"));

    return {
      module: this.module,
      data: {
        suspiciousExecutables,
        hiddenDirs,
        worldWritable,
        suidBinaries,
        recentlyModified,
      },
      raw: rawParts.join("\n\n"),
    };
  }

  private isPackaged(filePath: string): boolean {
    // Try dpkg first (Debian/Ubuntu)
    const dpkgResult = exec(`dpkg -S "${filePath}" 2>/dev/null`);
    if (dpkgResult.success && dpkgResult.stdout.length > 0) return true;

    // Try rpm (RHEL/CentOS/Fedora)
    const rpmResult = exec(`rpm -qf "${filePath}" 2>/dev/null`);
    if (rpmResult.success && rpmResult.stdout.length > 0 && !rpmResult.stdout.includes("not owned")) {
      return true;
    }

    return false;
  }
}
