import { exec, execLines } from "../utils/shell.js";
import { BaseCollector, type CollectorResult } from "./base.js";

interface KernelModule {
  name: string;
  size: number;
  usedBy: string;
}

export class RootkitCollector extends BaseCollector {
  readonly module = "rootkit" as const;

  async collect(): Promise<CollectorResult> {
    const rawParts: string[] = [];

    // 1. Check /etc/ld.so.preload
    const ldPreloadResult = exec("cat /etc/ld.so.preload 2>/dev/null");
    const ldPreload = ldPreloadResult.stdout || "";
    rawParts.push("=== /etc/ld.so.preload ===\n" + ldPreload);

    // 2. Search for .so files in suspicious locations
    const suspiciousSoFiles = this.findSuspiciousSoFiles();
    rawParts.push(
      "=== suspicious .so files ===\n" + suspiciousSoFiles.join("\n"),
    );

    // 3. Check if /etc/data directory exists and list contents
    const etcDataResult = exec("test -d /etc/data && echo exists");
    const etcDataExists = etcDataResult.stdout.includes("exists");
    let etcDataFiles: string[] = [];
    if (etcDataExists) {
      etcDataFiles = execLines("ls -la /etc/data/ 2>/dev/null");
      rawParts.push("=== /etc/data ===\n" + etcDataFiles.join("\n"));
    } else {
      rawParts.push("=== /etc/data ===\ndirectory does not exist");
    }

    // 4. Check kernel modules
    const kernelModules = this.getKernelModules();
    const lsmodResult = exec("lsmod");
    rawParts.push("=== lsmod ===\n" + (lsmodResult.stdout || ""));

    return {
      module: this.module,
      data: {
        ldPreload,
        suspiciousSoFiles,
        etcDataExists,
        etcDataFiles,
        kernelModules,
      },
      raw: rawParts.join("\n"),
    };
  }

  private findSuspiciousSoFiles(): string[] {
    const searchPaths = ["/etc", "/tmp", "/var/tmp", "/dev/shm"];
    const results: string[] = [];

    for (const searchPath of searchPaths) {
      const findResult = exec(
        `find ${searchPath} -name "*.so" -o -name "*.so.*" 2>/dev/null`,
        15_000,
      );
      if (findResult.stdout) {
        const files = findResult.stdout.split("\n").filter((f) => f.trim());
        // Filter out well-known library paths under /etc that are legitimate
        for (const file of files) {
          if (this.isSuspiciousSoFile(file)) {
            results.push(file);
          }
        }
      }
    }

    return results;
  }

  private isSuspiciousSoFile(filePath: string): boolean {
    // .so files in /tmp, /var/tmp, /dev/shm are always suspicious
    if (
      filePath.startsWith("/tmp/") ||
      filePath.startsWith("/var/tmp/") ||
      filePath.startsWith("/dev/shm/")
    ) {
      return true;
    }

    // Under /etc, skip known legitimate locations
    if (filePath.startsWith("/etc/")) {
      const legitimate = [
        "/etc/alternatives/",
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
      ];
      for (const prefix of legitimate) {
        if (filePath.startsWith(prefix)) return false;
      }
      return true;
    }

    return true;
  }

  private getKernelModules(): KernelModule[] {
    const modules: KernelModule[] = [];
    const lsmodResult = exec("lsmod");

    if (!lsmodResult.stdout) return modules;

    const lines = lsmodResult.stdout.split("\n");
    for (const line of lines) {
      const trimmed = line.trim();
      // Skip header
      if (!trimmed || trimmed.startsWith("Module")) continue;

      const parts = trimmed.split(/\s+/);
      if (parts.length >= 3) {
        modules.push({
          name: parts[0],
          size: parseInt(parts[1], 10) || 0,
          usedBy: parts.slice(3).join(",") || "",
        });
      }
    }

    return modules;
  }
}
