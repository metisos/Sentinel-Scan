import { hostname } from "node:os";
import { exec } from "./shell.js";

export interface PlatformInfo {
  hostname: string;
  os: string;
  kernel: string;
  ip: string;
}

export function getPlatformInfo(): PlatformInfo {
  const os = exec("lsb_release -ds 2>/dev/null || cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"' || uname -s").stdout || "Linux";
  const kernel = exec("uname -r").stdout || "unknown";
  const ip = exec("hostname -I 2>/dev/null | awk '{print $1}' || echo 'unknown'").stdout || "unknown";

  return {
    hostname: hostname(),
    os,
    kernel,
    ip,
  };
}
