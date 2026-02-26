<p align="center">
  <img src="https://img.shields.io/npm/v/sentinel-scan?color=red&label=npm" alt="npm version" />
  <img src="https://img.shields.io/badge/platform-linux-brightgreen" alt="platform" />
  <img src="https://img.shields.io/badge/node-%3E%3D18-blue" alt="node version" />
  <img src="https://img.shields.io/npm/l/sentinel-scan" alt="license" />
</p>

<h1 align="center">Sentinel</h1>

<p align="center">
  <strong>One command to know if your Linux server has been compromised.</strong>
</p>

<p align="center">
  Detects malware, backdoors, rootkits, cryptominers, and misconfigurations.<br/>
  Built for developers, founders, and AI agents — not security teams.
</p>

---

## Why Sentinel?

Most developers running VPS instances (Linode, DigitalOcean, AWS EC2) don't have security teams. They don't know what a compromised server looks like. They miss persistence mechanisms during manual cleanup. They clone compromised servers thinking they're clean.

Sentinel was born from a **real incident**: a production server compromised for 3+ months with a cryptominer, botnet, rootkit, and multiple backdoors — all of which survived a server clone because the operator didn't know what to look for.

Enterprise tools like CrowdStrike and Wazuh are overkill. Sentinel is the "run one command and know" tool.

## Quick Start

```bash
npm install -g sentinel-scan
sentinel
```

```
  ██████ ▓█████  ███▄    █ ▄▄▄█████▓ ██▓ ███▄    █ ▓█████  ██▓
▒██    ▒ ▓█   ▀  ██ ▀█   █ ▓  ██▒ ▓▒▓██▒ ██ ▀█   █ ▓█   ▀ ▓██▒
░ ▓██▄   ▒███   ▓██  ▀█ ██▒▒ ▓██░ ▒░▒██▒▓██  ▀█ ██▒▒███   ▒██░
  ▒   ██▒▒▓█  ▄ ▓██▒  ▐▌██▒░ ▓██▓ ░ ░██░▓██▒  ▐▌██▒▒▓█  ▄ ▒██░
▒██████▒▒░▒████▒▒██░   ▓██░  ▒██▒ ░ ░██░▒██░   ▓██░░▒████▒░██████▒

  Sentinel — Server Security Scanner v0.1.0
  my-server | Ubuntu 24.04 | 10.0.0.1

✔ Scanning processes (42ms)
✔ Checking network connections (38ms)
✔ Inspecting systemd services (156ms)
✔ Checking for rootkits (12ms)
...

  [CRITICAL] ld.so.preload contains /etc/data/libsystem.so — ROOTKIT
  [CRITICAL] bot.service runs /etc/data/kinsing — CRYPTOMINER
  [HIGH    ] SSH PasswordAuthentication is enabled
  [MEDIUM  ] 3 .env files with plaintext credentials found

Status: COMPROMISED — 2 critical, 1 high, 1 medium
```

## Install

```bash
# Global CLI
npm install -g sentinel-scan

# Project dependency (for programmatic use)
npm install sentinel-scan
```

## Usage

### CLI

```bash
sentinel                                    # Full scan, colored terminal output
sentinel --format json                      # JSON output (CI/CD, AI agents)
sentinel --format markdown > report.md      # Markdown report
sentinel --modules processes,network,rootkit # Specific modules only
sentinel --no-banner                        # Suppress ASCII banner
```

### Programmatic API

Sentinel is designed to be used by AI agents and automation tools:

```typescript
import { scan, formatResult, getExitCode } from 'sentinel-scan';

// Run a full scan
const result = await scan();
console.log(result.summary.status);
// → "CLEAN" | "INFORMATIONAL" | "WARNINGS" | "THREATS_FOUND" | "COMPROMISED"

// Run specific modules
const result = await scan({ modules: ['processes', 'network', 'rootkit'] });

// Access findings directly
for (const finding of result.findings) {
  console.log(`[${finding.severity}] ${finding.title}`);
  console.log(`  ${finding.description}`);
  console.log(`  Fix: ${finding.remediation}`);
}

// Export as JSON or Markdown
const json = formatResult(result, 'json');
const markdown = formatResult(result, 'markdown');

// Get CI/CD exit code
process.exit(getExitCode(result));
```

### Exit Codes

| Code | Meaning | CI/CD Action |
|------|---------|--------------|
| `0` | Clean — no findings | Pass |
| `1` | Low / informational only | Pass |
| `2` | Medium findings | Warn |
| `3` | High or critical findings | Fail |

## What It Scans

Sentinel runs **10 independent security modules**, each checking a different attack surface:

| Module | What It Checks | What It Catches |
|--------|----------------|-----------------|
| `processes` | All running processes | Known malware (Kinsing, XMRig, Mirai), binaries in /tmp, cryptominers (high CPU) |
| `network` | Listening ports + outbound connections | C2 servers, mining pools, botnet scanning (port 23/2323/37215) |
| `systemd` | All enabled services | Malicious persistence, suspicious ExecStart paths, auto-restart malware |
| `crontabs` | Root, user, and system crontabs | Download-and-execute (`curl \| bash`), base64 commands, binaries in /tmp |
| `rootkit` | ld.so.preload, .so files, /etc/data | Userspace rootkits, Kinsing artifacts, injected shared libraries |
| `ssh` | sshd_config, authorized_keys, sessions | Password auth enabled, empty passwords, unknown keys |
| `shell` | .bashrc, .profile, /etc/profile.d/ | Reverse shells, wget/curl backdoors, eval/exec injection |
| `filesystem` | /tmp executables, hidden dirs, SUID | Malware binaries, privilege escalation backdoors, tampered system files |
| `firewall` | UFW, fail2ban, iptables | Missing firewall, no brute-force protection, open SSH |
| `credentials` | .env files, keys, git creds | Exposed API keys, service account JSONs, plaintext passwords |

## Threat Intelligence

Sentinel ships with a threat database seeded from **real-world incidents**:

| Category | Examples |
|----------|----------|
| **Malware hashes** | Mirai variants, Kinsing payloads |
| **C2 IPs** | Known command-and-control servers |
| **Process names** | `kinsing`, `xmrig`, `Sofia`, `ntpclient`, `coinminer` |
| **File paths** | `/etc/data/`, `/root/.systemd-utils/`, `/tmp/xdlol` |
| **Service names** | `bot.service`, `alive.service`, `systemd-utils.service` |
| **Suspicious ports** | 3333, 4444, 8333 (mining), 23/2323 (telnet), 37215 (Huawei exploit) |

## Output Formats

**Terminal** (default) — colored, human-readable with severity tags and progress spinners.

**JSON** (`--format json`) — structured output for CI/CD pipelines, webhooks, and programmatic consumption. Clean stdout, progress on stderr.

**Markdown** (`--format markdown`) — full report with tables, suitable for documentation, sharing, or attaching to incident tickets.

## Requirements

- **Node.js 18+**
- **Linux** (uses standard utilities: `ps`, `ss`, `find`, `grep`, `systemctl`)
- **Root recommended** for full results (some checks need privileged access)

## Roadmap

- [x] **v0.1** — Core scanner with 10 modules, rule engine, threat DB
- [ ] **v0.2** — AI-powered analysis (Claude/GPT) for contextual threat assessment
- [ ] **v0.3** — Interactive remediation mode (`sentinel fix`)
- [ ] **v0.4** — Monitoring daemon (`sentinel watch`) with webhook/email alerts
- [ ] **v0.5** — GitHub Actions integration

## Contributing

Contributions welcome. Areas where help is needed:

- **Threat intelligence** — add known malware hashes, C2 IPs, process names to the JSON databases
- **New detection rules** — improve analyzers to catch more threats with fewer false positives
- **Platform support** — extend collectors for RHEL/CentOS/Alpine differences
- **Tests** — unit tests for analyzers with fixture data

## License

MIT
