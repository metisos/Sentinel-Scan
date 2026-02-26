---
name: security-scan
description: Run a security scan on the current Linux server to detect malware, backdoors, rootkits, cryptominers, exposed credentials, and misconfigurations. Use when the user asks to check server security, scan for threats, audit the system, or investigate a potential compromise.
allowed-tools: Bash, Read
argument-hint: [modules]
---

# Security Scan

Run a security scan on this server using `sentinel-scan`.

## Instructions

1. **Check if sentinel-scan is installed:**

```bash
command -v sentinel 2>/dev/null || npm install -g sentinel-scan
```

2. **Run the scan:**

If `$ARGUMENTS` is provided, use it as the module list:

```bash
sentinel --format json --modules $ARGUMENTS 2>/dev/null
```

If no arguments, run a full scan:

```bash
sentinel --format json 2>/dev/null
```

3. **Parse and present findings:**

Read the JSON output and present a clear summary to the user:

- **Status** — CLEAN, INFORMATIONAL, WARNINGS, THREATS_FOUND, or COMPROMISED
- **Finding count** by severity (critical, high, medium, low, info)
- **Top findings** — list each finding with its severity, title, description, and remediation
- **Actionable next steps** — what the user should do based on the results

4. **If the scan finds CRITICAL or HIGH findings**, clearly warn the user and prioritize those findings at the top of your response.

5. **Do NOT automatically remediate.** Present findings and recommendations, then let the user decide what to fix.

## Available Modules

| Module | What It Checks |
|--------|---------------|
| `processes` | Running processes — malware, cryptominers, suspicious paths |
| `network` | Listening ports, outbound connections, C2 servers, mining pools |
| `systemd` | Enabled services — malicious persistence mechanisms |
| `crontabs` | Scheduled tasks — download-and-execute, base64 payloads |
| `rootkit` | ld.so.preload, suspicious shared libraries, /etc/data |
| `ssh` | SSH config hardening, authorized keys, active sessions |
| `shell` | Shell profiles — backdoors, reverse shells, injected commands |
| `filesystem` | Executables in /tmp, SUID binaries, hidden directories |
| `firewall` | UFW, fail2ban, iptables rules |
| `credentials` | .env files, service account keys, git credentials, SSH keys |

## Exit Codes

- `0` — Clean
- `1` — Low/info findings only
- `2` — Medium findings
- `3` — High or critical findings

## Programmatic API

If you need to use sentinel-scan from Node.js/TypeScript code:

```typescript
import { scan, formatResult } from 'sentinel-scan';

const result = await scan({ modules: ['processes', 'network', 'rootkit'] });

// result.summary.status → "CLEAN" | "COMPROMISED" | etc.
// result.findings → array of { severity, title, description, remediation }
```

## Example Usage

```
/security-scan
/security-scan processes,network,rootkit
/security-scan credentials
```
