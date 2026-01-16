# Honeypot Detection in Argus

Argus uses a multi-layer scoring system to identify potential honeypots. This document explains the detection logic and provides examples.

## Scoring Overview

| Check | Max Score | Purpose |
|-------|-----------|---------|
| Port Density | 40 pts | Flags targets with too many open ports |
| Banner Consistency | 30 pts | Detects OS mismatches across services |
| Response Timing | 30 pts | Identifies artificial response patterns |
| Database Checks | Bonus | Known honeypot IPs, suspicious patterns |

**Total possible score: 100+ (capped at 100)**

---

## Confidence Levels

| Level | Score Range | Meaning |
|-------|-------------|---------|
| LOW | 0-39 | Likely legitimate server |
| MEDIUM | 40-59 | Suspicious, investigate further |
| HIGH | 60+ | Likely honeypot |

---

## Detection Methods

### 1. Port Density (40 pts max)

Real servers typically have 1-10 open ports. Honeypots often expose many ports to attract scanners.

| Open Ports | Score |
|------------|-------|
| < 10 | 0 |
| 10-19 | 5 |
| 20-29 | 15 |
| 30-49 | 25 |
| 50-99 | 35 |
| 100+ | 40 |

**Example:** A server with 150 open ports scores 40/40.

### 2. Banner Consistency (30 pts max)

Analyzes OS indicators across services. Mismatches indicate a honeypot or misconfiguration.

**Suspicious patterns:**
- SSH banner says "Ubuntu" but HTTP says "Windows Server"
- FTP indicates "Linux" but SMB shows "Windows"

| Conflicts | Score |
|-----------|-------|
| 0 conflicts | 0 |
| 1 OS family conflict | 15 |
| 2+ OS family conflicts | 30 |

**OS Families Detected:**
- **Linux:** Ubuntu, Debian, CentOS, Fedora, OpenSSH
- **Windows:** Microsoft, IIS, Win32, Win64
- **FreeBSD:** FreeBSD
- **macOS:** Darwin, macOS

### 3. Response Timing (30 pts max)

Real servers have natural timing variations. Honeypots often respond too fast or too consistently.

| Issue | Score |
|-------|-------|
| >50% responses under 5ms | +15 |
| Near-zero jitter (CV < 5%) | +15 |

**CV = Coefficient of Variation** (standard deviation / mean)

### 4. Database Checks (Bonus)

Argus consults community-maintained databases:

- **honeypot_ips.json** - Known honeypot IP ranges
- **service_patterns.json** - Suspicious service combinations

**Example pattern:**
```json
{
  "name": "Linux SSH + Windows IIS",
  "requires": ["SSH", "IIS"],
  "score": 35
}
```

---

## Example: Legitimate Server

```
Target: scanme.nmap.org
Open Ports: 22, 80, 443, 9929

╭────────────────── Honeypot Detection ──────────────────╮
│ ✓ Honeypot Score: 5/100 (LOW)                          │
│   • Port Density: 0/40 - 4 open ports is normal        │
│   • Banner Consistency: 0/30 - OS consistent (Linux)   │
│   • Timing: 5/30 - Normal variation                    │
╰────────────────────────────────────────────────────────╯
```

**Analysis:** Low score indicates a legitimate server.

---

## Example: Suspected Honeypot

```
Target: suspicious-target.example
Open Ports: 21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 8080... (75 total)

╭────────────────── Honeypot Detection ──────────────────╮
│ ⚠ Honeypot Score: 72/100 (HIGH)                        │
│   • Port Density: 35/40 - 75 open ports is suspicious  │
│   • Banner Consistency: 22/30 - Linux SSH + Windows RDP│
│   • Timing: 15/30 - Too-fast responses (<5ms)          │
╰────────────────────────────────────────────────────────╯
```

**Analysis:**
1. **Port Density (35/40):** 75 open ports is highly unusual
2. **Banner Mismatch (22/30):** SSH says Linux, RDP says Windows
3. **Fast Timing (15/30):** Responses under 5ms suggest emulation

---

## Limitations

- **False positives:** Load balancers and CDNs may trigger warnings
- **False negatives:** Sophisticated honeypots can mimic real servers
- **Network conditions:** High latency can mask timing anomalies

Always use honeypot scores as one factor in your assessment, not a definitive verdict.
