# Argus Real-World Validation

Evidence of Argus performance across different target types.

**Test Date:** January 16, 2026  
**Argus Version:** 1.0.0  
**Environment:** Windows 11, Python 3.14

---

## Test 1: Normal VPS (scanme.nmap.org)

**Target:** `scanme.nmap.org` (Nmap's authorized test server)

```bash
argus -t scanme.nmap.org -p 1-1000 -sV -o docs/results_vps.json
```

### Results

| Metric | Value |
|--------|-------|
| Open Ports | 4 |
| Scan Time | 11.86s (with -sV deep probing) |
| Honeypot Score | **0/100 (LOW)** |
| OS Detected | Ubuntu Linux |

### Ports Found

| Port | Service | Banner |
|------|---------|--------|
| 21 | FTP | (no banner) |
| 22 | SSH | `SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13` |
| 80 | Apache | `HTTP/1.1 200 OK` |
| 554 | RTSP | (no banner) |

### Honeypot Analysis

```
✓ Honeypot Score: 0/100 (LOW)
  • Port Density: 0/40 - 4 open ports is normal
  • Banner Consistency: 0/30 - OS indicators consistent (Linux)
  • Timing: 0/30 - Normal variation (9.55ms - 253.09ms)
```

**Verdict:** Correctly identified as legitimate server.

---

## Test 2: CDN-Fronted Site (Cloudflare)

**Target:** `www.cloudflare.com`

```bash
argus -t www.cloudflare.com -p 80,443 -sV -o docs/results_cdn.json
```

### Results

| Metric | Value |
|--------|-------|
| Open Ports | 2 |
| Scan Time | 5.51s |
| Honeypot Score | **0/100 (LOW)** |
| Server Detected | Cloudflare |

### Ports Found

| Port | Service | Banner |
|------|---------|--------|
| 80 | Cloudflare | `HTTP/1.1 400 Bad Request` |
| 443 | Cloudflare | `HTTP/1.1 200 OK` |

### Honeypot Analysis

```
✓ Honeypot Score: 0/100 (LOW)
  • Port Density: 0/40 - 2 open ports is normal
  • Banner Consistency: 0/30 - OS consistent (Unknown/CDN)
  • Timing: 0/30 - Normal variation (26.29ms - 36.89ms)
```

**Verdict:** Correctly identified CDN, no false positive.

---

## Performance Benchmark

### Test Setup

- **Target:** scanme.nmap.org
- **Port range:** 1-1000
- **Network:** Home broadband

### Results

| Tool | Command | Time | Ports Found |
|------|---------|------|-------------|
| **Argus** | `argus -t scanme.nmap.org -p 1-1000` | **12.60s** | 4 |
| **Argus -sV** | `argus -t scanme.nmap.org -p 1-1000 -sV` | 11.86s | 4 |
| **Nmap** | `nmap scanme.nmap.org -p 1-1000` | **6.52s** | 4 |

### Analysis

Nmap is ~2x faster for basic scans. This is expected—Nmap uses raw sockets and SYN scanning, while Argus uses full TCP connect() via asyncio.

**Argus advantages:**
- No root/admin required
- Rich honeypot detection (Nmap lacks this)
- JSON output with structured honeypot breakdown
- Works on restricted networks where raw sockets are blocked

---

## JSON Output Examples

### VPS Scan ([results_vps.json](results_vps.json))

```json
{
    "target": "45.33.32.156",
    "os_detected": "Ubuntu Linux",
    "honeypot_detection": {
        "score": 0,
        "confidence": "LOW",
        "is_likely_honeypot": false
    }
}
```

### CDN Scan ([results_cdn.json](results_cdn.json))

```json
{
    "target": "104.16.124.96",
    "os_detected": "Unknown",
    "honeypot_detection": {
        "score": 0,
        "confidence": "LOW",
        "is_likely_honeypot": false
    }
}
```

---

## Conclusion

| Test Case | Honeypot Score | Expected | Result |
|-----------|----------------|----------|--------|
| Normal VPS | 0 (LOW) | LOW | ✅ Pass |
| CDN Site | 0 (LOW) | LOW | ✅ Pass |

Argus correctly identifies legitimate servers and CDN infrastructure without false positives.
