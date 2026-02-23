# sni-probe

Network diagnostic tool for detecting DNS poisoning, DPI (deep packet inspection), and SNI-based blocking.

## What it tests

| # | Section | What it does |
|---|---------|-------------|
| 1 | DNS Analysis | Compares system/public/custom DNS — detects poisoning & overrides |
| 2 | Connectivity | Tests 36 domains across 13 services (Discord, Twitch, Battle.net, Steam, etc.) |
| 3 | DPI Detection | Real SNI vs fake SNI to same IP — detects SNI-based blocking |
| 4 | Cloudflare Path | Tests if DPI inspects traffic to Cloudflare IPs |
| 5 | Network Quality | TCP latency, jitter, download speed |

## Usage

```
# Set DNS to 46.245.69.222 first
sni-probe-windows-amd64.exe
```

Generates `sni-probe-report-*.json` — share it for troubleshooting.

## Download

**[Releases](https://github.com/ars1364/sni-probe/releases/latest)** — Windows & Linux binaries.

## Legend

- ☠️ DNS poisoned (ISP returns fake IP)
- 🛡️ DPI blocked (ISP reads TLS SNI, resets connection)
- 🚫 IP blocked
- 🔀 DNS overridden to proxy
- ✅ Working
