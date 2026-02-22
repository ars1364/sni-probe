# SNI Probe

Connectivity diagnostic tool for SNI proxy users. Tests DNS resolution and TLS connectivity through the proxy for gaming, streaming, and app services.

## What it does

1. Resolves each test domain via the DNS server (`46.245.69.222`)
2. Verifies the DNS returns the proxy IP (`188.40.147.153`)
3. Attempts a TLS handshake through the proxy to the real server
4. Reports pass/fail with latency for each domain
5. Saves a JSON report file for sharing

## Build

```bash
# Build for your platform
go build -o sni-probe .

# Cross-compile for Windows
GOOS=windows GOARCH=amd64 go build -o sni-probe.exe .

# Cross-compile for macOS
GOOS=darwin GOARCH=arm64 go build -o sni-probe-mac .
```

## Usage

**Before running:** Set your DNS to `46.245.69.222`

```bash
# Linux/macOS
./sni-probe

# Windows
sni-probe.exe
```

## Output

```
╔══════════════════════════════════════════════════════╗
║         SNI Proxy Connectivity Probe                ║
║         DNS: 46.245.69.222                          ║
╚══════════════════════════════════════════════════════╝

Testing 35 domains across 17 services...

  ✅ discord.com                  [Discord] 320ms
  ✅ open.spotify.com             [Spotify] 450ms
  ❌ eu.actual.battle.net         [Battle.net] TLS: timeout
  ...

────────────────────────────────────────────────────────
  DNS OK: 35/35  |  TLS OK: 33/35  |  Failed: 2
────────────────────────────────────────────────────────

  📄 Full report saved: sni-probe-report-20260222-193000.json
```

Share the JSON file for troubleshooting.

## Services Tested

Discord, Spotify, Steam/Epic, Riot (LoL/Valorant), EA, Xbox Live, Nintendo, Battle.net, Ubisoft, ChatGPT, Claude AI, Twitch, Nvidia, Fortnite, Google AI, Apple Music
