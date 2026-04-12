<div align="center">

# PLGames Svoboda

### Autonomous DPI Bypass Agent

**Your internet -- your rules. AI-powered, self-adapting, community-driven.**

[Download](#-quick-start) | [How it works](#how-it-works) | [Support](#-support-the-project)

---

<img src="https://img.shields.io/badge/Platform-Windows-blue?style=for-the-badge&logo=windows" alt="Windows">
<img src="https://img.shields.io/badge/Engine-zapret2-green?style=for-the-badge" alt="zapret2">
<img src="https://img.shields.io/badge/AI-Powered-purple?style=for-the-badge" alt="AI">
<img src="https://img.shields.io/badge/Tests-110%20passed-brightgreen?style=for-the-badge" alt="Tests">
<img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="MIT">

</div>

---

## What is this?

Svoboda is an **autonomous agent** that detects internet censorship on your connection and bypasses it -- without any manual configuration.

You launch it. It figures out your ISP, identifies how the DPI blocks traffic, finds a working bypass strategy, applies it, and monitors 24/7. If censorship changes -- it re-adapts automatically.

## What it unblocks

YouTube, Discord, Twitter/X, Instagram, Facebook, Telegram, LinkedIn, Reddit, Medium -- and everything else blocked by SNI filtering in Russia. Verified on **13 major platforms** with full page load + body content verification.

## How is it different?

| | Svoboda | GoodbyeDPI | Zapret GUI | ByeDPI |
|---|:---:|:---:|:---:|:---:|
| Auto-detects ISP + DPI type | Yes | No | No | No |
| Finds strategy automatically | Yes | No | No | No |
| Community intelligence | Yes | No | No | No |
| Self-adapts when DPI changes | Yes | No | No | No |
| Blocks QUIC automatically | Yes | No | No | No |
| Verifies with body content check | Yes | No | No | No |
| 81,000+ domain blocklist | Yes | No | No | No |

Other tools give you a config file. Svoboda **is** the config file -- it writes itself.

## How it works

```
Launch (admin)
  |
  +-- Detect ISP (AS number, DPI type, hop distance)
  +-- Block QUIC via firewall (forces TCP where desync works)
  +-- Try cached strategy from community (5 sec)
  |     |
  |     +-- Works? --> Apply + Monitor
  |     +-- Stale? --> Fast enumeration
  |
  +-- Enumerate 62+ proven strategies (10-30 sec)
  |     |
  |     +-- Test each with real connections
  |     +-- Follow redirects, verify body (>512B = real page)
  |     +-- First strategy above threshold --> Apply
  |
  +-- Monitor 24/7
  |     |
  |     +-- Health check every 1-5 min (adaptive interval)
  |     +-- Network change detection (WiFi/mobile switch)
  |     +-- Auto-recovery on degradation
  |
  +-- Share working strategy with community
        |
        +-- Next user on same ISP gets it instantly
```

### Under the hood

- **62+ no-fake strategies** -- TSPU blocks fake packets, so we use pure packet splitting/reordering (multisplit, multidisorder, seqovl patterns)
- **QUIC firewall block** -- browsers prefer QUIC (UDP 443) which TSPU blocks. We force TCP fallback where desync works. Removed on exit.
- **Browser-like verification** -- follows redirects (-L), checks body size, tests www.youtube.com (not just youtube.com). A 200 OK with <512 bytes = block page, not success.
- **Per-host solver** -- if YouTube works but Discord doesn't, finds a separate strategy for Discord
- **Adaptive watchdog** -- 1 min checks after failure, 10 min when stable
- **Thread-safe** -- mutex on winws2 start/stop, PID-targeted process kill, SQLite locking

## Quick Start

```
git clone https://github.com/Leonid1095/PLGames-Svoboda.git
cd PLGames-Svoboda
pip install -r requirements.txt
run.bat
```

**Requirements:** Windows 10+, Python 3.11+, Administrator rights

## Internet broken?

If something went wrong:

```
fix_internet.bat
```

Kills winws2, removes QUIC firewall rule, unloads WinDivert, clears proxy, flushes DNS.

## Architecture

```
run_real.py              -- Orchestrator (profiles, watchdog, cleanup)
brain/
  enumerator.py          -- 62+ proven strategies, fast enumeration
  tester.py              -- Shadow testing with body verification
  genetic.py             -- GA evolution (when enumeration isn't enough)
  block_classifier.py    -- Detects block type (SNI, RST, TLS, IP)
  tspu_profiler.py       -- DPI distance, TTL, stateful detection
  host_solver.py         -- Per-host strategy optimization
  proxy_router.py        -- Smart routing (desync vs proxy vs tunnel)
  analytics.py           -- Thread-safe SQLite telemetry
  ai_engine.py           -- Autonomous AI decision-making
  telemost_tunnel.py     -- WebRTC tunnel for whitelist scenarios
  morpher.py             -- TLS fingerprint morphing
  sync.py                -- Community strategy sharing
  tier.py                -- Subscription management
tests/                   -- 110 unit tests (security, compilation, logic)
zapret2-v0.9.4.5/        -- DPI bypass engine (winws2 + WinDivert)
```

## Privacy

- **Zero personal data** -- no IP, MAC, hostname, or browsing history
- **Anonymous telemetry** -- ISP type + strategy fitness score only
- Telemetry trains the community AI to find better strategies for everyone
- Full opt-out: `"share": false` in config.json

---

## Support the project

Svoboda is **fully free and open source**. All bypass features work without paying anything.

Donations cover two things:

1. **AI infrastructure** -- the AI models that analyze DPI patterns and suggest strategies learn from community data. More compute = smarter AI = faster bypass discovery for everyone.
2. **Server hosting** -- community strategy sync, domain blocklist updates, and coordination between users on the same ISP.

That's it. No paywalls on features. The tool works the same for free and paid users. Paid tiers simply get more frequent AI analysis -- useful when your ISP changes blocking methods multiple times per day.

| Tier | Price | AI analysis | Details |
|------|-------|-------------|---------|
| **Free** | 0 | 1x/day | Full bypass + community strategies + 62+ built-in strategies |
| **Supporter** | 300 RUB/mo | ~12x/day | Faster AI adaptation to DPI changes |
| **Pro** | 600 RUB/mo | ~48x/day | Priority AI + PLGames encrypted DNS (Germany) |

**[Support on DonatePay](https://new.donatepay.ru/@lenya)**

---

## Tested and verified

| Platform | Status | Response | Latency |
|----------|--------|----------|---------|
| YouTube | Working | 200 OK, 707KB | 0.6s |
| Instagram | Working | 200 OK, 571KB | 0.9s |
| Facebook | Working | 200 OK, 463KB | 1.4s |
| Discord | Working | 200 OK, 164KB | 0.4s |
| X / Twitter | Working | 200 OK, 244KB | 0.7s |
| Telegram Web | Working | 200 OK | 0.3s |
| LinkedIn | Working | 200 OK, 142KB | 1.6s |
| Reddit | Working | 200 OK | 0.4s |
| Medium | Working | 403 (accessible) | 0.3s |

Tested April 2026 on er-telecom (AS42116, Tatarstan) with TSPU stateful DPI.

---

## License

MIT -- use freely, contribute back.

<div align="center">

**Made by PLGames**

</div>
