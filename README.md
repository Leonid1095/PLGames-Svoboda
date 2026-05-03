<div align="center">

# 🌐 PLGames Svoboda

### Autonomous DPI Bypass Agent

**Your internet — your rules.** AI-powered, self-adapting, community-driven.<br>
No VPN tunnel. No proxy server. Pure local packet manipulation.

[Download](#-quick-start) · [How it works](#-the-smart-bypass-chain) · [Roadmap](#-roadmap) · [Support](#-support-the-project)

<br>

![Platform](https://img.shields.io/badge/Platform-Windows%2010%2B-0078D4?style=for-the-badge&logo=windows)
![Engine](https://img.shields.io/badge/Engine-zapret2%20%2B%20WinDivert-2EA44F?style=for-the-badge)
![AI](https://img.shields.io/badge/AI-Strategy%20Engineer-8B5CF6?style=for-the-badge)
![Tests](https://img.shields.io/badge/Tests-184%20passing-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-EAB308?style=for-the-badge)

</div>

---

## 🇷🇺 Кратко по-русски

**PLGames Svoboda** — автономный агент, который сам обходит блокировки в РФ.<br>
Запускаешь — он определяет провайдера, тип блокировки, подбирает рабочую стратегию обхода, применяет её и круглосуточно следит за работой. Если ТСПУ меняет правила — переподстраивается за секунды.

**Это НЕ VPN.** Никаких туннелей, своих серверов или подмены IP. Только локальная манипуляция пакетами на уровне ядра Windows. Сервер используется только как «коллективный мозг» — клиенты делятся друг с другом рабочими стратегиями.

```cmd
git clone https://github.com/Leonid1095/PLGames-Svoboda.git
cd PLGames-Svoboda
pip install -r requirements.txt
run.bat
```

---

## What is this?

Svoboda is an **autonomous bypass agent**, not a VPN. There's no tunnel, no proxy server, no shared IP. Everything happens locally on your machine through kernel-level packet manipulation (`zapret2` + `WinDivert`).

You launch it. It figures out your ISP, identifies how DPI blocks traffic, finds a working bypass strategy, applies it, and monitors 24/7. When censorship changes — it re-adapts.

The cloud component is **intelligence only**: clients share which strategies work on which ISPs, so the next person on the same network gets a working setup instantly.

---

## 🔓 What it unblocks

<table>
<tr>
<td valign="top" width="33%">

**💬 Social & Messaging**
- Discord
- Telegram
- Twitter / X
- Instagram
- Facebook / Meta
- LinkedIn
- WhatsApp
- Reddit

</td>
<td valign="top" width="33%">

**🎮 Games**
- Riot Games / League of Legends
- Roblox
- PlayStation Network
- Xbox / Microsoft Store
- Epic Games
- EA / Origin
- Steam Community
- Battle.net
- Ubisoft

</td>
<td valign="top" width="33%">

**🎬 Streaming & Media**
- YouTube (throttled → fast)
- Netflix
- Crunchyroll / Funimation
- Spotify
- Twitch
- Disney+
- HBO Max
- Paramount+, Peacock
- Hidive

</td>
</tr>
</table>

Hostlist is curated — only services genuinely blocked or throttled in RU are included, so antivirus / Steam / Office stay untouched.

---

## ⚡ The Smart Bypass Chain

When something is blocked, Svoboda goes through **7 layers automatically**:

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1   Community DB        another user found a strategy    │
│            ↓ fail              for your ISP — applied in 5 sec  │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2   Local cache         strategy that worked here before │
│            ↓ fail                                                │
├─────────────────────────────────────────────────────────────────┤
│  Layer 3   AI Advisor          top-4 from learned memory        │
│            ↓ fail              ranked by past fitness            │
├─────────────────────────────────────────────────────────────────┤
│  Layer 4   Enumerator          75+ hardcoded + harvested        │
│            ↓ fail              configs from Flowseal et al      │
├─────────────────────────────────────────────────────────────────┤
│  Layer 5   AI Strategy Engineer LLM analyzes raw symptoms,     │
│            ↓ fail              invents NOVEL flag combination   │
├─────────────────────────────────────────────────────────────────┤
│  Layer 6   ByeDPI Layer 2      SOCKS5 userspace — different     │
│            ↓ fail              attack model than packet desync  │
├─────────────────────────────────────────────────────────────────┤
│  Layer 7   GA Evolution        genetic mutations of best        │
│                                strategy found so far             │
└─────────────────────────────────────────────────────────────────┘
```

Once a working strategy is found, it's **monitored 24/7**, **shared anonymously** with the community DB, and **re-tested** if connectivity degrades.

---

## 🆚 How it compares

|  | **Svoboda** | GoodbyeDPI | Zapret GUI | ByeDPI | Zapret-Discord-YouTube |
|---|:---:|:---:|:---:|:---:|:---:|
| Auto-detects ISP + DPI type | ✅ | ❌ | ❌ | ❌ | ❌ |
| Self-finds working strategy | ✅ | ❌ | ❌ | ❌ | ❌ |
| Community strategy sync | ✅ | ❌ | ❌ | ❌ | ❌ |
| Live config harvesting | ✅ | ❌ | ❌ | ❌ | manual |
| AI generates novel strategies | ✅ | ❌ | ❌ | ❌ | ❌ |
| Self-adapts to DPI changes | ✅ | ❌ | ❌ | ❌ | ❌ |
| QUIC auto-block | ✅ | ❌ | partial | ❌ | partial |
| Cross-host learning (per-ISP) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Body-content verification | ✅ | ❌ | ❌ | ❌ | ❌ |
| 184-test safety harness | ✅ | ❌ | ❌ | ❌ | ❌ |

> Other tools give you a config. **Svoboda *is* the config — it writes itself.**

---

## 🆕 What's new (May 2026)

| Feature | What it does |
|---|---|
| **Live Strategy Harvester** | Pulls fresh `.bat` configs from `Flowseal/zapret-discord-youtube` every 6h, translates zapret v1 → v2 lua, dedupes, adds to enum pool |
| **AI Strategy Engineer** | When all known strategies fail, sends raw symptoms (curl exit codes, latency, ISP) to LLM, parses novel flag combination, validates, tests on the fly |
| **Pattern Transfer Engine** | Strategy that worked for `discord.com` is tried first for `cdn.discordapp.com` (cross-host learning per ISP+block_type) |
| **ProbeEye** | Continuous active probing thread (30s interval), measures real throughput + TTFB — not just HTTP 200 OK |
| **Block-type dispatcher** | TSPU MITM (`exit=60 SSL`) gets SNI-fragmentation first; HTTP/2 stream kill gets `alpn_strip` first |
| **Hostlist v2** | Curated 72 actually-blocked domains (down from 81 149 garbage); 115 must-not-touch in exclude (AV, anti-cheat, critical CDNs) |

---

## 🚀 Quick Start

```bash
git clone https://github.com/Leonid1095/PLGames-Svoboda.git
cd PLGames-Svoboda
pip install -r requirements.txt
run.bat                       # production mode (requires Administrator)
```

**Requirements**

- Windows 10+ (Linux secondary, in development)
- Python 3.11+
- Administrator privileges (for WinDivert kernel driver)

**Internet stuck?**

```bash
fix_internet.bat              # kills winws2, removes QUIC block, clears proxy, flushes DNS
```

---

## 🏗️ Architecture

```
run_real.py                       Orchestrator: profiles, watchdog, cleanup, escalation chain
brain/
  ├─ enumerator.py                75+ proven strategies, fast enumeration with rate-limit guard
  ├─ strategy_harvester.py        ⭐ NEW — live config sync from Flowseal et al
  ├─ ai_strategy_engineer.py      ⭐ NEW — LLM proposes novel strategies on enum exhaustion
  ├─ tester.py                    Shadow testing with body verification + throughput
  ├─ probe_eye.py                 ⭐ NEW — continuous probing, throughput/TTFB
  ├─ pattern_transfer.py          ⭐ NEW — cross-host strategy transfer per (ISP, block_type)
  ├─ host_solver.py               Per-host strategy optimization with hoisting
  ├─ block_classifier.py          Detects SNI / RST / TLS_MITM / HTTP2_KILL / IP_BLOCK
  ├─ tspu_profiler.py             DPI distance, TTL, stateful detection
  ├─ genetic.py                   GA evolution (Geneva-style mutations)
  ├─ byedpi.py                    Layer 2 fallback (SOCKS5 userspace desync)
  ├─ ai_engine.py                 Autonomous agentic decision loop
  ├─ ai_advisor.py                LLM-backed strategy ranking
  ├─ analytics.py                 Thread-safe SQLite telemetry
  ├─ proxy_router.py              Smart routing (desync vs proxy vs tunnel)
  ├─ morpher.py                   TLS fingerprint morphing (Chrome / Firefox / Safari)
  ├─ sync.py                      Community strategy sharing
  └─ tier.py                      Subscription management
lua/                              Custom zapret2 lua extensions (alpn_strip, tls_morph)
server/api.py                     FastAPI intelligence layer (NOT a tunnel)
tests/                            184 unit tests (security, compilation, logic, parsers)
zapret2-v0.9.4.5/                 Bundled DPI bypass engine
```

---

## 🗺️ Roadmap

### ✅ Shipped & verified live
- 7-layer escalation chain (community → cache → AI → enum → AI Engineer → ByeDPI → GA)
- Live Strategy Harvester (Flowseal sync, zapret v1↔v2 translator)
- AI Strategy Engineer (LLM-as-strategy-designer with flag validation)
- Pattern Transfer Engine (cross-host learning)
- ProbeEye continuous probing
- Block-type-aware strategy hoisting
- Hostlist v2 (games + streaming + social, anti-cheat exclusions)
- Telegram no longer auto-removed from solver test set
- ByeDPI Layer 2 fallback wiring

### 🟡 In progress
- Discord TSPU MITM bypass (`exit=60 SSL` — SNI hiding partial; AI Engineer experiments ongoing)
- Telegram on partial-IP-block ISPs (some IPs blackholed, others SNI-filtered)
- Server-side hardening:
  - Rate-limited host-strategy reports + per-host fitness validation
  - Per-ISP strategy blocklist (mark dead strategies, stop testing them)
  - AI proxy fallback chain (DeepSeek → primary → cache → 503)
  - Curated hostlist endpoint (`/api/v1/hostlist/curated`)
  - Block-type taxonomy enum (incl. `TLS_MITM_INJECTION`)

### ⏳ Planned
- **GitHub Pages landing site** — proper public-facing page with download, screenshots, FAQ
- Anomaly Detector — detect when ISP swaps blocking method, trigger re-discovery
- Adaptive Rotation — round-robin among top-N strategies per host
- Federated Meta-Learning — cross-ISP strategy transfer (one ISP's solution helps another)
- Live LLM strategy injection without restart
- Tray UI with traffic graph + manual override
- Mobile clients (Android via `VpnService`)
- Linux daemon (`nfqws2` + `iptables NFQUEUE`)
- macOS support

---

## 🧪 Verified live

Tested **May 2026** on **er-telecom (AS42116, Tatarstan)** with TSPU stateful DPI:

| Platform | Status | Method | Notes |
|---|:---:|---|---|
| YouTube | ✅ | `multisplit:pos=1:seqovl=4096 \| multidisorder:pos=1,midsld` | full HD video, no buffering |
| Instagram | ✅ | same | feed + DMs + stories |
| Facebook | ✅ | same | feed + Messenger |
| X / Twitter | 🟡 | same | works but throttled (~10s TTFB on cold connections) |
| LinkedIn | ✅ | same | full functionality |
| Reddit | ✅ | passthrough | not blocked here |
| Discord | 🟡 | `multisplit:pos=1:seqovl=N` + AI Engineer | TSPU MITM injection — investigating |
| Telegram | 🟡 | `multisplit:pos=1` + per-host solver | partial IP block on some servers |

✅ working · 🟡 partial / in progress · ❌ blocked

> Status updates after each live run are tracked in [`ROADMAP.md`](ROADMAP.md).

---

## 🛡️ Privacy

- **Zero personal data collected** — no IP, MAC, hostname, or browsing history
- **Anonymous telemetry only** — ISP type + strategy fitness score
- Telemetry trains the community AI to discover better strategies for everyone
- All API keys server-side, never embedded in client
- Full opt-out: set `"share": false` in `config.json`
- Server is intelligence only — **never** routes your traffic

---

## 💛 Support the project

Svoboda is **fully free and open source**. Every bypass feature works without paying anything.

Donations cover:

1. **AI infrastructure** — LLMs that analyze DPI patterns and suggest strategies. More compute = smarter AI = faster bypass discovery for everyone.
2. **Server hosting** — community strategy sync, hostlist updates, ISP coordination.

No paywalls. The tool is identical for free and paid users. Paid tiers just get faster AI analysis — useful when your ISP changes blocking methods multiple times per day.

| Tier | Price | AI analysis | Includes |
|---|:---:|:---:|---|
| **Free** | 0₽ | 1×/day | Full bypass + 75+ built-in strategies + community sync |
| **Supporter** | 300₽/mo | ~12×/day | Faster AI adaptation when DPI rules shift |
| **Pro** | 600₽/mo | ~48×/day | Priority AI + PLGames encrypted DNS (Germany DoH/DoT) |

[**Support on DonatePay →**](https://new.donatepay.ru/@lenya)

---

## 🤝 Contributing

PRs welcome. Before submitting:

```bash
python -m pytest tests/ -v                                       # all 184 tests must pass
python -c "import py_compile; py_compile.compile('run_real.py', doraise=True)"   # syntax check
```

Particularly useful contributions:
- New DPI bypass strategies for ISPs we don't cover
- Translators for additional config formats (sing-box, NekoBox, GoodbyeDPI)
- Mobile / Linux / macOS ports
- Documentation in your language

See [`CLAUDE.md`](CLAUDE.md) for project conventions.

---

## 📜 License

MIT — use freely, contribute back.

<div align="center">

---

**Made with ❤️ by [PLGames](https://github.com/Leonid1095)**

*Свобода — не свобода что-то конкретное обходить. Свобода — это возможность не задумываться об этом.*

</div>
