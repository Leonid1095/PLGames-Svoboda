# PLGames Svoboda

**AI-powered DPI bypass tool** that automatically finds and applies the best bypass strategy for your ISP. Inspired by [Geneva](https://geneva.cs.umd.edu/) genetic algorithm + [zapret2](https://github.com/bol-van/zapret2) packet manipulation engine.

> YouTube, Twitch, Twitter and other blocked sites — working in seconds, not minutes.

## How It Works

```
Run bat file → ISP detected → DPI profiled → Strategy found → Sites unblocked
                                                    ↑
                                    Community data + AI + Genetic Algorithm
```

1. **TSPU Profiler** — fingerprints your ISP's DPI: hop distance, block type, behavior
2. **Block Classifier** — determines HOW each site is blocked (RST injection, SNI filtering, throttling)
3. **Community Intelligence** — tries strategies proven by other users on your ISP (5 sec)
4. **Fast Enumeration** — tests 19 known strategies in priority order (40 sec)
5. **Genetic Algorithm** — evolves new strategies if nothing else works (5-10 min)
6. **Watchdog** — monitors 24/7, re-evolves if DPI changes

## Quick Start (Windows)

```batch
git clone https://github.com/Leonid1095/PLGames-Svoboda.git
cd PLGames-Svoboda
run.bat
```

That's it. Run as Administrator (required for WinDivert driver). zapret2 downloads automatically.

**Requirements:** Windows 10+, Python 3.10+, Administrator rights

## What Gets Unblocked

| Site | Status | Method |
|------|--------|--------|
| YouTube (video + shorts) | Working | multisplit + multidisorder |
| Twitch (streams) | Working | hostlist-protected |
| Twitter / X | Working | same strategy |
| Discord (web) | Working | incognito mode* |
| Discord (app) | In progress | Electron/Schannel conflict |

*Discord web works in incognito. Regular mode may conflict with browser extensions (Kaspersky, Perplexity AI).

## Architecture

```
run.bat
  ├── run_real.py          Console mode (full output)
  └── svoboda_tray.py      Background mode (system tray icon)

brain/
  ├── block_classifier.py  Classifies block type per host
  ├── tspu_profiler.py     Fingerprints DPI middlebox
  ├── enumerator.py        Fast strategy enumeration (blockcheck2-style)
  ├── genetic.py           Genetic algorithm for strategy evolution
  ├── tester.py            Real connection testing with winws2
  ├── ai_advisor.py        AI strategy suggestions (server proxy)
  ├── failure_analyzer.py  Structured failure analysis
  ├── analytics.py         Local SQLite telemetry
  ├── manager.py           Strategy persistence + migration
  ├── sync.py              Anonymous server sync + community voting
  ├── profiler.py          ISP detection (ASN, seed strategies)
  ├── ui.py                Colored terminal output
  ├── tier.py              FREE / SUPPORTER / PRO tiers
  └── donate.py            DonatePay integration

server/
  └── api.py               FastAPI backend (AI proxy, telemetry, tiers)

fix_internet.bat           Emergency: kill winws2 + reset network
```

## How DPI Bypass Works

PLGames Svoboda uses [zapret2](https://github.com/bol-van/zapret2) `winws2.exe` to manipulate TCP packets at the kernel level via WinDivert:

- **multisplit** — splits TLS ClientHello into multiple segments so DPI can't read SNI
- **multidisorder** — sends segments out of order, confusing DPI reassembly
- **fake** — sends a decoy packet with wrong SNI and short TTL (reaches DPI but not server)
- **seqovl** — overlaps TCP sequences with fake data

Strategies are applied **only to blocked domains** (81K+ from Russian blocklist) via `--hostlist`. Your regular traffic is untouched.

## Tier System

| Feature | Free | Supporter (300 RUB) | Pro (600 RUB) |
|---------|------|---------------------|---------------|
| DPI bypass | Yes | Yes | Yes |
| AI analysis | 1x/day | Every 2h | Every 30min |
| AI model | Standard | Standard | DeepSeek V3 |
| Community strategies | Yes | Yes | Yes |
| PLGames DNS (DoH) | - | - | Yes |

Support the project: [DonatePay](https://new.donatepay.ru/@lenya)

## Privacy & Security

- **Zero secrets in client code** — all API keys stay server-side
- **Anonymous telemetry** — no IP, MAC, hostname, or accounts collected
- **Per-install tokens** — auto-generated HMAC, individually revocable
- **Hostlist filtering** — only blocked domains processed, rest untouched
- **Open source** — audit everything

## Self-Hosting

```bash
git clone https://github.com/Leonid1095/PLGames-Svoboda.git
cd PLGames-Svoboda
sudo bash deploy_server.sh
```

Sets up FastAPI + nginx + systemd on your VPS.

## Emergency: Internet Broken?

If winws2 crashed and your internet stopped working:

```batch
fix_internet.bat
```

This kills winws2, unloads WinDivert driver, flushes DNS, and resets Winsock.

## Contributing

Pull requests welcome. Key areas:
- New bypass strategies for specific ISPs
- TSPU fingerprinting improvements
- Traffic morphing (anti-ML detection)
- ByeDPI-style SOCKS proxy fallback (no admin needed)

## License

MIT
