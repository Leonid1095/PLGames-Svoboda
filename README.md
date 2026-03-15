# PLGames Svoboda

**AI-powered DPI bypass tool** that automatically finds the best network strategies for your ISP using a genetic algorithm inspired by [Geneva](https://geneva.cs.umd.edu/).

Works with [zapret2/nfqws2](https://github.com/bol-van/zapret) — the most popular DPI circumvention tool.

## How It Works

1. **Genetic Algorithm** evolves populations of zapret2 flag combinations
2. **AI Advisor** analyzes your network and suggests optimized strategies
3. **Connection Tester** validates each strategy against real hosts
4. **Analytics Engine** collects data to improve over time
5. **Server Sync** shares anonymous results to help all users

No manual flag tweaking. No guessing. The algorithm finds what works for your specific ISP and middlebox.

## Quick Start (Windows)

```
git clone https://github.com/Leonid1095/PLGames-Svoboda.git
cd PLGames-Svoboda
run.bat
```

That's it. The app auto-registers, connects to the AI server, and starts evolving strategies.

**Requirements:** Python 3.10+

## How It Works Under the Hood

```
              +------------------+
              |  Genetic Engine  |
              | population=12    |
              | generations=30   |
              +--------+---------+
                       |
            evolve flag combinations
                       |
              +--------v---------+
              | Connection Tester|  test against youtube, discord, x.com
              +--------+---------+
                       |
              +--------v---------+
              |   AI Advisor     |  suggest better seeds via LLM
              +--------+---------+
                       |
              +--------v---------+
              |  Server Sync     |  share results anonymously
              +------------------+
```

Each cycle:
- Generates a population of zapret2 flag combos
- Tests each one (mock mode without zapret2, real mode with it)
- Selects the fittest, mutates, crosses over
- Saves the best strategy locally and syncs with the server
- AI suggests new seeds based on collected data

## Tier System

| Feature | Free | Supporter (300 RUB) | Pro (600 RUB) |
|---------|------|---------------------|---------------|
| Genetic algorithm | Yes | Yes | Yes |
| AI scans | 1x/day | Every 2h | Every 30min |
| AI model | Standard | Standard | DeepSeek V3 |
| Auto-test | - | Yes | Yes |
| Priority strategies | - | Yes | Yes |

Support the project: [DonatePay](https://new.donatepay.ru/@lenya)

## Project Structure

```
brain/
  genetic.py        # Geneva-inspired genetic algorithm
  ai_advisor.py     # LLM strategy advisor (via server proxy)
  analytics.py      # SQLite analytics engine
  tester.py         # Connection testing (mock + real)
  manager.py        # Strategy persistence
  profiler.py       # ISP fingerprinting
  tier.py           # Tier/license management
  sync.py           # Anonymous server sync + auto-registration
  donate.py         # DonatePay integration
  watchdog.py       # Strategy health monitoring
  svoboda_brain.py  # Main orchestrator

server/
  api.py            # FastAPI backend (telemetry, AI proxy, licensing)

lua/seeds/          # ISP-specific seed strategies
updater/            # Auto-update system
```

## Security & Privacy

- **Zero secrets in client code** — all API keys stay server-side
- **AI proxy architecture** — client never sees AI endpoints
- **Anonymous telemetry** — no IP, no MAC, no hostname, no accounts
- **Per-install tokens** — auto-generated, individually revocable
- **Open source** — audit the code yourself

## Self-Hosting the Server

```bash
git clone https://github.com/Leonid1095/PLGames-Svoboda.git
cd PLGames-Svoboda
sudo bash deploy_server.sh
```

The script sets up FastAPI + nginx + systemd. Compatible with existing 3x-ui installations.

See [ROADMAP.md](ROADMAP.md) for the full development plan.

## Contributing

Pull requests welcome. The genetic algorithm and AI prompt engineering are the most impactful areas for contribution.

## License

MIT
