# PLGames Svoboda -- DPI Bypass Tool

## Architecture
- **Client**: Python 3.11+, Windows (primary), Linux (secondary)
- **Server**: FastAPI on VPS (api.svaboda-shwe.online)
- **DPI Engine**: zapret2 (winws2.exe / nfqws2) + WinDivert driver
- **Brain**: 28 modules in brain/ (~10,500 lines) -- GA, AI, discovery, proxy routing
- **Orchestrator**: run_real.py (~2,300 lines) -- simple profiles, watchdog, cleanup
- **Tests**: 110 unit tests in tests/ (security, compilation, logic)

## Key Commands
- `python run_real.py` -- production mode (requires admin for WinDivert)
- `python run_shadow.py` -- shadow testing (separate winws2 instance)
- `fix_internet.bat` -- emergency: kill winws2, remove QUIC block, remove PAC proxy, flush DNS
- `python -c "import py_compile; py_compile.compile('run_real.py', doraise=True)"` -- syntax check
- `python -m pytest tests/ -v` -- run 110 unit tests

## CRITICAL RULES
- NEVER start winws2 without killing the previous instance first (WinDivert conflicts break internet)
- NEVER leave QUIC firewall rule on exit (Svoboda Block QUIC must be deleted)
- NEVER leave PAC proxy in Windows registry on exit (AutoConfigURL must be cleaned)
- NEVER hardcode API keys, tokens, or proxy credentials in tracked files
- NEVER add domains from list-exclude.txt to desync processing
- NEVER use fake packets -- TSPU detects and blocks ALL fake packets (April 2026)
- NEVER test bare googlevideo.com -- has invalid cert, not DPI. Real CDN is *.googlevideo.com
- ALWAYS wrap discovery/solver/watchdog code in try-finally to restart zapret2
- ALWAYS test that run_real.py compiles after changes
- ALWAYS check list-exclude.txt when adding new desync profiles
- If not sure about a desync strategy -- ASK, don't guess

## Profile System (run_real.py) -- SIMPLIFIED
Multi-profile approach (8 profiles) caused winws2 crashes. Now simplified:
- Profile 1: All TLS (port 443) -- found strategy via --hostlist
- Profile 2: HTTP (port 80) -- same strategy
- QUIC: blocked via Windows Firewall (forces browsers to use TCP where desync works)
- Per-host overrides: inserted before main profiles if host_solver found better per-domain strategy

## Safety Architecture
- `_emergency_cleanup()` in atexit + console handler:
  - Removes QUIC firewall rule (Svoboda Block QUIC)
  - Kills winws2 + gost processes
  - Removes PAC proxy from registry
  - Notifies WinINet of proxy change
- `_zapret_lock` -- threading.Lock on winws2 start/stop to prevent WinDivert conflicts
- `_start_permanent_zapret()` always kills previous instance before starting
- Shadow tester uses PID-targeted kill (not blanket taskkill)
- `list-exclude.txt` -- domains that must NEVER be processed (anthropic, google, microsoft, steam...)
- `hostlist-auto-fail-threshold=8` -- prevents innocent domains from being auto-added

## Verification (how we test strategies)
- `_curl_check_one()` -- follows redirects (-L), checks body size (>512B = real page)
- `test_strategy_thorough()` -- browser-like: -L, body check, full trial count
- Default test_hosts: youtube.com, www.youtube.com, discord.com, cdn.discordapp.com
- Fast screening (GA/enum): no -L, 1 trial (speed)
- Thorough/watchdog: -L, body check, 3 trials (accuracy)

## Security
- All API keys in env vars on server (os.environ.get), never in code
- config.json in .gitignore (contains install_id, server_api_key)
- Embedded proxy credentials removed from tier.py (was XOR+base64)
- Password masking in console output (proxy_router.py)
- Server secrets: AI_API_KEY, DEEPSEEK_API_KEY, DONATEPAY_API_KEY -- only on VPS
- SQLite thread-safe with threading.Lock (analytics.py)

## ISP Context
- Primary test ISP: er-telecom (AS42116, Tatarstan)
- DPI type: TSPU stateful (blocks ALL fake packets, SNI filtering)
- Working strategy: multisplit:pos=1:seqovl=568 | multidisorder:pos=1,midsld (no-fake)
- TSPU TTL: minimum 3, default 4 (CDN edge servers at 5-8 hops)

## Working Style
- Small diffs: one fix at a time, compile check, then next
- Always verify with `py_compile` before committing
- Read logs (svoboda.log) before diagnosing issues
- Test on real ISP after changes (run.bat)
- Run `python -m pytest tests/ -v` before committing

## Agents
- Use `planner` agent for planning complex changes
- Use `tester` agent after code changes to verify imports and compilation
- Use `code-reviewer` agent before commits to check for regressions
