# PLGames Svoboda — DPI Bypass Tool

## Architecture
- **Client**: Python 3.11+, Windows (primary), Linux (secondary)
- **Server**: FastAPI on VPS (api.svaboda-shwe.online)
- **DPI Engine**: zapret2 (winws2.exe / nfqws2) + WinDivert driver
- **Brain**: 28 modules in brain/ (~10,500 lines) — GA, AI, discovery, proxy routing
- **Orchestrator**: run_real.py (~2,100 lines) — profiles, watchdog, cleanup

## Key Commands
- `python run_real.py` — production mode (requires admin for WinDivert)
- `python run_shadow.py` — shadow testing (separate winws2 instance)
- `fix_internet.bat` — emergency: kill winws2, remove PAC proxy, flush DNS
- `python -c "import py_compile; py_compile.compile('run_real.py', doraise=True)"` — syntax check

## CRITICAL RULES
- NEVER start winws2 without killing the previous instance first (WinDivert conflicts break internet)
- NEVER leave PAC proxy in Windows registry on exit (AutoConfigURL must be cleaned)
- NEVER hardcode API keys, tokens, or proxy credentials in tracked files
- NEVER add domains from list-exclude.txt to desync processing
- NEVER use fake packets on YouTube image CDN (ytimg, ggpht, googleapis) — corrupts thumbnails
- ALWAYS wrap discovery/solver/watchdog code in try-finally to restart zapret2
- ALWAYS test that run_real.py compiles after changes: `python -c "import py_compile; py_compile.compile('run_real.py', doraise=True)"`
- ALWAYS check list-exclude.txt when adding new desync profiles
- If not sure about a desync strategy — ASK, don't guess (wrong TTL/fake can break CDN)

## Profile System (run_real.py)
- Profile 1: General TLS (excludes YouTube+Discord domains) — aggressive desync from GA
- Profile 2a: YouTube video (googlevideo, youtube.com) — fake + multisplit (needs fake for TLS_INTERFERENCE)
- Profile 2b: YouTube images (ytimg, ggpht, googleapis) — multisplit only (NO fake — CDN too close)
- Profile 3: Discord TLS — multisplit:pos=1:seqovl=4096 (host solver confirmed)
- Profile 4: HTTP port 80
- Profile 5: Discord media TCP 2053-8443 — multisplit:pos=1:seqovl=4096
- Profile 6: Discord voice UDP 50000-50100
- Profile 7: QUIC UDP 443

## Safety Architecture
- `_emergency_cleanup()` in atexit + console handler (kills winws2, removes PAC, notifies WinINet)
- `atexit.register(router.shutdown)` — ensures PAC proxy cleanup on ANY exit
- `_start_permanent_zapret()` always kills previous instance before starting
- `list-exclude.txt` — domains that must NEVER be processed (anthropic, google, microsoft, steam...)
- `hostlist-auto-fail-threshold=8` — prevents innocent domains from being auto-added

## Security
- All API keys in env vars on server (os.environ.get), never in code
- config.json in .gitignore (contains install_id, server_api_key)
- Proxy URL obfuscated with XOR+base64 in tier.py
- Server secrets: AI_API_KEY, DEEPSEEK_API_KEY, DONATEPAY_API_KEY — only on VPS

## ISP Context
- Primary test ISP: er-telecom (AS42116, Tatarstan)
- DPI type: TSPU with TLS_INTERFERENCE (sends RST packets on SNI match)
- TSPU TTL: minimum 3, default 4 (CDN edge servers at 5-8 hops)

## Working Style
- Small diffs: one fix at a time, compile check, then next
- Always verify with `py_compile` before committing
- Read logs (svoboda.log) before diagnosing issues
- Test on real ISP after changes (run.bat)

## Agents
- Use `planner` agent for planning complex changes
- Use `tester` agent after code changes to verify imports and compilation
- Use `code-reviewer` agent before commits to check for regressions
