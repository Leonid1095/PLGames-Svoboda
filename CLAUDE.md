# PLGames Svoboda -- DPI Bypass Tool

## Architecture
- **Client**: Python 3.11+, Windows (primary), Linux (secondary)
- **Server**: FastAPI on VPS (api.svaboda-shwe.online)
- **DPI Engine**: zapret2 v1.0.4 (winws2.exe / nfqws2) + WinDivert 2.2.2 driver
  Binaries are NOT in the zapret2 git repo -- only in GitHub releases. `updater/zapret2_updater.py`
  downloads + sha256-verifies them. Multiple `zapret2-v*` dirs may coexist; the NEWEST wins,
  picked numerically by `brain/zapret_paths.py` (a string sort puts v0.9.4.5 above v1.0.4).
  zapret2 v1.0 bumped LUA_COMPAT_VER to 6, so the binary and the lua/ dir must come from the SAME release.
- **Brain**: 44 modules in brain/ -- GA, AI, discovery, proxy routing, DNS, lint
- **Orchestrator**: run_real.py (~2,780 lines) -- simple profiles, watchdog, cleanup
- **GUI**: gui/ (PySide6) + run_gui.py -- desktop shell over the engine; reads runtime/status.json
- **Tests**: 328 unit tests in tests/ (security, compilation, logic, DNS, lint)

## Key Commands
- `python run_gui.py` -- friendly desktop shell (PySide6 + tray); self-elevates, spawns run_real.py as engine
- `python run_real.py` -- production mode (requires admin for WinDivert)
- `python run_shadow.py` -- shadow testing (separate winws2 instance)
- `fix_internet.bat` -- emergency: kill winws2, remove QUIC block, remove PAC proxy, flush DNS
- `python -c "import py_compile; py_compile.compile('run_real.py', doraise=True)"` -- syntax check
- `python -m pytest tests/ -v` -- run 328 unit tests
- `python -m updater.zapret2_updater [--check]` -- install/verify the newest zapret2 release

## CRITICAL RULES
- NEVER start winws2 without killing the previous instance first (WinDivert conflicts break internet)
- NEVER leave QUIC firewall rule on exit (Svoboda Block QUIC must be deleted)
- NEVER leave PAC proxy in Windows registry on exit (AutoConfigURL must be cleaned)
- NEVER hardcode API keys, tokens, or proxy credentials in tracked files
- NEVER add domains from list-exclude.txt to desync processing
- NEVER use fake packets ON TSPU (project policy; see the caveat below).
  Enforced in code: when tspu_profile.dpi_type starts with "tspu", run_real.py strips
  fake/fakedsplit/fakeddisorder/hostfakesplit from GA seeds, GA mutation pool, enumerator,
  and AI context (via _tspu_excluded / _FAKE_FUNCS). Kept ONLY for non-TSPU / unknown DPI.
  run_shadow.py intentionally keeps fake seeds -- it is the sandbox for re-testing the claim.
  CAVEAT (research 2026-09-01, _research/dpi-bypass-2026-09/findings.md): "TSPU blocks ALL
  fakes since April 2026" is NOT corroborated by any primary source. The 2026-04-06 outage
  was all-strategies/all-services (banks and Gosuslugi too), and Flowseal kept shipping
  fake profiles through Aug 2026. The documented detection vector is narrower: a fake and a
  real packet repeating the same non-zero ip_id -> use ip_id=zero. Re-test in run_shadow.py
  before relaxing the rule.
- NEVER measure through a proxy. HTTP(S)_PROXY in the environment silently routes every curl
  check through it: strategies look "working" while the real DPI path is untested, and the ISP
  is detected as the proxy's exit. run_real/run_shadow call brain.netenv.scrub_proxy_env() at
  startup and every measurement curl carries --noproxy * (brain/netenv.py CURL_DIRECT).
- NEVER trust a "not blocked" DPI probe taken while a bypass is running -- it says nothing about
  the DPI. Russian networks (country RU or a known RU ISP) are always classified tspu_*; a probe
  behind an active bypass is marked probe_inconclusive (brain/tspu_profiler.py).
- NEVER test bare googlevideo.com -- has invalid cert, not DPI. Real CDN is *.googlevideo.com
- ALWAYS wrap discovery/solver/watchdog code in try-finally to restart zapret2
- ALWAYS test that run_real.py compiles after changes
- ALWAYS check list-exclude.txt when adding new desync profiles
- If not sure about a desync strategy -- ASK, don't guess
- ALWAYS lint new/changed strategies: `brain/strategy_lint.py` validates them against the
  INSTALLED engine's zapret-antidpi.lua. winws2 needs admin even to parse arguments, so a typo
  is otherwise found only on a live run -- or never, because an invalid desync is silently
  skipped and then scores like a working bypass.

## Profile System (run_real.py) -- SIMPLIFIED
Multi-profile approach (8 profiles) caused winws2 crashes. Now simplified:
- Profile 1: All TLS (port 443) -- found strategy via --hostlist
- Profile 2: HTTP (port 80) -- same strategy
- QUIC: blocked via Windows Firewall (forces browsers to use TCP where desync works)
- Per-host overrides: inserted before main profiles if host_solver found better per-domain strategy
- Profile 3 (opt-in `discord_udp_fake`): Discord voice/STUN on UDP 19294-19344, 50000-50100.
  UDP cannot be split, so a fake blob is the only known desync -- OFF by default under no-fake.
- Named blobs: strategies may reference real ClientHello patterns (`seqovl_pattern=tls_google`).
  `brain/zapret_blobs.py` resolves the name to a file and emits `--blob=name:@path`, taking it
  from the engine's `files/fake/` or from `blobs/` (mirrored from Flowseal by the harvester).
  A missing blob makes zapret2 v1.0.4 skip the packet (VERDICT_PASS), so only referenced
  blobs are passed -- long winws2 command lines have caused crashes before.

## GUI Shell (gui/ + run_gui.py)
- PySide6 desktop app + system tray. Thin frontend -- NEVER desyncs packets itself.
- Engine IPC: run_real.py writes runtime/status.json via brain/status_writer.py
  (atomic, best-effort, never raises into engine); GUI polls it every 1s.
- `run_gui.py` self-elevates (UAC) so the run_real.py child inherits admin for WinDivert.
- Single-instance guard (QSharedMemory) -- two engines = WinDivert conflict = broken internet.
- CRITICAL: GUI Stop is a 3-step contract (gui/engine_bridge.py). TerminateProcess does NOT
  fire the engine's atexit/_emergency_cleanup, so the GUI must guarantee cleanup itself:
    1. Ask nicely -- write runtime/stop.request; the engine polls it and exits its normal way.
    2. If it is still alive after ~12s (busy enumerating), terminate it.
    3. ALWAYS run brain.net_cleanup.cleanup_network() afterwards. It is idempotent, so running
       it after a clean exit is harmless. fix_internet.bat stays the MANUAL last resort -- its
       winsock/IP-stack reset and WinDivert service deletion are too heavy for every Stop and
       can break other software.
  Stop runs off the UI thread (stop_async) so the window does not freeze during cleanup.
- Status states: stopped | starting | searching | active | error (see status_writer constants).

## Concurrency: ONE winws2, ever
One WinDivert driver means one instance. Three ways this was violated, all fixed:
- The engine now holds a named mutex (`Global\PLGamesSvobodaEngine`). A second
  `run_real.py` refuses to start. The GUI's QSharedMemory guard covers only the GUI,
  so an orphaned engine plus a fresh launch used to give two engines flapping.
- `_zapret_maintenance` (threading.Event) is set by `_stop_permanent_zapret` and
  cleared by `_start_permanent_zapret`. The health monitor skips respawning while it
  is set, and needs two consecutive dead readings — otherwise it read the 1-4s window
  where `_active_process` still points at a just-terminated process, called it a crash,
  and respawned on top of the shadow tester.
- The GA's per-generation callback must NEVER start a permanent instance: `ga.evolve()`
  keeps starting shadow instances between callbacks. The winner is applied after
  evolution finishes.
Every exit path that returns while a permanent instance exists must stop it first —
otherwise the QUIC rule and CertificateRevocation=0 stay applied, possibly while
`_pause_exit` blocks on the console.

## winws2 profiles are independent
zapret2 picks the FIRST profile whose filter matches, and a profile sees only its OWN
options — nothing is inherited across `--new`. So `--hostlist`/`--hostlist-exclude` are
emitted into EVERY traffic profile. Two bugs came from getting this wrong: the HTTP
profile had no hostlist at all (it desynced every port-80 flow, excluded domains
included), and the main TLS profile had no `--new` before it, so it fused into the last
per-host override and the general hostlist lost its TLS desync entirely. The shadow
tester gets the exclude list too — a GA run lasts minutes and must not desync antivirus
or anti-cheat traffic.

## Safety Architecture
- `brain/net_cleanup.py` -- ONE implementation of the restore steps, shared by the engine's
  `_emergency_cleanup()` (atexit + console handler) and the GUI Stop button:
  - Removes QUIC firewall rule (Svoboda Block QUIC)
  - Restores CertificateRevocation=1 (the engine sets 0 because DPI blocks CRL servers)
  - Kills winws2 + gost + ciadpi processes
  - Removes PAC proxy from registry + notifies WinINet
  - Removes the hosts-file DNS block, flushes DNS
  Every step is best-effort and independent: one failing must not skip the rest.
  `_legacy_emergency_cleanup()` in run_real.py is the fallback if the module cannot be imported.
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
- Deep fetch (`_curl_test_h2_stream`) requests 64KB and now checks how much ARRIVED.
  TSPU lets ~16KB through to suspect foreign/CDN IPs and then silently stalls the connection
  with no RST, which a ">512B body" check scores as success -- YouTube "works" but no video
  plays. A timeout holding 8-32KB is reported as `freeze16k` and is NOT a success; other
  partials are `truncated`. Both are weighted like a timeout in fitness. A short resource that
  ends cleanly stays a success. (Range requests answer 206, which was missing from the success
  codes -- every deep fetch used to be scored as a failure.)

## Security
- All API keys in env vars on server (os.environ.get), never in code
- config.json in .gitignore (contains install_id, server_api_key)
- Embedded proxy credentials removed from tier.py (was XOR+base64)
- Password masking in console output (proxy_router.py)
- Server secrets: AI_API_KEY, DEEPSEEK_API_KEY, DONATEPAY_API_KEY -- only on VPS
- SQLite thread-safe with threading.Lock (analytics.py)

## DNS (why desync alone is not enough)
- Desync cannot fix a wrong IP. Seen live on er-telecom: youtube/x/discord/instagram all
  resolved to ONE foreign "SNI proxy" that serves some of them and not others (discord =
  curl exit 60 on EVERY strategy), and instagram/rutracker to an ISP stub.
- `brain/dns_fixer.py::diagnose_and_fix_dns` TLS-probes each system answer and overrides ONLY
  answers proven bogus (certificate for another name, the shared stub IP, or one IP shared by
  2+ unrelated hosts). A DPI block with a correct IP is left to the desync engine.
- `brain/dns_resolver.py` resolves without the ISP: DoH -> DoT (853) -> plain DNS (UDP/TCP 53)
  to public resolvers, implementing the DNS wire format on stdlib only. Verified working on
  er-telecom while the ISP resolver was poisoned.
- Google DoH / Cloudflare DoT are SNI-blocked at several RU ISPs since 2026-07-03, so the DoH
  hostnames are in the hostlist (desyncing them makes DoH work again) and the provider list
  includes IP-URL variants.

## ISP Context
- Primary test ISP: er-telecom (AS42116, Tatarstan)
- DPI type: TSPU stateful (SNI filtering; see the fake-packet caveat above)
- Working strategy: multisplit:pos=1:seqovl=568 | multidisorder:pos=1,midsld (no-fake)
- TSPU TTL: minimum 3, default 4 (CDN edge servers at 5-8 hops)
- `tcp_ts` fooling needs the TCP Timestamp option, which Windows 11 disables by default.
  The enumerator probes it once and drops tcp_ts strategies when it is off (brain/netenv.py).

## Hostlists
- `hostlist-curated.txt` is the TRACKED source of truth; `hostlist.txt` is the gitignored
  runtime copy the GUI edits. It is seeded from the curated file and NEVER overwritten by a
  download -- the 81k Re-filter list broke AV, Steam and anti-cheat. Public blocklists are only
  a last resort when neither file exists.
- Geo/sanctions restrictions (PSN, Xbox, EA store, Netflix, Spotify) are NOT DPI blocks:
  desync cannot fix them and only risks breaking the service. Keep them out.

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
