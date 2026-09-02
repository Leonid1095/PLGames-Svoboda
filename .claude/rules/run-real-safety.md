---
globs: ["run_real.py"]
---
# run_real.py Safety Rules
- _start_permanent_zapret() MUST call _stop_permanent_zapret() before starting
- _active_process must NEVER stay None after try-finally blocks
- Every watchdog/discovery/solver block: stop zapret → try work → finally restart zapret
- Profile changes require checking list-exclude.txt and _gentle_exclude domains
- TTL for fake packets: minimum 3, never lower (CDN servers at hop 5-8)
- hostlist-auto-fail-threshold must be >= 8 (prevents false positives)
- All return/break paths from watchdog loops must call _stop_permanent_zapret if _active_process exists
