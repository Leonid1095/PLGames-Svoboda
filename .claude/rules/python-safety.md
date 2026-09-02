---
globs: ["**/*.py"]
---
# Python Safety Rules
- All subprocess calls to winws2/nfqws2 must kill previous instance first
- All exit paths must clean up: PAC proxy, winws2 process, gost tunnel
- Never bare `except:` — always `except Exception as exc:` with logging
- Wrap long-running operations (solver, discovery, enum) in try-finally
- Use `timeout` parameter on all subprocess.run calls
- Never store secrets in Python files — use os.environ.get() or config.json
