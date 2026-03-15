"""PLGames Svoboda — Data Review Tool.

Run after 1+ day of data collection to analyze collected telemetry,
strategy effectiveness, and system health.

Usage:
    python review_data.py
    python review_data.py --db path/to/svoboda_analytics.db
    python review_data.py --log path/to/svoboda.log --json
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


def get_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def section(title: str) -> None:
    print()
    print(f"  {'=' * 56}")
    print(f"  {title}")
    print(f"  {'=' * 56}")
    print()


def review_analytics(db_path: str, as_json: bool = False) -> dict:
    """Analyze the local analytics database."""

    if not os.path.exists(db_path):
        print(f"  [ERROR] Database not found: {db_path}")
        return {}

    conn = get_db(db_path)
    report = {}

    # ── 1. Overview ──────────────────────────────────────────────────────
    section("1. DATABASE OVERVIEW")

    tables = {}
    for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
        name = row[0]
        count = conn.execute(f"SELECT COUNT(*) FROM [{name}]").fetchone()[0]
        tables[name] = count
        print(f"    {name:30s} {count:>6d} rows")

    db_size = os.path.getsize(db_path)
    print(f"\n    Database size: {db_size / 1024:.1f} KB")
    report["tables"] = tables
    report["db_size_kb"] = round(db_size / 1024, 1)

    # ── 2. Strategy analysis ─────────────────────────────────────────────
    section("2. STRATEGY ANALYSIS")

    strategies = conn.execute("""
        SELECT id, flags, fitness, isp, source, created_at
        FROM strategies
        ORDER BY fitness DESC
        LIMIT 20
    """).fetchall()

    if strategies:
        print(f"    Total strategies: {tables.get('strategies', 0)}")
        print()
        print(f"    {'#':>4s}  {'Fitness':>7s}  {'ISP':>15s}  {'Source':>8s}  Flags")
        print(f"    {'-' * 80}")

        top_strategies = []
        for i, s in enumerate(strategies, 1):
            flags_raw = s["flags"]
            flags = json.loads(flags_raw) if isinstance(flags_raw, str) else flags_raw
            flags_str = " ".join(flags) if isinstance(flags, list) else str(flags)
            isp_val = s["isp"] if s["isp"] else "unknown"
            src_val = s["source"] if s["source"] else "local"
            print(f"    {i:4d}  {s['fitness']:7.3f}  {isp_val:>15s}  {src_val:>8s}  {flags_str[:60]}")
            top_strategies.append({
                "fitness": s["fitness"],
                "flags": flags,
                "isp": s["isp"],
            })

        report["top_strategies"] = top_strategies

        # Fitness distribution
        print()
        dist = conn.execute("""
            SELECT
                COUNT(CASE WHEN fitness >= 0.9 THEN 1 END) as excellent,
                COUNT(CASE WHEN fitness >= 0.7 AND fitness < 0.9 THEN 1 END) as good,
                COUNT(CASE WHEN fitness >= 0.5 AND fitness < 0.7 THEN 1 END) as medium,
                COUNT(CASE WHEN fitness < 0.5 THEN 1 END) as poor,
                AVG(fitness) as avg_fitness,
                MAX(fitness) as max_fitness,
                MIN(fitness) as min_fitness
            FROM strategies
        """).fetchone()

        print(f"    Fitness distribution:")
        print(f"      Excellent (>=0.9): {dist['excellent']}")
        print(f"      Good (0.7-0.9):    {dist['good']}")
        print(f"      Medium (0.5-0.7):  {dist['medium']}")
        print(f"      Poor (<0.5):       {dist['poor']}")
        print(f"      Average:           {dist['avg_fitness']:.3f}")
        print(f"      Best:              {dist['max_fitness']:.3f}")
        print(f"      Worst:             {dist['min_fitness']:.3f}")

        report["fitness_distribution"] = {
            "excellent": dist["excellent"],
            "good": dist["good"],
            "medium": dist["medium"],
            "poor": dist["poor"],
            "avg": round(dist["avg_fitness"], 3),
            "max": round(dist["max_fitness"], 3),
            "min": round(dist["min_fitness"], 3),
        }
    else:
        print("    No strategies recorded yet.")

    # ── 3. Evolution log ─────────────────────────────────────────────────
    section("3. EVOLUTION LOG")

    evolutions = conn.execute("""
        SELECT generation, best_fitness, avg_fitness, best_flags, population_size, isp, logged_at
        FROM evolution_log
        ORDER BY logged_at DESC
        LIMIT 50
    """).fetchall()

    if evolutions:
        # Group by run (same isp + close timestamps)
        runs = []
        current_run = []
        last_isp = None

        for ev in reversed(evolutions):
            if ev["isp"] != last_isp and current_run:
                runs.append(current_run)
                current_run = []
            current_run.append(ev)
            last_isp = ev["isp"]
        if current_run:
            runs.append(current_run)

        print(f"    Evolution runs detected: {len(runs)}")
        print()

        for i, run in enumerate(runs, 1):
            first = run[0]
            last = run[-1]
            improvement = last["best_fitness"] - first["best_fitness"]
            print(f"    Run {i}: ISP={first['isp']} | {len(run)} generations")
            print(f"      Start fitness:  {first['best_fitness']:.3f}")
            print(f"      Final fitness:  {last['best_fitness']:.3f}")
            print(f"      Improvement:    {improvement:+.3f}")
            print(f"      Final avg:      {last['avg_fitness']:.3f}")
            best_flags_raw = last["best_flags"] if "best_flags" in last.keys() else None
            if best_flags_raw:
                flags = json.loads(best_flags_raw) if isinstance(best_flags_raw, str) else best_flags_raw
                print(f"      Best flags:     {' '.join(flags) if isinstance(flags, list) else flags}")
            print()

        report["evolution_runs"] = len(runs)
    else:
        print("    No evolution data recorded yet.")

    # ── 4. Test results ──────────────────────────────────────────────────
    section("4. TEST RESULTS")

    tests = conn.execute("""
        SELECT COUNT(*) as total,
               AVG(success) as avg_success,
               COUNT(CASE WHEN success = 1 THEN 1 END) as successful
        FROM test_results
    """).fetchone()

    if tests and tests["total"] > 0:
        print(f"    Total tests:      {tests['total']}")
        print(f"    Avg success:      {tests['avg_success']:.3f}")
        print(f"    Success rate:     {tests['successful']}/{tests['total']} ({tests['successful']/tests['total']*100:.0f}%)")

        # Per-host breakdown
        host_stats = conn.execute("""
            SELECT host, COUNT(*) as cnt, AVG(success) as rate
            FROM test_results
            WHERE host IS NOT NULL
            GROUP BY host
            ORDER BY rate DESC
        """).fetchall()

        if host_stats:
            print()
            print(f"    Per-host success rates:")
            for h in host_stats:
                rate = h["rate"] if h["rate"] else 0
                bar_len = int(rate * 20)
                bar = "#" * bar_len + "." * (20 - bar_len)
                print(f"      {h['host']:20s} [{bar}] {rate*100:.0f}% ({h['cnt']} tests)")

        report["test_results"] = {
            "total": tests["total"],
            "avg_success": round(tests["avg_success"], 3),
            "success_rate": round(tests["successful"] / tests["total"], 3),
        }
    else:
        print("    No test results recorded yet.")

    # ── 5. ISP snapshots ─────────────────────────────────────────────────
    section("5. ISP / NETWORK PROFILE")

    isp_snapshots = conn.execute("""
        SELECT external_ip, asn, isp_name, org, region,
               middlebox_type, middlebox_ttl, middlebox_window, detected_at
        FROM isp_snapshots
        ORDER BY detected_at DESC
        LIMIT 10
    """).fetchall()

    if isp_snapshots:
        latest = isp_snapshots[0]
        print(f"    External IP:      {latest['external_ip'] or 'unknown'}")
        print(f"    ASN:              {latest['asn'] or 'unknown'}")
        print(f"    ISP:              {latest['isp_name'] or 'unknown'}")
        print(f"    Organization:     {latest['org'] or 'unknown'}")
        print(f"    Region:           {latest['region'] or 'unknown'}")
        print(f"    Middlebox type:   {latest['middlebox_type'] or 'unknown'}")
        if latest['middlebox_ttl']:
            print(f"    Middlebox TTL:    {latest['middlebox_ttl']}")
        if latest['middlebox_window']:
            print(f"    Middlebox window: {latest['middlebox_window']}")
        print(f"    Total snapshots:  {len(isp_snapshots)}")
        print(f"    Last check:       {latest['detected_at']}")

        report["isp"] = {
            "name": latest["isp_name"],
            "asn": latest["asn"],
            "region": latest["region"],
            "middlebox": latest["middlebox_type"],
        }
    else:
        print("    No ISP data recorded yet.")

    # ── 6. Sync queue ────────────────────────────────────────────────────
    section("6. SERVER SYNC STATUS")

    sync_stats = conn.execute("""
        SELECT
            COUNT(*) as total,
            COUNT(CASE WHEN synced = 0 THEN 1 END) as pending,
            COUNT(CASE WHEN synced = 1 THEN 1 END) as synced
        FROM sync_queue
    """).fetchone()

    if sync_stats:
        print(f"    Total queued:     {sync_stats['total']}")
        print(f"    Pending sync:     {sync_stats['pending']}")
        print(f"    Already synced:   {sync_stats['synced']}")

        if sync_stats["pending"] > 0:
            print()
            print(f"    [WARN] {sync_stats['pending']} events waiting to sync.")
            print(f"    Check server connectivity and server_api_url in config.json")

        report["sync"] = {
            "total": sync_stats["total"],
            "pending": sync_stats["pending"],
            "synced": sync_stats["synced"],
        }
    else:
        print("    No sync data.")

    # ── 7. Flag frequency analysis ───────────────────────────────────────
    section("7. FLAG FREQUENCY ANALYSIS")

    all_flags_rows = conn.execute("SELECT flags FROM strategies").fetchall()
    if all_flags_rows:
        flag_counts = {}
        for row in all_flags_rows:
            flags = json.loads(row["flags"]) if isinstance(row["flags"], str) else row["flags"]
            if isinstance(flags, list):
                for f in flags:
                    # Extract base flag name
                    base = f.split("=")[0] if "=" in f else f
                    flag_counts[base] = flag_counts.get(base, 0) + 1

        sorted_flags = sorted(flag_counts.items(), key=lambda x: x[1], reverse=True)
        print(f"    Most common flags across all strategies:")
        print()
        for flag, count in sorted_flags[:15]:
            bar_len = min(30, int(count / max(1, sorted_flags[0][1]) * 30))
            bar = "#" * bar_len
            print(f"      {flag:35s} {count:4d}x  {bar}")

        report["top_flags"] = dict(sorted_flags[:10])
    else:
        print("    No flag data to analyze.")

    conn.close()
    return report


def review_log(log_path: str) -> dict:
    """Analyze the svoboda.log file for errors and patterns."""
    section("8. LOG ANALYSIS")

    if not os.path.exists(log_path):
        print(f"    Log file not found: {log_path}")
        return {}

    log_size = os.path.getsize(log_path)
    print(f"    Log file: {log_path} ({log_size / 1024:.1f} KB)")
    print()

    errors = []
    warnings = []
    info_count = 0
    debug_count = 0
    first_ts = None
    last_ts = None

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Extract timestamp
            if line.startswith("["):
                ts_end = line.find("]")
                if ts_end > 0:
                    ts_str = line[1:ts_end]
                    if not first_ts:
                        first_ts = ts_str
                    last_ts = ts_str

            if "[ERROR]" in line:
                errors.append(line)
            elif "[WARNING]" in line:
                warnings.append(line)
            elif "[INFO]" in line:
                info_count += 1
            elif "[DEBUG]" in line:
                debug_count += 1

    print(f"    Time range:  {first_ts or 'N/A'} -> {last_ts or 'N/A'}")
    print(f"    Total lines: INFO={info_count}, DEBUG={debug_count}, WARN={len(warnings)}, ERROR={len(errors)}")
    print()

    if errors:
        print(f"    ---- ERRORS ({len(errors)}) ----")
        for e in errors[-20:]:  # Last 20 errors
            print(f"      {e[:120]}")
        print()

    if warnings:
        print(f"    ---- WARNINGS ({len(warnings)}) ----")
        # Group similar warnings
        warn_groups = {}
        for w in warnings:
            # Extract message part
            msg_start = w.find("] ", w.find("] ") + 2) + 2
            msg = w[msg_start:msg_start+80] if msg_start > 2 else w[:80]
            key = msg[:50]
            warn_groups[key] = warn_groups.get(key, 0) + 1

        for msg, count in sorted(warn_groups.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"      ({count}x) {msg}")
        print()

    report = {
        "log_size_kb": round(log_size / 1024, 1),
        "errors": len(errors),
        "warnings": len(warnings),
        "info": info_count,
        "time_range": f"{first_ts} -> {last_ts}",
    }

    if not errors and not warnings:
        print("    No errors or warnings found. System running clean.")

    return report


def print_recommendations(report: dict) -> None:
    """Print actionable recommendations based on the data review."""
    section("RECOMMENDATIONS")

    recs = []

    # Check fitness
    fitness_dist = report.get("fitness_distribution", {})
    if fitness_dist.get("avg", 0) < 0.5:
        recs.append("[!] Average fitness is low (<0.5). Mock testing may need tuning, or real testing should be enabled.")
    elif fitness_dist.get("avg", 0) >= 0.8:
        recs.append("[+] Average fitness is strong (>=0.8). Ready for real-world testing.")

    # Check sync
    sync = report.get("sync", {})
    if sync.get("pending", 0) > 10:
        recs.append(f"[!] {sync['pending']} events pending sync. Check server_api_url in config.json and server availability.")
    elif sync.get("synced", 0) > 0:
        recs.append("[+] Server sync is working. Data is being collected centrally.")

    # Check strategies
    if report.get("tables", {}).get("strategies", 0) < 5:
        recs.append("[i] Very few strategies recorded. Let it run longer or increase ga_population_size.")

    # Check ISP
    isp = report.get("isp", {})
    if isp.get("name") and isp["name"] != "unknown":
        recs.append(f"[+] ISP identified: {isp['name']} — GA can use ISP-specific seeds.")
    elif not isp:
        recs.append("[i] No ISP profile yet. Run the full daemon (not shadow mode) for ISP detection.")

    # Check logs
    if report.get("errors", 0) > 10:
        recs.append(f"[!] {report['errors']} errors in log. Review errors above for patterns.")

    if not recs:
        recs.append("[+] Everything looks good. Keep collecting data.")

    for r in recs:
        print(f"    {r}")
    print()


def main():
    parser = argparse.ArgumentParser(description="PLGames Svoboda — Data Review Tool")
    parser.add_argument("--db", default="svoboda_analytics.db", help="Path to analytics DB")
    parser.add_argument("--log", default="svoboda.log", help="Path to log file")
    parser.add_argument("--json", action="store_true", help="Output report as JSON")
    args = parser.parse_args()

    # Resolve paths relative to script dir
    base = Path(__file__).resolve().parent
    db_path = str(base / args.db) if not os.path.isabs(args.db) else args.db
    log_path = str(base / args.log) if not os.path.isabs(args.log) else args.log

    print()
    print("  ========================================================")
    print("   PLGames Svoboda — Data Review Report")
    print(f"   Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("  ========================================================")

    report = review_analytics(db_path, args.json)
    log_report = review_log(log_path)
    report.update(log_report)

    print_recommendations(report)

    if args.json:
        json_path = base / "review_report.json"
        json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"  JSON report saved to: {json_path}")
        print()


if __name__ == "__main__":
    main()
