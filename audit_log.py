"""
audit_log.py — append-only record of every analysis run
==========================================================
For a security tool used by an IT department, "who ran an analysis,
when, on what, and what did it find" needs to be reconstructable later
-- e.g. if a firewall change goes wrong and someone asks "did we check
this beforehand?".

Design choices, deliberately kept simple for v1:

  - Plain CSV, one row per completed analysis, append-only. No database
    dependency, human-readable/greppable with any spreadsheet tool the
    IT staff already has, and trivially backed up (it's one file).
  - FAIL-OPEN: logging failures (disk full, permissions, concurrent
    write issues on some odd filesystem) must NEVER block or corrupt
    an actual security analysis. log_run() below catches everything
    and returns a bool rather than raising -- callers can surface a
    non-fatal warning but must still render the real report.
  - No PII beyond what's already in the uploaded filename (no attempt
    at authenticated "who" yet -- see README's Known Limitations; this
    logs WHAT was analyzed and WHEN, which is the part that doesn't
    require adding an auth layer first).
  - Uses Python's csv module (not manual string joining) so filenames
    or explanations containing commas/quotes/newlines round-trip
    correctly instead of corrupting the log's column structure.
"""

from __future__ import annotations

import csv
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

_LOG_PATH = Path(__file__).parent / "audit_log.csv"
_HEADER = [
    "timestamp_utc",
    "mode",              # "full" | "incremental"
    "source_name",        # uploaded filename(s)
    "rules_count",         # rules analyzed (base+new for incremental)
    "new_rules_count",      # empty for full mode
    "findings_total",
    "findings_critical",
    "findings_high",
    "findings_medium",
    "findings_low",
    "parse_errors_count",
    "analysis_complete",     # "yes" | "no" (had unsupported lines)
    "engine_backend",         # "pyswip" | "subprocess"
]

# csv writes from multiple simultaneous Flask requests (Flask's dev
# server is single-threaded by default, but production WSGI servers
# like gunicorn with multiple workers/threads are not) could otherwise
# interleave partial rows. One process-wide lock keeps each row atomic;
# it does not help across multiple separate OS processes (e.g. several
# gunicorn workers) -- see README's Known Limitations for that caveat.
_lock = threading.Lock()


def _ensure_header() -> None:
    if not _LOG_PATH.exists() or _LOG_PATH.stat().st_size == 0:
        with open(_LOG_PATH, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(_HEADER)


def log_run(
    mode: str,
    source_name: str,
    rules_count: int,
    findings: list,          # list[bridge.Finding]
    parse_errors_count: int,
    analysis_complete: bool,
    engine_backend: str,
    new_rules_count: int | None = None,
) -> bool:
    """Appends one row describing a completed analysis run.
    Returns True on success, False on any logging failure -- callers
    should treat False as non-fatal (log a stderr warning at most) and
    must still return the real report to the user either way.
    """
    try:
        with _lock:
            _ensure_header()
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for finding in findings:
                if finding.severity in severity_counts:
                    severity_counts[finding.severity] += 1

            with open(_LOG_PATH, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow([
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    mode,
                    source_name,
                    rules_count,
                    "" if new_rules_count is None else new_rules_count,
                    len(findings),
                    severity_counts["critical"],
                    severity_counts["high"],
                    severity_counts["medium"],
                    severity_counts["low"],
                    parse_errors_count,
                    "yes" if analysis_complete else "no",
                    engine_backend,
                ])
        return True
    except OSError as e:
        # Disk full, permissions, path unwritable, etc. -- log to stderr
        # and let the caller continue; a missed audit-log line is far
        # less bad than a failed/blocked security analysis.
        print(f"[audit_log] failed to write audit log entry: {e}", flush=True)
        return False
