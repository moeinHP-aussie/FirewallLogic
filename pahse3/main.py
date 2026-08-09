"""
main.py — Phase 3 entry point
==============================
Usage:
    python3 main.py <config_file>
    python3 main.py <config_file> --format text     (default)
    python3 main.py <config_file> --format json
    python3 main.py --demo                           (runs built-in sample)

The pipeline:
    1. Read the firewall config file
    2. parser.py  → list of Rule objects
    3. bridge.py  → Prolog engine → list of Finding objects
    4. Render a report (text or JSON) to stdout

Phase 4 will add HTML/PDF rendering here without changing steps 1-3.
"""

import sys
import json
import argparse
from pathlib import Path

from parser import parse, ParseError
from bridge import run_engine, Finding

# -------------------------------------------------------------------
# 1. Report renderers
# -------------------------------------------------------------------

SEVERITY_LABEL = {
    "critical": "بحرانی",
    "high":     "شدید",
    "medium":   "متوسط",
    "low":      "کم",
}

TYPE_LABEL = {
    "shadowing":      "سایه‌خوردگی",
    "redundancy":     "افزونگی",
    "correlation":    "تداخل / تعارض",
    "generalization": "تعمیم",
}


def configure_utf8_output() -> None:
    """Keep reports usable on Windows consoles configured with a legacy codec."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            # Non-standard streams used by embedders/test runners may not
            # expose reconfigure(); their encoding remains the caller's job.
            pass


def render_text(findings: list[Finding], rules_count: int,
                errors: list[ParseError], source_name: str) -> str:
    lines = [
        "=" * 70,
        "  گزارش ممیزی قوانین فایروال",
        f"  منبع: {source_name}",
        f"  قوانین تحلیل‌شده: {rules_count}",
        f"  خطوط پشتیبانی‌نشده: {len(errors)}",
        f"  یافته‌ها: {len(findings)}",
        "=" * 70,
    ]

    if not findings:
        lines += ["", "  هیچ آنومالی‌ای کشف نشد.", ""]
        return "\n".join(lines)

    current_severity = None
    for f in findings:
        if f.severity != current_severity:
            current_severity = f.severity
            lines += [
                "",
                f"── {SEVERITY_LABEL.get(f.severity, f.severity.upper())} ──",
            ]
        lines += [
            "",
            f"  [{TYPE_LABEL.get(f.type, f.type)}]  Rule #{f.primary_id} ↔ Rule #{f.secondary_id}",
            "",
        ]
        for expl_line in f.explanation.splitlines():
            lines.append("    " + expl_line)
        lines.append("")

    if errors:
        lines += [
            "─" * 70,
            f"  تحلیل ناقص است: {len(errors)} خط پشتیبانی یا مدل نشده است:",
        ]
        for e in errors[:10]:  # show at most 10 skipped lines
            lines.append(f"    خط {e.line_number}: {e.reason}")
            lines.append(f"      {e.raw_line!r}")
        if len(errors) > 10:
            lines.append(f"    ... و {len(errors)-10} مورد دیگر")

    lines.append("=" * 70)
    return "\n".join(lines)


def render_json(findings: list[Finding], rules_count: int,
                errors: list[ParseError], source_name: str) -> str:
    return json.dumps({
        "source":       source_name,
        "rules_parsed": rules_count,
        "lines_skipped": len(errors),
        "analysis_complete": not errors,
        "findings": [
            {
                "type":         f.type,
                "severity":     f.severity,
                "primary_rule": f.primary_id,
                "secondary_rule": f.secondary_id,
                "explanation":  f.explanation,
            }
            for f in findings
        ],
        "parse_errors": [
            {"line": e.line_number, "text": e.raw_line, "reason": e.reason}
            for e in errors
        ],
    }, ensure_ascii=False, indent=2)


# -------------------------------------------------------------------
# 2. Demo config (for --demo flag)
# -------------------------------------------------------------------

DEMO_CONFIG = """\
# Demo iptables-save config — contains intentional anomalies
*filter
:INPUT   DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT  ACCEPT [0:0]

# [1] Allow all internal LAN to reach web server
-A FORWARD -s 172.16.0.0/16 -d 10.0.0.5 -p tcp --dport 80 -j ACCEPT

# [2] SHADOWED: this deny can never fire (rule 1 already covers 172.16.1.10)
-A FORWARD -s 172.16.1.10 -d 10.0.0.5 -p tcp --dport 80 -j DROP

# [3] Allow broad internal range to reach database tier on HTTPS
-A FORWARD -s 192.168.0.0/16 -d 10.1.0.0/16 -p tcp --dport 443 -j ACCEPT

# [4] REDUNDANT: 10.1.5.0/24 is fully covered by rule 3 with same action
-A FORWARD -s 192.168.0.0/16 -d 10.1.5.0/24 -p tcp --dport 443 -j ACCEPT

# [5] Allow DNS
-A FORWARD -p udp --dport 53 -j ACCEPT

# [6] Default deny
-A FORWARD -j DROP
COMMIT
"""


# -------------------------------------------------------------------
# 3. Main
# -------------------------------------------------------------------

def main():
    configure_utf8_output()
    ap = argparse.ArgumentParser(description="Firewall Anomaly Auditor — Phase 3")
    ap.add_argument("config", nargs="?", help="Path to firewall config file")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--demo", action="store_true", help="Run with built-in demo config")
    ap.add_argument("--strict", action="store_true",
                    help="Fail instead of producing a partial report when any rule is unsupported")
    args = ap.parse_args()

    if args.demo:
        config_text = DEMO_CONFIG
        source_name = "<demo config>"
    elif args.config:
        path = Path(args.config)
        if not path.exists():
            print(f"Error: file not found: {path}", file=sys.stderr)
            sys.exit(1)
        config_text = path.read_text(encoding="utf-8")
        source_name = str(path)
    else:
        ap.print_help()
        sys.exit(1)

    # Step 1: parse
    rules, parse_errors = parse(config_text)
    if not rules:
        print("No rules could be parsed from the input.", file=sys.stderr)
        for e in parse_errors:
            print(f"  line {e.line_number}: {e.reason}", file=sys.stderr)
        sys.exit(1)
    if args.strict and parse_errors:
        print("Analysis stopped: unsupported rules make a strict report incomplete.", file=sys.stderr)
        sys.exit(2)

    # Step 2: run Prolog engine
    findings, engine_error = run_engine(rules)
    if engine_error:
        print(f"Engine error: {engine_error}", file=sys.stderr)
        sys.exit(1)

    # Step 3: render report
    if args.format == "json":
        print(render_json(findings, len(rules), parse_errors, source_name))
    else:
        print(render_text(findings, len(rules), parse_errors, source_name))


if __name__ == "__main__":
    main()
