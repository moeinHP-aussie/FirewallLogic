"""Local web interface for Phase 4 firewall-policy reports."""

from __future__ import annotations

from collections import Counter

from flask import Flask, render_template, request

from bridge import Finding, run_engine
from parser import ParseError, parse

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

SEVERITY_ORDER = ("critical", "high", "medium", "low")
SEVERITY_LABELS = {
    "critical": "بحرانی",
    "high": "شدید",
    "medium": "متوسط",
    "low": "کم",
}
TYPE_LABELS = {
    "shadowing": "سایه‌خوردگی",
    "redundancy": "افزونگی",
    "correlation": "تداخل / تعارض",
    "generalization": "تعمیم",
}
RECOMMENDATIONS = {
    "shadowing": "قانون ثانویه هرگز اجرا نمی‌شود؛ ترتیب دو قانون را بازبینی کنید یا قانون غیرقابل‌دسترسی را حذف کنید.",
    "redundancy": "قانون افزونه تصمیمی را تغییر نمی‌دهد؛ پس از تأیید مسئول شبکه، حذف یا ادغام آن را بررسی کنید.",
    "correlation": "دو قانون روی بخشی از ترافیک نتیجهٔ متضاد دارند؛ ترتیب و هدف امنیتی آن‌ها باید دستی تأیید شود.",
    "generalization": "ممکن است این ترتیب عمدی باشد؛ آن را مستند کنید تا در تغییرات بعدی جابه‌جا نشود.",
}


def _finding_view(finding: Finding) -> dict[str, str | int]:
    return {
        "type": TYPE_LABELS[finding.type],
        "severity": SEVERITY_LABELS[finding.severity],
        "severity_key": finding.severity,
        "primary_rule": finding.primary_id,
        "secondary_rule": finding.secondary_id,
        "explanation": finding.explanation,
        "recommendation": RECOMMENDATIONS[finding.type],
    }


def _report_context(
    source_name: str,
    rules_count: int,
    errors: list[ParseError],
    findings: list[Finding],
    strict: bool,
    strict_blocked: bool = False,
) -> dict:
    counts = Counter(finding.severity for finding in findings)
    return {
        "source_name": source_name,
        "rules_count": rules_count,
        "errors": errors,
        "findings": [_finding_view(finding) for finding in findings],
        "findings_count": len(findings),
        "severity_cards": [
            {"key": key, "label": SEVERITY_LABELS[key], "count": counts[key]}
            for key in SEVERITY_ORDER
        ],
        "analysis_complete": not errors,
        "strict": strict,
        "strict_blocked": strict_blocked,
    }


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/analyze")
def analyze():
    uploaded = request.files.get("config")
    strict = request.form.get("strict") == "on"
    if uploaded is None or not uploaded.filename:
        return render_template("index.html", error="یک فایل پیکربندی انتخاب کنید."), 400

    try:
        config_text = uploaded.read().decode("utf-8-sig")
    except UnicodeDecodeError:
        return render_template(
            "index.html",
            error="فایل باید با UTF-8 ذخیره شده باشد تا تحلیل بدون ابهام انجام شود.",
        ), 400

    rules, parse_errors = parse(config_text)
    if not rules:
        return render_template(
            "index.html",
            error="هیچ قانون پشتیبانی‌شده‌ای در فایل پیدا نشد.",
        ), 422

    if strict and parse_errors:
        context = _report_context(
            uploaded.filename, len(rules), parse_errors, [], strict, strict_blocked=True
        )
        return render_template("report.html", **context), 422

    findings, engine_error = run_engine(rules)
    if engine_error:
        return render_template("index.html", error=f"خطای موتور تحلیل: {engine_error}"), 500

    context = _report_context(uploaded.filename, len(rules), parse_errors, findings, strict)
    return render_template("report.html", **context)


@app.errorhandler(413)
def too_large(_error):
    return render_template("index.html", error="حجم فایل باید حداکثر ۵ مگابایت باشد."), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
