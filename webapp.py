"""Local web interface for Phase 4 firewall-policy reports."""

from __future__ import annotations

import os
import secrets
import time
from collections import Counter

from flask import Flask, Response, render_template, request

from bridge import Finding, backend_name, run_engine
from incremental import check_new_rules
from parser import ParseError, parse
import audit_log

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

# ── minimal access control ──────────────────────────────────────────
# This app reads firewall topology (IPs, ports, allow/deny structure)
# uploaded by whoever can reach it -- that's sensitive enough that an
# unauthenticated, network-reachable instance is not acceptable for
# real IT-center use, even though the analysis itself is read-only and
# makes no changes to the actual firewall.
#
# Deliberately kept to single-shared-password HTTP Basic Auth rather
# than a full user/session/database system: this app has no per-user
# state or roles to justify that complexity yet (see README's Known
# Limitations for what a real multi-user login would need). Basic Auth
# over plain HTTP still sends the password in a trivially-decodable
# (base64, not encrypted) form on every request -- it is NOT a
# substitute for running this behind HTTPS/a reverse proxy if it is
# ever exposed beyond localhost/a trusted LAN.
#
# Auth is OFF (open access) unless FIREWALLLOGIC_PASSWORD is set in
# the environment, so the zero-setup local/demo workflow
# (`python3 webapp.py` with no configuration) keeps working exactly as
# before for anyone who hasn't opted in.
_AUTH_PASSWORD = os.environ.get("FIREWALLLOGIC_PASSWORD")
_AUTH_USERNAME = os.environ.get("FIREWALLLOGIC_USERNAME", "admin")


def _check_auth(username: str, password: str) -> bool:
    # secrets.compare_digest instead of == to avoid a timing side
    # channel leaking how many leading characters of the password guess
    # were correct.
    return (
        secrets.compare_digest(username, _AUTH_USERNAME)
        and secrets.compare_digest(password, _AUTH_PASSWORD)
    )


@app.before_request
def _require_auth():
    if _AUTH_PASSWORD is None:
        return None  # auth not configured — open access, as before
    auth = request.authorization
    if not auth or not _check_auth(auth.username or "", auth.password or ""):
        lang = _resolve_lang()
        message = (
            "دسترسی نیازمند احراز هویت است."
            if lang == "fa"
            else "Authentication is required."
        )
        return Response(
            message,
            401,
            {"WWW-Authenticate": 'Basic realm="FirewallLogic"'},
        )
    return None


SEVERITY_ORDER = ("critical", "high", "medium", "low")

# ── bilingual content ───────────────────────────────────────────────
# Every user-facing string that lives in Python (as opposed to inside
# firewall_engine.pl's Explanation text, which bridge.py/webapp.py
# receive already rendered in the right language via lang=...) is
# keyed here by language so a single _t()/_labels_for() lookup covers
# both. fa stays first / default in every dict so behavior for anyone
# who never touches the language switch is byte-for-byte unchanged
# from before this feature existed.
SUPPORTED_LANGS = ("fa", "en")
DEFAULT_LANG = "en"

SEVERITY_LABELS = {
    "fa": {"critical": "بحرانی", "high": "شدید", "medium": "متوسط", "low": "کم"},
    "en": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"},
}
TYPE_LABELS = {
    "fa": {
        "shadowing": "سایه‌خوردگی",
        "redundancy": "افزونگی",
        "correlation": "تداخل / تعارض",
        "generalization": "تعمیم",
    },
    "en": {
        "shadowing": "Shadowing",
        "redundancy": "Redundancy",
        "correlation": "Correlation",
        "generalization": "Generalization",
    },
}
RECOMMENDATIONS = {
    "fa": {
        "shadowing": "قانون ثانویه هرگز اجرا نمی‌شود؛ ترتیب دو قانون را بازبینی کنید یا قانون غیرقابل‌دسترسی را حذف کنید.",
        "redundancy": "قانون افزونه تصمیمی را تغییر نمی‌دهد؛ پس از تأیید مسئول شبکه، حذف یا ادغام آن را بررسی کنید.",
        "correlation": "دو قانون روی بخشی از ترافیک نتیجهٔ متضاد دارند؛ ترتیب و هدف امنیتی آن‌ها باید دستی تأیید شود.",
        "generalization": "ممکن است این ترتیب عمدی باشد؛ آن را مستند کنید تا در تغییرات بعدی جابه‌جا نشود.",
    },
    "en": {
        "shadowing": "The secondary rule never executes; review the order of the two rules or remove the unreachable one.",
        "redundancy": "The redundant rule never changes the decision; after confirming with the network owner, consider removing or merging it.",
        "correlation": "The two rules disagree on part of their shared traffic; their order and security intent should be verified manually.",
        "generalization": "This ordering may be intentional; document it so it isn't accidentally reordered in future changes.",
    },
}

# Static template strings (index/report/check_new pages). Kept here
# rather than duplicated as separate .html files per language, so a
# copy-edit only ever needs to happen in one place per string, and the
# fa/en versions can't silently drift out of structural sync with each
# other (same keys always exist in both, checked by _t() below).
UI_TEXT = {
    "fa": {
        "dir": "rtl",
        "html_lang": "fa",
        "app_title": "FirewallLogic — تحلیل‌گر قوانین فایروال",
        "lang_switch_label": "زبان گزارش",
        "lang_name_fa": "فارسی",
        "lang_name_en": "English",
        "nav_full_check": "بررسی کامل",
        "nav_incremental": "بررسی افزایشی",
        "upload_label": "فایل پیکربندی فایروال",
        "upload_hint": "iptables-save یا nftables — حداکثر ۵ مگابایت",
        "strict_label": "حالت سخت‌گیرانه (توقف در صورت وجود خط غیرقابل‌تجزیه)",
        "submit_analyze": "تحلیل کن",
        "error_no_file": "یک فایل پیکربندی انتخاب کنید.",
        "error_bad_encoding": "فایل باید با UTF-8 ذخیره شده باشد تا تحلیل بدون ابهام انجام شود.",
        "error_no_rules": "هیچ قانون پشتیبانی‌شده‌ای در فایل پیدا نشد.",
        "error_file_too_large": "حجم فایل باید حداکثر ۵ مگابایت باشد.",
        "error_engine_prefix": "خطای موتور تحلیل: ",
        "error_both_files_required": "هر دو فایل (پیکربندی فعلی و قوانین پیشنهادی) الزامی هستند.",
        "error_bad_encoding_both": "هر دو فایل باید با UTF-8 ذخیره شده باشند.",
        "error_no_rules_either": "هیچ قانون پشتیبانی‌شده‌ای در هیچ‌کدام از دو فایل پیدا نشد.",
        "error_no_new_rules": "هیچ قانون پشتیبانی‌شده‌ای در فایل «قوانین پیشنهادی» پیدا نشد — فقط قوانینی که می‌خواهید اضافه کنید را در آن فایل قرار دهید.",
        "base_config_label": "پیکربندی فعلی",
        "new_rules_label": "قوانین پیشنهادی",
        "submit_check_new": "بررسی کن",
        "report_title": "گزارش تحلیل",
        "source_label": "منبع",
        "rules_count_label": "تعداد قوانین",
        "findings_count_label": "تعداد یافته‌ها",
        "no_findings": "هیچ ناهنجاری‌ای یافت نشد.",
        "recommendation_label": "پیشنهاد",
        "back_link": "بازگشت",
        "page_title_index": "ممیزی قوانین فایروال · FirewallLogic",
        "masthead_h1": "گزارش قابل‌اعتماد برای قوانین فایروال",
        "masthead_lead": "فایل پیکربندی را فقط در همین رایانه تحلیل کنید — هیچ فایلی ذخیره یا به جای دیگری ارسال نمی‌شود.",
        "upload_title": "تحلیل یک فایل پیکربندی",
        "upload_field_label": "فایل iptables-save یا nftables",
        "strict_checkbox_label": "حالت دقیق: در صورت وجود قانون پشتیبانی‌نشده، گزارش نهایی صادر نشود.",
        "submit_start": "شروع تحلیل",
        "form_note": "محدودیت حجم فایل: ۵ مگابایت · فرمت فایل باید UTF-8 باشد",
        "submitting_label": "در حال تحلیل...",
        "scope_title": "دامنهٔ فعلی تحلیل",
        "scope_body": "قوانین Allow/Deny را بر اساس IP، پورت، پروتکل و chain بررسی می‌کند و چهار آنومالی اصلی — سایه‌خوردگی، افزونگی، تداخل و تعمیم — را تشخیص می‌دهد.",
        "check_new_title": "افزودن قوانین جدید به یک پیکربندی موجود؟",
        "check_new_body_pre": "اگر فقط می‌خواهید بدانید چند قانون جدید با پیکربندی فعلی یا با یکدیگر تداخل دارند — بدون بازبینی مجدد قوانین قبلی — از ",
        "check_new_body_link": "حالت بررسی قوانین جدید",
        "check_new_body_post": " استفاده کنید.",
        "page_title_report": "نتیجهٔ ممیزی فایروال · FirewallLogic",
        "back_to_new_analysis": "بازگشت به تحلیل جدید",
        "report_eyebrow": "گزارش ممیزی",
        "report_h1": "نتیجهٔ تحلیل سیاست فایروال",
        "strict_blocked_title": "تحلیل در حالت دقیق متوقف شد",
        "strict_blocked_body": "برخی قوانین مدل نشده‌اند؛ برای جلوگیری از گزارش ناقص، هیچ نتیجه‌ای صادر نشد.",
        "incomplete_title": "تحلیل ناقص است",
        "incomplete_body": "یافته‌ها فقط برای قوانین پشتیبانی‌شده معتبرند. قبل از هر تصمیم عملیاتی، خطوط ردشده را بررسی کنید.",
        "complete_message": "تحلیل کامل شد.",
        "complete_body": "همهٔ خطوط قابل‌تحلیل بودند.",
        "metrics_label": "خلاصهٔ گزارش",
        "metric_analyzed_rules": "قوانین تحلیل‌شده",
        "metric_unsupported_lines": "خطوط پشتیبانی‌نشده",
        "metric_findings": "یافته‌ها",
        "metric_analysis_time": "زمان تحلیل",
        "severity_grid_label": "یافته‌ها بر اساس شدت",
        "unsupported_lines_title": "خطوط پشتیبانی‌نشده",
        "line_word": "خط",
        "findings_title": "یافته‌های نیازمند بازبینی",
        "rule_and_rule": "قانون {a} و قانون {b}",
        "empty_state_title": "هیچ آنومالی‌ای کشف نشد",
        "empty_state_body": "قوانین تحلیل‌شده در این مدل با یکدیگر تعارضی ندارند.",
        "page_title_check_new": "بررسی قوانین جدید فایروال · FirewallLogic",
        "back_to_full_analysis": "بازگشت به تحلیل کامل",
        "incremental_eyebrow": "بررسی افزایشی",
        "check_new_h1": "آیا قوانین جدید پیشنهادی مشکلی ایجاد می‌کنند؟",
        "check_new_lead": "پیکربندی فعلی (که قبلاً بررسی و تأیید شده) را همراه با فایلی که فقط شامل قوانین جدید پیشنهادی است بارگذاری کنید. فقط یافته‌هایی که به قوانین جدید مربوط‌اند نمایش داده می‌شود.",
        "check_new_upload_title": "بررسی قوانین جدید",
        "base_config_field_label": "۱. پیکربندی فعلی (قوانین موجود و تأییدشده)",
        "new_rules_field_label": "۲. فقط قوانین جدید پیشنهادی (همان فرمت: iptables-save یا nftables)",
        "submit_check_new_button": "بررسی قوانین جدید",
        "check_new_form_note": "محدودیت حجم هر فایل: ۵ مگابایت · فرمت هر دو فایل باید UTF-8 باشد",
        "check_new_form_note2": "شمارهٔ قوانین در فایل دوم نادیده گرفته می‌شود و به‌صورت خودکار پس از آخرین قانون فایل اول شماره‌گذاری می‌شوند.",
        "check_new_scope_title": "این حالت چه تفاوتی با تحلیل کامل دارد؟",
        "check_new_scope_body": "تحلیل کامل همهٔ جفت‌قوانین را از نو بررسی می‌کند. این حالت فرض می‌کند پیکربندی فعلی قبلاً بررسی و پذیرفته شده است، و فقط نشان می‌دهد قوانین جدید با قوانین موجود یا با یکدیگر چه تداخلی دارند — مناسب برای بررسی سریع قبل از اعمال یک تغییر کوچک روی یک پیکربندی بزرگ.",
        "checking_label": "در حال بررسی...",
        "page_title_check_new_report": "نتیجهٔ بررسی قوانین جدید · FirewallLogic",
        "check_new_report_h1": "نتیجهٔ بررسی قوانین جدید",
        "metric_base_rules": "قوانین پیکربندی فعلی",
        "metric_new_rules": "قوانین جدید بررسی‌شده",
        "new_rule_ids_label": "شمارهٔ قوانین جدید",
        "base_errors_title": "خطوط پشتیبانی‌نشده در پیکربندی فعلی",
        "new_errors_title": "خطوط پشتیبانی‌نشده در قوانین جدید",
        "no_new_findings_title": "قوانین جدید مشکلی ایجاد نکردند",
        "no_new_findings_body": "قوانین جدید پیشنهادی با پیکربندی فعلی یا با یکدیگر تداخلی ندارند.",
        "check_another_link": "بررسی قوانین جدید دیگر",
        "new_rules_summary": "{base} قانون موجود · {new} قانون جدید پیشنهادی (شماره‌های {first} تا {last})",
        "incomplete_check_title": "بررسی ناقص است",
        "incomplete_check_body": "برخی خطوط در یکی از دو فایل پشتیبانی نشدند. یافته‌ها فقط برای قوانین پشتیبانی‌شده معتبرند.",
        "check_complete_message": "بررسی کامل شد.",
        "check_complete_body": "همهٔ خطوط هر دو فایل قابل‌تحلیل بودند.",
        "check_metrics_label": "خلاصهٔ بررسی",
        "metric_existing_rules": "قوانین موجود",
        "metric_new_rules_short": "قوانین جدید",
        "metric_new_findings": "یافته‌های مرتبط با قوانین جدید",
        "new_findings_note": "فقط یافته‌هایی نشان داده شده‌اند که دست‌کم یکی از دو طرفشان یکی از قوانین جدید (شماره‌های {first} تا {last}) باشد.",
    },
    "en": {
        "back_link": "Back",
        "page_title_index": "Firewall Rule Audit · FirewallLogic",
        "masthead_h1": "A trustworthy report for your firewall rules",
        "masthead_lead": "The configuration file is analyzed only on this machine — nothing is stored or sent anywhere else.",
        "upload_title": "Analyze a configuration file",
        "upload_field_label": "iptables-save or nftables file",
        "strict_checkbox_label": "Strict mode: don't produce a final report if any rule is unsupported.",
        "submit_start": "Start analysis",
        "form_note": "File size limit: 5 MB · file must be UTF-8",
        "submitting_label": "Analyzing...",
        "scope_title": "Current analysis scope",
        "scope_body": "Checks Allow/Deny rules by IP, port, protocol, and chain, and detects four core anomalies — shadowing, redundancy, correlation, and generalization.",
        "check_new_title": "Adding new rules to an existing configuration?",
        "check_new_body_pre": "If you just want to know whether some new rules conflict with the current configuration or with each other — without re-reviewing the existing rules — use ",
        "check_new_body_link": "incremental rule check mode",
        "check_new_body_post": ".",
        "dir": "ltr",
        "html_lang": "en",
        "app_title": "FirewallLogic — Firewall Rule Analyzer",
        "lang_switch_label": "Report language",
        "lang_name_fa": "فارسی",
        "lang_name_en": "English",
        "nav_full_check": "Full check",
        "nav_incremental": "Incremental check",
        "upload_label": "Firewall configuration file",
        "upload_hint": "iptables-save or nftables — 5 MB max",
        "strict_label": "Strict mode (stop if any line can't be parsed)",
        "submit_analyze": "Analyze",
        "error_no_file": "Please select a configuration file.",
        "error_bad_encoding": "The file must be saved as UTF-8 for unambiguous analysis.",
        "error_no_rules": "No supported rules were found in the file.",
        "error_file_too_large": "The file must be 5 MB or smaller.",
        "error_engine_prefix": "Analysis engine error: ",
        "error_both_files_required": "Both files (current configuration and proposed rules) are required.",
        "error_bad_encoding_both": "Both files must be saved as UTF-8.",
        "error_no_rules_either": "No supported rules were found in either file.",
        "error_no_new_rules": "No supported rules were found in the \"proposed rules\" file — only put the rules you want to add in that file.",
        "base_config_label": "Current configuration",
        "new_rules_label": "Proposed rules",
        "submit_check_new": "Check",
        "report_title": "Analysis report",
        "source_label": "Source",
        "rules_count_label": "Rule count",
        "findings_count_label": "Findings",
        "no_findings": "No anomalies found.",
        "recommendation_label": "Recommendation",
        "page_title_report": "Firewall Audit Result · FirewallLogic",
        "back_to_new_analysis": "Back to a new analysis",
        "report_eyebrow": "Audit report",
        "report_h1": "Firewall policy analysis result",
        "strict_blocked_title": "Analysis stopped in strict mode",
        "strict_blocked_body": "Some rules could not be modeled; to avoid an incomplete report, no results were produced.",
        "incomplete_title": "Analysis is incomplete",
        "incomplete_body": "Findings are only valid for the supported rules. Review the skipped lines before making any operational decision.",
        "complete_message": "Analysis complete.",
        "complete_body": "Every line could be analyzed.",
        "metrics_label": "Report summary",
        "metric_analyzed_rules": "Rules analyzed",
        "metric_unsupported_lines": "Unsupported lines",
        "metric_findings": "Findings",
        "metric_analysis_time": "Analysis time",
        "severity_grid_label": "Findings by severity",
        "unsupported_lines_title": "Unsupported lines",
        "line_word": "Line",
        "findings_title": "Findings that need review",
        "rule_and_rule": "Rule {a} and rule {b}",
        "empty_state_title": "No anomalies found",
        "empty_state_body": "The analyzed rules in this model do not conflict with each other.",
        "page_title_check_new": "Check New Firewall Rules · FirewallLogic",
        "back_to_full_analysis": "Back to full analysis",
        "incremental_eyebrow": "Incremental check",
        "check_new_h1": "Do the proposed new rules cause a problem?",
        "check_new_lead": "Upload the current configuration (already reviewed and approved) together with a file containing only the proposed new rules. Only findings involving the new rules are shown.",
        "check_new_upload_title": "Check new rules",
        "base_config_field_label": "1. Current configuration (existing, approved rules)",
        "new_rules_field_label": "2. Only the proposed new rules (same format: iptables-save or nftables)",
        "submit_check_new_button": "Check new rules",
        "check_new_form_note": "File size limit per file: 5 MB · both files must be UTF-8",
        "check_new_form_note2": "Rule numbers in the second file are ignored and automatically renumbered after the last rule of the first file.",
        "check_new_scope_title": "How is this different from a full analysis?",
        "check_new_scope_body": "A full analysis re-checks every pair of rules from scratch. This mode assumes the current configuration has already been reviewed and accepted, and only shows how the new rules conflict with existing rules or with each other — useful for a quick check before applying a small change to a large configuration.",
        "checking_label": "Checking...",
        "page_title_check_new_report": "New Rules Check Result · FirewallLogic",
        "check_new_report_h1": "New rules check result",
        "metric_base_rules": "Current configuration rules",
        "metric_new_rules": "New rules checked",
        "new_rule_ids_label": "New rule numbers",
        "base_errors_title": "Unsupported lines in the current configuration",
        "new_errors_title": "Unsupported lines in the new rules",
        "no_new_findings_title": "The new rules caused no problems",
        "no_new_findings_body": "The proposed new rules do not conflict with the current configuration or with each other.",
        "check_another_link": "Check other new rules",
        "new_rules_summary": "{base} existing rule(s) · {new} proposed new rule(s) (numbers {first} to {last})",
        "incomplete_check_title": "Check is incomplete",
        "incomplete_check_body": "Some lines in one of the two files were unsupported. Findings are only valid for the supported rules.",
        "check_complete_message": "Check complete.",
        "check_complete_body": "Every line in both files could be analyzed.",
        "check_metrics_label": "Check summary",
        "metric_existing_rules": "Existing rules",
        "metric_new_rules_short": "New rules",
        "metric_new_findings": "Findings involving new rules",
        "new_findings_note": "Only findings where at least one side is one of the new rules (numbers {first} to {last}) are shown.",
    },
}


def _resolve_lang() -> str:
    """
    Determines the language for this request, in priority order:
      1. ?lang=xx query param or lang form field (explicit switch,
         e.g. the language selector submitting a GET/POST) -- also
         persisted to a cookie so it "sticks" for later requests.
      2. firewalllogic_lang cookie (from a previous switch).
      3. DEFAULT_LANG ("en"), i.e. what a fresh visitor with no cookie
         and no ?lang= sees on their first request.
    Only "fa"/"en" are ever accepted; anything else silently falls
    back to the default rather than erroring, since a language switch
    should never be able to break analysis.
    """
    requested = request.values.get("lang")
    if requested in SUPPORTED_LANGS:
        return requested
    cookie_lang = request.cookies.get("firewalllogic_lang")
    if cookie_lang in SUPPORTED_LANGS:
        return cookie_lang
    return DEFAULT_LANG


def _t(lang: str) -> dict[str, str]:
    """Static UI text dict for lang, always falling back to fa."""
    return UI_TEXT.get(lang, UI_TEXT[DEFAULT_LANG])


def _finding_view(finding: Finding, lang: str) -> dict[str, str | int]:
    return {
        "type": TYPE_LABELS[lang][finding.type],
        "severity": SEVERITY_LABELS[lang][finding.severity],
        "severity_key": finding.severity,
        "primary_rule": finding.primary_id,
        "secondary_rule": finding.secondary_id,
        "explanation": finding.explanation,
        "recommendation": RECOMMENDATIONS[lang][finding.type],
    }


def _format_duration(seconds: float, lang: str) -> str:
    """
    Human-friendly rendering of an analysis duration.
    - Under 1 second: shown in milliseconds (no decimals) since fractional
      seconds like "0.03s" are harder to read at a glance than "34 ms",
      and most configs in this project's own benchmarks (see README/
      run_tests.py) finish well under a second.
    - 1 second and above: shown in seconds with 2 decimals, e.g. "1.42s" /
      "۱٫۴۲ ثانیه" -- matches the unit used in the project's own sweep-line
      benchmark writeup (13.8s / 0.45s), so this is consistent with numbers
      already documented elsewhere in the project.
    """
    ms = seconds * 1000
    if ms < 1000:
        value = f"{ms:.0f}"
        return f"{value} میلی‌ثانیه" if lang == "fa" else f"{value} ms"
    value = f"{seconds:.2f}"
    return f"{value} ثانیه" if lang == "fa" else f"{value}s"


def _report_context(
    source_name: str,
    rules_count: int,
    errors: list[ParseError],
    findings: list[Finding],
    strict: bool,
    lang: str,
    strict_blocked: bool = False,
    analysis_duration_seconds: float | None = None,
) -> dict:
    counts = Counter(finding.severity for finding in findings)
    context = {
        "source_name": source_name,
        "rules_count": rules_count,
        "errors": errors,
        "findings": [_finding_view(finding, lang) for finding in findings],
        "findings_count": len(findings),
        "severity_cards": [
            {"key": key, "label": SEVERITY_LABELS[lang][key], "count": counts[key]}
            for key in SEVERITY_ORDER
        ],
        "analysis_complete": not errors,
        "strict": strict,
        "strict_blocked": strict_blocked,
        "analysis_duration": (
            _format_duration(analysis_duration_seconds, lang)
            if analysis_duration_seconds is not None
            else None
        ),
    }
    context.update(_t(lang))
    context["lang"] = lang
    return context


@app.after_request
def _persist_lang_cookie(response):
    # Only re-set the cookie when the request actually specified a
    # language explicitly (query/form field) -- so a plain page reload
    # with no ?lang= doesn't re-issue the cookie on every request, only
    # when the user actually flips the switch.
    requested = request.values.get("lang")
    if requested in SUPPORTED_LANGS:
        response.set_cookie(
            "firewalllogic_lang", requested, max_age=60 * 60 * 24 * 365, samesite="Lax"
        )
    return response


@app.get("/")
def index():
    lang = _resolve_lang()
    return render_template("index.html", lang=lang, **_t(lang))


@app.post("/analyze")
def analyze():
    lang = _resolve_lang()
    uploaded = request.files.get("config")
    strict = request.form.get("strict") == "on"
    if uploaded is None or not uploaded.filename:
        return render_template(
            "index.html", lang=lang, error=_t(lang)["error_no_file"], **_t(lang)
        ), 400

    try:
        config_text = uploaded.read().decode("utf-8-sig")
    except UnicodeDecodeError:
        return render_template(
            "index.html",
            lang=lang,
            error=_t(lang)["error_bad_encoding"],
            **_t(lang),
        ), 400

    # Timing window covers parsing + engine reasoning only -- the actual
    # "analysis" work -- not template rendering, which is presentation
    # rather than analysis and would make the number less meaningful for
    # judging how long the engine itself took (e.g. across large configs).
    # time.perf_counter() (monotonic, sub-microsecond resolution) is used
    # instead of time.time() (wall clock) since it can't be affected by
    # system clock adjustments during the request.
    analysis_started_at = time.perf_counter()

    rules, parse_errors = parse(config_text)
    if not rules:
        return render_template(
            "index.html",
            lang=lang,
            error=_t(lang)["error_no_rules"],
            **_t(lang),
        ), 422

    if strict and parse_errors:
        analysis_duration_seconds = time.perf_counter() - analysis_started_at
        audit_log.log_run(
            mode="full",
            source_name=uploaded.filename,
            rules_count=len(rules),
            findings=[],
            parse_errors_count=len(parse_errors),
            analysis_complete=False,
            engine_backend="n/a (strict-blocked before engine ran)",
        )
        context = _report_context(
            uploaded.filename,
            len(rules),
            parse_errors,
            [],
            strict,
            lang,
            strict_blocked=True,
            analysis_duration_seconds=analysis_duration_seconds,
        )
        return render_template("report.html", **context), 422

    findings, engine_error = run_engine(rules, lang=lang)
    if engine_error:
        return render_template(
            "index.html",
            lang=lang,
            error=f"{_t(lang)['error_engine_prefix']}{engine_error}",
            **_t(lang),
        ), 500

    analysis_duration_seconds = time.perf_counter() - analysis_started_at

    audit_log.log_run(
        mode="full",
        source_name=uploaded.filename,
        rules_count=len(rules),
        findings=findings,
        parse_errors_count=len(parse_errors),
        analysis_complete=not parse_errors,
        engine_backend=backend_name(),
    )

    context = _report_context(
        uploaded.filename,
        len(rules),
        parse_errors,
        findings,
        strict,
        lang,
        analysis_duration_seconds=analysis_duration_seconds,
    )
    return render_template("report.html", **context)


@app.errorhandler(413)
def too_large(_error):
    lang = _resolve_lang()
    return render_template(
        "index.html", lang=lang, error=_t(lang)["error_file_too_large"], **_t(lang)
    ), 413


def _read_upload(field_name: str, lang: str) -> tuple[str | None, str | None, str | None]:
    """Reads one uploaded file field as UTF-8 text.
    Returns (text, filename, error_message) — error_message is None on success.
    """
    uploaded = request.files.get(field_name)
    if uploaded is None or not uploaded.filename:
        return None, None, _t(lang)["error_both_files_required"]
    try:
        return uploaded.read().decode("utf-8-sig"), uploaded.filename, None
    except UnicodeDecodeError:
        return None, None, _t(lang)["error_bad_encoding_both"]


@app.get("/check-new")
def check_new_form():
    lang = _resolve_lang()
    return render_template("check_new.html", lang=lang, **_t(lang))


@app.post("/check-new")
def check_new():
    lang = _resolve_lang()
    base_text, base_uploaded_name, err = _read_upload("base_config", lang)
    if err:
        return render_template("check_new.html", lang=lang, error=err, **_t(lang)), 400

    new_text, new_uploaded_name, err = _read_upload("new_rules", lang)
    if err:
        return render_template("check_new.html", lang=lang, error=err, **_t(lang)), 400

    analysis_started_at = time.perf_counter()
    result = check_new_rules(base_text, new_text, lang=lang)
    analysis_duration_seconds = time.perf_counter() - analysis_started_at

    if not result.new_rules and not result.base_rules_count:
        return render_template(
            "check_new.html",
            lang=lang,
            error=_t(lang)["error_no_rules_either"],
            **_t(lang),
        ), 422

    if not result.new_rules:
        return render_template(
            "check_new.html",
            lang=lang,
            error=_t(lang)["error_no_new_rules"],
            **_t(lang),
        ), 422

    if result.engine_error:
        return render_template(
            "check_new.html",
            lang=lang,
            error=f"{_t(lang)['error_engine_prefix']}{result.engine_error}",
            **_t(lang),
        ), 500

    audit_log.log_run(
        mode="incremental",
        source_name=f"base={base_uploaded_name} + new={new_uploaded_name}",
        rules_count=result.base_rules_count + len(result.new_rules),
        findings=result.findings,
        parse_errors_count=len(result.base_errors) + len(result.new_errors),
        analysis_complete=not result.base_errors and not result.new_errors,
        engine_backend=backend_name(),
        new_rules_count=len(result.new_rules),
    )

    counts = Counter(f.severity for f in result.findings)
    context = {
        "base_rules_count": result.base_rules_count,
        "new_rules_count": len(result.new_rules),
        "new_rule_ids": [r.id for r in result.new_rules],
        "base_errors": result.base_errors,
        "new_errors": result.new_errors,
        "findings": [_finding_view(f, lang) for f in result.findings],
        "findings_count": len(result.findings),
        "severity_cards": [
            {"key": key, "label": SEVERITY_LABELS[lang][key], "count": counts[key]}
            for key in SEVERITY_ORDER
        ],
        "analysis_complete": not result.base_errors and not result.new_errors,
        "analysis_duration": _format_duration(analysis_duration_seconds, lang),
        "lang": lang,
    }
    context.update(_t(lang))
    return render_template("check_new_report.html", **context)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
