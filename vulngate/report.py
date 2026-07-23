"""Output renderers: pretty terminal summary + SARIF export.

findings.json itself is just the schema envelope written verbatim (json.dump),
so there's no separate writer for it — the CLI dumps build_report()'s dict.
"""

from __future__ import annotations

import os
import sys
from typing import Any

from .schema import SEVERITIES

# ── color handling ───────────────────────────────────────────────────────────
_C = {
    "critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m",
    "low": "\033[96m", "dim": "\033[2m", "bold": "\033[1m",
    "green": "\033[92m", "reset": "\033[0m",
}


def _use_color(flag: bool) -> bool:
    if not flag or os.environ.get("NO_COLOR"):   # NO_COLOR wins (de-facto standard)
        return False
    if os.environ.get("FORCE_COLOR"):            # opt back in for CI logs / pipes
        return True
    return sys.stdout.isatty()


def _paint(text: str, key: str, on: bool) -> str:
    return f"{_C[key]}{text}{_C['reset']}" if on else text


def _short_rule(rule: str) -> str:
    """Terminal-friendly rule label. findings.json keeps the full id."""
    if "." not in rule:
        return rule                       # GHSA-..., PYSEC-..., npm:pkg
    parts = rule.split(".")
    if len(parts) >= 2 and parts[-1] == parts[-2]:
        parts = parts[:-1]                # semgrep often duplicates the leaf
    return parts[-1]


# ── terminal report ──────────────────────────────────────────────────────────
def terminal_report(report: dict[str, Any], color: bool = True) -> str:
    on = _use_color(color)
    scan, summary = report["scan"], report["summary"]
    lines: list[str] = []

    title = f"vulngate {scan['tool_version']}  —  scan of {scan['target']}"
    lines.append(_paint(title, "bold", on))
    lines.append("─" * min(len(title), 72))

    # Scanner status line — a glyph per outcome so a "0" is never ambiguous:
    #   ✓N completed · ✗ error · ∅ not installed · – n/a · ⊘ disabled
    chips = []
    for s in scan["scanners"]:
        st = s["status"]
        if st == "completed":
            chips.append(f"{s['name']} {_paint('✓', 'green', on)}{s['finding_count']}")
        elif st == "error":
            chips.append(_paint(f"{s['name']} ✗", "high", on))
        elif st == "unavailable":
            chips.append(_paint(f"{s['name']} ∅", "dim", on))
        elif st == "disabled":
            chips.append(_paint(f"{s['name']} ⊘", "dim", on))
        else:  # not_applicable (or any future non-run state)
            chips.append(_paint(f"{s['name']} –", "dim", on))
    lines.append("scanners: " + "   ".join(chips))
    lines.append("")

    findings = report["findings"]
    _DEP = ("pip-audit", "npm-audit")

    def _tag(sev: str) -> str:
        return _paint(f" {sev.upper():<8}", sev, on)

    def _most_severe(fs: list) -> str:
        return min((x["severity"] for x in fs), key=lambda s: SEVERITIES.index(s))

    items: list[tuple[str, list[str]]] = []  # (severity, rendered lines)

    # Code findings (SAST/secrets) render one block each.
    for f in findings:
        if f["scanner"] in _DEP:
            continue
        loc = f["file"] + (f":{f['line']}" if f.get("line") else "")
        items.append((f["severity"], [
            f"{_tag(f['severity'])} {loc}  {_paint('[' + f['scanner'] + ']', 'dim', on)} {_short_rule(f['rule'])}",
            f"          {f['plain_summary']}",
            _paint(f"          fix: {f['remediation_hint']}", "dim", on),
        ]))

    # Dependency findings collapse per package — one line for N advisories,
    # so a noisy transitive tree doesn't bury the code-level issues. (The full
    # per-advisory list still lives in findings.json.)
    groups: dict[tuple, list] = {}
    for f in findings:
        if f["scanner"] in _DEP:
            groups.setdefault((f["scanner"], f["file"], (f["details"] or {}).get("package", "?")), []).append(f)
    for (scanner, file, pkg), fs in groups.items():
        sev, n = _most_severe(fs), len(fs)
        ids = ", ".join(x["rule"] for x in fs[:4]) + (f"  (+{n - 4} more)" if n > 4 else "")
        items.append((sev, [
            f"{_tag(sev)} {file}  {_paint('[' + scanner + ']', 'dim', on)} {pkg} — {n} known advisor{'y' if n == 1 else 'ies'}",
            f"          {fs[0]['plain_summary']}",
            _paint(f"          fix: update {pkg} to a patched version  ·  {ids}", "dim", on),
        ]))

    if not items:
        lines.append(_paint("No findings. ✓", "green", on))
    else:
        items.sort(key=lambda it: SEVERITIES.index(it[0]))
        for _sev, block in items:
            lines.extend(block)
            lines.append("")

    # Diagnostics (run conditions, not vulnerabilities).
    for d in report.get("diagnostics", []):
        lines.append(_paint(f"note: {d['message']}", "dim", on))
    if report.get("diagnostics"):
        lines.append("")

    counts = "  ·  ".join(
        _paint(f"{summary[s]} {s}", s, on) for s in SEVERITIES if summary[s]
    ) or "0 findings"
    lines.append(f"summary: {counts}   ({summary['total']} total)")

    ec = scan["exit_code"]
    if scan.get("status") == "no_coverage":
        verdict = _paint("NO COVERAGE", "medium", on) + " — no scanner ran; this is NOT a clean result"
    elif ec == 0:
        verdict = _paint("PASS", "green", on) + f" — nothing at or above '{scan['fail_on']}'"
    elif ec == 1:
        n = sum(summary[s] for s in SEVERITIES
                if SEVERITIES.index(s) <= SEVERITIES.index(scan["fail_on"]))
        verdict = _paint("FAIL", "high", on) + f" — {n} finding(s) at or above '{scan['fail_on']}'"
    else:
        verdict = _paint("ERROR", "high", on) + " — a scanner failed to run"
    lines.append(f"result:  {verdict}  (exit {ec})")
    return "\n".join(lines)


# ── SARIF export (GitHub code scanning compatible) ───────────────────────────
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_SARIF_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.0", "low": "2.0"}


def to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    rules: dict[str, dict] = {}
    results = []
    for f in report["findings"]:
        rid = f["rule"]
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "shortDescription": {"text": rid},
                "helpUri": (f.get("details") or {}).get("rule_url") or "https://github.com/cisoventures/vulngate",
                "properties": {"security-severity": _SARIF_SEVERITY.get(f["severity"], "5.0")},
            }
        physical: dict[str, Any] = {"artifactLocation": {"uri": f["file"]}}
        if f.get("line"):
            physical["region"] = {"startLine": f["line"]}
        results.append({
            "ruleId": rid,
            "level": _SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": f"{f['plain_summary']} ({f['description']})"},
            "locations": [{"physicalLocation": physical}],
            "partialFingerprints": {"vulngateDedupeHash": f["dedupe_hash"]},
            "properties": {"scanner": f["scanner"], "severity": f["severity"]},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "vulngate",
                "informationUri": "https://github.com/cisoventures/vulngate",
                "version": report["scan"]["tool_version"],
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
