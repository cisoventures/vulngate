"""Semgrep adapter — static analysis (SAST)."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from ..knowledge import plain_summary
from ..schema import Diagnostic, Finding, fingerprint
from .base import (ScanOutput, completed, errored, normalize_cwes,
                   not_applicable, rel_posix, resolve_cmd, run_cmd, unavailable)

NAME = "semgrep"
_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
# Semgrep OSS (no platform login — which is exactly how vulngate runs it) stamps
# EVERY finding's extra.fingerprint with this constant placeholder. Treating it
# as a real per-match fingerprint would collapse every match of a rule in a file
# into one id, silently dropping distinct findings on other lines.
_PLACEHOLDER_FP = "requires login"


def _native_identity(rule: str, rel: str, start: dict, extra: dict) -> str:
    """Stable identity for a semgrep match, used for the dedupe id.

    Prefer semgrep's own per-match fingerprint (stable AND line-independent) when
    it's real. When it's absent or the OSS "requires login" placeholder, fall back
    to a LOCATION-keyed identity so two distinct matches of the same rule in the
    same file stay distinct instead of merging into one finding.
    """
    raw_fp = str((extra or {}).get("fingerprint") or "").strip()
    if raw_fp and raw_fp.lower() != _PLACEHOLDER_FP:
        return raw_fp
    start = start or {}
    return f"{rule}:{rel}:{start.get('line')}:{start.get('col')}"


def _has_results(data: object) -> bool:
    """A genuine semgrep report always carries a 'results' key (even when empty).
    Its absence means the scan didn't actually run — not that the code is clean."""
    return isinstance(data, dict) and "results" in data


def _version(cmd: list[str]) -> str | None:
    proc = run_cmd([*cmd, "--version"], timeout=30)
    return proc.stdout.strip().splitlines()[0] if proc and proc.stdout else None


def run(root: Path, det, opts: dict | None = None) -> ScanOutput:
    if not det.languages:
        return not_applicable(NAME, "no source files detected to analyze")
    cmd = resolve_cmd([NAME])
    if not cmd:
        return unavailable(NAME, "semgrep is not installed (pip install semgrep)")

    version = _version(cmd)
    # Give semgrep a writable state dir — in restricted sandboxes it crashes when
    # it can't write ~/.semgrep, which previously slipped through as "0 findings".
    with tempfile.TemporaryDirectory(prefix="vulngate-semgrep-") as tmp:
        sg_env = {
            "SEMGREP_SETTINGS_FILE": os.path.join(tmp, "settings.yml"),
            "XDG_CONFIG_HOME": tmp,
            "XDG_CACHE_HOME": tmp,
        }
        # p/default is a broad community ruleset that works WITHOUT telemetry.
        # (`--config auto` refuses to run when --metrics=off, and we won't force
        # telemetry on users of a security tool.)
        proc = run_cmd(
            [*cmd, "scan", "--config", "p/default", "--json", "--quiet",
             "--metrics=off", "--disable-version-check", str(root)],
            cwd=root, timeout=600, env=sg_env,
        )
    if proc is None:
        return errored(NAME, version, "semgrep timed out or failed to launch")
    if proc.returncode >= 2:  # 0 = clean, 1 = findings, >=2 = real error
        tail = (proc.stderr or "").strip()[-300:]
        return errored(NAME, version, f"semgrep failed (exit {proc.returncode}): {tail}")
    try:
        data = json.loads(proc.stdout or "")
    except json.JSONDecodeError:
        tail = (proc.stderr or "").strip()[-300:]
        return errored(NAME, version, f"semgrep produced no parseable output (exit {proc.returncode}): {tail}")
    if not _has_results(data):
        # Empty '{}' or a non-report payload means semgrep didn't actually scan
        # (e.g. a crash that still exited 1) — never treat that as "0 findings".
        tail = (proc.stderr or "").strip()[-300:]
        return errored(NAME, version, f"semgrep did not return a valid report (exit {proc.returncode}): {tail}")

    findings: list[Finding] = []
    seen_ids: set[str] = set()
    for r in data.get("results", []):
        rule = r.get("check_id", "semgrep.unknown")
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        severity = _SEV.get(str(extra.get("severity", "")).upper(), "medium")
        rel = rel_posix(r.get("path", ""), root)
        cwes = normalize_cwes(meta.get("cwe"))
        start = r.get("start", {}) or {}
        native = _native_identity(rule, rel, start, extra)
        fid, dedupe = fingerprint(NAME, rule, rel, native)
        if fid in seen_ids:
            # semgrep can emit the same match multiple times (e.g. several taint
            # paths to one sink). Collapse identical ids so finding_count is honest.
            continue
        seen_ids.add(fid)
        desc = extra.get("message") or meta.get("message") or rule
        rule_url = meta.get("shortlink") or meta.get("source")
        # semgrep's extra.fix is autofix replacement text, but emits the literal
        # string "False" when a rule has no autofix — reject stringified bools.
        fix_val = extra.get("fix")
        if isinstance(fix_val, str) and fix_val.strip().lower() not in ("", "false", "true", "none"):
            remediation = fix_val
        elif rule_url:
            remediation = f"See the rule guidance: {rule_url}"
        else:
            remediation = "Review and refactor the flagged pattern."
        findings.append(Finding(
            id=fid, scanner=NAME, rule=rule, severity=severity,
            file=rel, line=start.get("line"),
            plain_summary=plain_summary(scanner=NAME, rule=rule, cwes=cwes, description=desc),
            description=desc, remediation_hint=remediation, dedupe_hash=dedupe,
            details={
                "column": start.get("col"),
                "end_line": (r.get("end", {}) or {}).get("line"),
                "cwe": cwes,
                "owasp": normalize_cwes(meta.get("owasp")) or meta.get("owasp"),
                "rule_url": rule_url,
            },
        ))
    # semgrep can exit 1 with results=[] but errors[] populated (e.g. it couldn't
    # write its state dir, or files failed to parse). Do NOT report that as a clean
    # "completed 0" — that's the silent-coverage-failure trap.
    errors = data.get("errors") or []
    if errors and not findings:
        msg = "; ".join(str((e or {}).get("message", "error"))[:120] for e in errors[:3])
        return errored(NAME, version, f"semgrep produced no results but reported errors: {msg}")
    out = completed(NAME, version, findings)
    if errors:
        out.diagnostics.append(Diagnostic(
            scanner=NAME, level="warning", code="scanner_partial_errors",
            message=f"semgrep reported {len(errors)} error(s); some files may not have been scanned",
        ))
    return out
