"""Semgrep adapter — static analysis (SAST)."""

from __future__ import annotations

import json
from pathlib import Path

from ..knowledge import plain_summary
from ..schema import Diagnostic, Finding, fingerprint
from .base import (ScanOutput, completed, errored, normalize_cwes, rel_posix,
                   resolve_cmd, run_cmd, skipped)

NAME = "semgrep"
_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def _version(cmd: list[str]) -> str | None:
    proc = run_cmd([*cmd, "--version"], timeout=30)
    return proc.stdout.strip().splitlines()[0] if proc and proc.stdout else None


def run(root: Path, det, opts: dict | None = None) -> ScanOutput:
    if not det.languages:
        return skipped(NAME, "no source files detected to analyze")
    cmd = resolve_cmd([NAME])
    if not cmd:
        return skipped(NAME, "semgrep is not installed (pip install semgrep)")

    version = _version(cmd)
    # p/default is a broad community ruleset that works WITHOUT telemetry.
    # (`--config auto` refuses to run when --metrics=off, and we won't force
    # telemetry on users of a security tool.)
    proc = run_cmd(
        [*cmd, "scan", "--config", "p/default", "--json", "--quiet",
         "--metrics=off", "--disable-version-check", str(root)],
        cwd=root, timeout=600,
    )
    if proc is None:
        return errored(NAME, version, "semgrep timed out or failed to launch")
    if proc.returncode >= 2:  # 0 = clean, 1 = findings, >=2 = real error
        tail = (proc.stderr or "").strip()[-300:]
        return errored(NAME, version, f"semgrep failed (exit {proc.returncode}): {tail}")
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        tail = (proc.stderr or "").strip()[-300:]
        return errored(NAME, version, f"could not parse semgrep output: {tail}")

    findings: list[Finding] = []
    for r in data.get("results", []):
        rule = r.get("check_id", "semgrep.unknown")
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        severity = _SEV.get(str(extra.get("severity", "")).upper(), "medium")
        rel = rel_posix(r.get("path", ""), root)
        cwes = normalize_cwes(meta.get("cwe"))
        native = extra.get("fingerprint") or f"{rule}:{rel}"
        fid, dedupe = fingerprint(NAME, rule, rel, native)
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
            file=rel, line=(r.get("start", {}) or {}).get("line"),
            plain_summary=plain_summary(scanner=NAME, rule=rule, cwes=cwes, description=desc),
            description=desc, remediation_hint=remediation, dedupe_hash=dedupe,
            details={
                "column": (r.get("start", {}) or {}).get("col"),
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
