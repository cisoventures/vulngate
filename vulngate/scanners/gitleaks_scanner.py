"""Gitleaks adapter — secret scanning.

Secret VALUES and matched text are never copied into our output. We read only
the rule, location, and gitleaks' own fingerprint.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ..knowledge import plain_summary
from ..schema import Finding, fingerprint
from .base import (ScanOutput, completed, errored, rel_posix, resolve_cmd,
                   run_cmd, skipped)

NAME = "gitleaks"


def _version(cmd: list[str]) -> str | None:
    proc = run_cmd([*cmd, "version"], timeout=30)
    return proc.stdout.strip() if proc and proc.stdout else None


def run(root: Path, det, opts: dict | None = None) -> ScanOutput:
    cmd = resolve_cmd([NAME])
    if not cmd:
        return skipped(NAME, "gitleaks is not installed (see https://github.com/gitleaks/gitleaks)")

    version = _version(cmd)
    # gitleaks 8.19+ uses the `dir` subcommand to scan files (the old
    # `detect --no-git --source` form was removed). --redact keeps secret
    # values out of gitleaks' own logs; we drop them from findings regardless.
    with tempfile.TemporaryDirectory() as td:
        report_path = Path(td) / "gitleaks.json"
        proc = run_cmd(
            [*cmd, "dir", str(root), "--report-format", "json",
             "--report-path", str(report_path), "--redact", "--no-banner",
             "--exit-code", "0"],
            cwd=root, timeout=300,
        )
        if proc is None:
            return errored(NAME, version, "gitleaks timed out or failed to launch")
        try:
            data = json.loads(report_path.read_text() or "[]")
        except (json.JSONDecodeError, OSError):
            return errored(NAME, version, "could not parse gitleaks report")

    findings: list[Finding] = []
    for leak in data or []:
        rule = leak.get("RuleID", "generic-secret")
        rel = rel_posix(leak.get("File", ""), root)
        line = leak.get("StartLine")
        native = leak.get("Fingerprint") or f"{rule}:{rel}:{line}"
        fid, dedupe = fingerprint(NAME, rule, rel, native)
        desc = leak.get("Description") or f"Potential hard-coded secret ({rule})."
        findings.append(Finding(
            id=fid, scanner=NAME, rule=rule, severity="high",
            file=rel, line=line,
            plain_summary=plain_summary(scanner=NAME, rule=rule, cwes=["CWE-798"], description=desc),
            description=desc,
            remediation_hint="Remove the secret from source, rotate it immediately, and load it from an environment variable or secrets manager.",
            dedupe_hash=dedupe,
            details={  # deliberately NO 'Secret' / 'Match' fields
                "end_line": leak.get("EndLine"),
                "column": leak.get("StartColumn"),
                "cwe": ["CWE-798"],
                "entropy": leak.get("Entropy"),
            },
        ))
    return completed(NAME, version, findings)
