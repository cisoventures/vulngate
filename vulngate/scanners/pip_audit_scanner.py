"""pip-audit adapter — Python dependency vulnerabilities (SCA)."""

from __future__ import annotations

import json
from pathlib import Path

from ..schema import Finding, fingerprint
from .base import (ScanOutput, completed, errored, rel_posix, resolve_cmd,
                   run_cmd, skipped)

NAME = "pip-audit"


def _version(cmd: list[str]) -> str | None:
    proc = run_cmd([*cmd, "--version"], timeout=30)
    return proc.stdout.strip() if proc and proc.stdout else None


def _iter_deps(data):
    """pip-audit JSON has been either a bare list or {'dependencies': [...]}."""
    if isinstance(data, dict):
        return data.get("dependencies", [])
    return data or []


def run(root: Path, det, opts: dict | None = None) -> ScanOutput:
    opts = opts or {}
    # pip-audit's JSON carries no CVSS, so severity is a caller-set default.
    severity = opts.get("dependency_severity", "medium")
    no_deps = opts.get("no_deps", False)
    if not det.py_requirements:
        return skipped(NAME, "no requirements*.txt found to audit")
    cmd = resolve_cmd([NAME], module="pip_audit")
    if not cmd:
        return skipped(NAME, "pip-audit is not installed (pip install pip-audit)")

    version = _version(cmd)
    findings: list[Finding] = []
    for req in det.py_requirements:
        rel_req = rel_posix(req, root)
        argv = [*cmd, "-r", str(req), "-f", "json", "--progress-spinner", "off"]
        if no_deps:
            argv.append("--no-deps")
        proc = run_cmd(argv, cwd=root, timeout=300)
        if proc is None:
            return errored(NAME, version, f"pip-audit failed on {rel_req}")
        try:
            data = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError:
            tail = (proc.stderr or "").strip()[-300:]
            return errored(NAME, version, f"could not parse pip-audit output: {tail}")

        for dep in _iter_deps(data):
            name = dep.get("name", "?")
            installed = dep.get("version", "?")
            for vuln in dep.get("vulns", []) or []:
                vid = vuln.get("id", "UNKNOWN")
                fixes = vuln.get("fix_versions", []) or []
                aliases = vuln.get("aliases", []) or []
                fid, dedupe = fingerprint(NAME, vid, rel_req, f"{name}:{vid}")
                desc = (vuln.get("description") or f"{name} {installed} has a known vulnerability ({vid}).").strip()
                remediation = (
                    f"Upgrade {name} from {installed} to {fixes[0]}." if fixes
                    else f"No fixed version is published yet for {name}; review the advisory ({vid})."
                )
                # Dependency vulns are the PACKAGE's flaw, not the user's code —
                # so the summary is package-framed, never the code-pattern CWE text.
                summary = (
                    f"The '{name}' package your project depends on has a known security "
                    f"flaw. Updating it to a fixed version closes the hole."
                )
                findings.append(Finding(
                    id=fid, scanner=NAME, rule=vid, severity=severity,
                    file=rel_req, line=None,
                    plain_summary=summary,
                    description=desc[:500], remediation_hint=remediation, dedupe_hash=dedupe,
                    details={
                        "package": name, "installed_version": installed,
                        "fixed_versions": fixes, "aliases": aliases,
                    },
                ))
    return completed(NAME, version, findings)
