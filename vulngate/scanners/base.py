"""Shared plumbing for scanner adapters: command resolution + subprocess safety.

Every scanner adapter turns its tool's native output into the same
(ScannerRun, [Finding], [Diagnostic]) triple via ScanOutput, so the CLI can
treat them uniformly and degrade gracefully when a tool is absent.
"""

from __future__ import annotations

import os
import shutil
import site
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..schema import Diagnostic, Finding, ScannerRun


@dataclass
class ScanOutput:
    run: ScannerRun
    findings: list[Finding] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)


def resolve_cmd(names: list[str], module: Optional[str] = None) -> Optional[list[str]]:
    """Locate a scanner even when pip installed its script off-PATH.

    Order: PATH -> Python user/base script dirs -> `python -m <module>`.
    Returns the argv prefix to invoke it, or None if unavailable.
    """
    for name in names:
        found = shutil.which(name)
        if found:
            return [found]
    # pip frequently drops console scripts in a user-base bin/ that isn't on PATH.
    candidate_dirs = []
    try:
        candidate_dirs.append(Path(site.getuserbase()) / "bin")
    except Exception:
        pass
    candidate_dirs.append(Path(sys.prefix) / "bin")
    for d in candidate_dirs:
        for name in names:
            p = d / name
            if p.exists() and os.access(p, os.X_OK):
                return [str(p)]
    if module:
        try:
            probe = subprocess.run(
                [sys.executable, "-m", module, "--version"],
                capture_output=True, text=True, timeout=30,
            )
            if probe.returncode == 0:
                return [sys.executable, "-m", module]
        except Exception:
            pass
    return None


def rel_posix(path: str | Path, root: Path) -> str:
    """Repo-relative POSIX path — never an absolute machine path in output."""
    try:
        return Path(os.path.relpath(str(path), str(root))).as_posix()
    except Exception:
        return Path(str(path)).as_posix()


def normalize_cwes(raw) -> list[str]:
    """Coerce a scanner's CWE field (str | list | None) into ['CWE-79', ...]."""
    import re
    if raw is None:
        return []
    items = raw if isinstance(raw, list) else [raw]
    out = []
    for it in items:
        m = re.search(r"CWE-\d+", str(it))
        if m:
            out.append(m.group(0))
    return out


def run_cmd(cmd: list[str], cwd: Optional[Path] = None, timeout: int = 300,
            env: Optional[dict] = None):
    """Run a scanner. Returns CompletedProcess, or None on launch failure/timeout.

    When the tool was resolved by absolute path (e.g. a pip user-base bin that
    isn't on PATH), put its directory on the child's PATH so tools that exec
    sibling helpers — semgrep -> pysemgrep — can find them. `env` merges extra
    variables into the child environment (e.g. a writable state dir for semgrep).
    """
    child_env: Optional[dict] = None
    exe = cmd[0]
    if os.path.isabs(exe) or env:
        child_env = dict(os.environ)
        if os.path.isabs(exe):
            child_env["PATH"] = os.path.dirname(exe) + os.pathsep + child_env.get("PATH", "")
        if env:
            child_env.update(env)
    try:
        return subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=child_env,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def not_applicable(name: str, reason: str) -> ScanOutput:
    """Nothing for this scanner to scan (no matching files/manifests).

    Not a problem — it's honest coverage accounting, so the diagnostic is info,
    not a warning. `applicable=False` keeps it out of scan.status coverage gaps.
    """
    return ScanOutput(
        run=ScannerRun(name=name, version=None, status="not_applicable",
                       finding_count=0, message=reason, applicable=False),
        diagnostics=[Diagnostic(scanner=name, level="info", code="scanner_not_applicable", message=reason)],
    )


def unavailable(name: str, reason: str) -> ScanOutput:
    """The tool applies here but isn't installed — a real coverage gap, so warn.

    `applicable=True, available=False` makes scan.status downgrade to 'partial'."""
    return ScanOutput(
        run=ScannerRun(name=name, version=None, status="unavailable",
                       finding_count=0, message=reason, applicable=True, available=False),
        diagnostics=[Diagnostic(scanner=name, level="warning", code="scanner_not_installed", message=reason)],
    )


def disabled(name: str, reason: str) -> ScanOutput:
    """Turned off in config — user's choice, so applicability is never probed."""
    return ScanOutput(
        run=ScannerRun(name=name, version=None, status="disabled",
                       finding_count=0, message=reason),
        diagnostics=[Diagnostic(scanner=name, level="info", code="scanner_disabled", message=reason)],
    )


def errored(name: str, version: Optional[str], message: str) -> ScanOutput:
    """Scanner was present + applicable but failed to run/parse — surface it, keep going."""
    return ScanOutput(
        run=ScannerRun(name=name, version=version, status="error", finding_count=0,
                       message=message, applicable=True, available=True),
        diagnostics=[Diagnostic(scanner=name, level="warning", code="scanner_error", message=message)],
    )


def completed(name: str, version: Optional[str], findings: list[Finding]) -> ScanOutput:
    return ScanOutput(
        run=ScannerRun(name=name, version=version, status="completed",
                       finding_count=len(findings), applicable=True, available=True),
        findings=findings,
    )
