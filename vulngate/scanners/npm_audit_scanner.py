"""npm audit adapter — JavaScript/npm dependency vulnerabilities (SCA).

Uses the npm already on the machine; no extra install needed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..schema import Finding, fingerprint
from .base import (ScanOutput, completed, errored, normalize_cwes,
                   not_applicable, rel_posix, resolve_cmd, run_cmd, unavailable)

NAME = "npm-audit"
_SEV = {"critical": "critical", "high": "high", "moderate": "medium", "low": "low", "info": "low"}


def _dep_summary(pkg: str) -> str:
    # A dependency vuln is the package's flaw, not the user's code — frame it that way.
    return (f"The '{pkg}' npm package your project depends on has a known security "
            f"flaw. Updating it to a fixed version closes the hole.")


def _version(cmd: list[str]) -> str | None:
    proc = run_cmd([*cmd, "--version"], timeout=30)
    return proc.stdout.strip() if proc and proc.stdout else None


def run(root: Path, det, opts: dict | None = None) -> ScanOutput:
    if not det.npm_lock_dirs:
        return not_applicable(NAME, "no package-lock.json found to audit")
    cmd = resolve_cmd(["npm"])
    if not cmd:
        return unavailable(NAME, "npm is not installed")

    version = _version(cmd)
    findings: list[Finding] = []
    for d in det.npm_lock_dirs:
        rel_lock = rel_posix(d / "package-lock.json", root)
        proc = run_cmd([*cmd, "audit", "--json"], cwd=d, timeout=300)
        # npm audit exits non-zero WHEN VULNS EXIST — that's success for us.
        if proc is None:
            return errored(NAME, version, f"npm audit failed to launch in {rel_lock}")
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return errored(NAME, version, f"could not parse npm audit output in {rel_lock}")
        if "error" in data:
            msg = (data.get("error") or {}).get("summary", "npm audit reported an error")
            return errored(NAME, version, msg)

        for pkg, info in (data.get("vulnerabilities", {}) or {}).items():
            advisories = [v for v in info.get("via", []) if isinstance(v, dict)]
            native_sev = _SEV.get(info.get("severity", "low"), "low")
            fix = info.get("fixAvailable")
            fix_hint = (
                f"Run `npm audit fix` (a compatible fix is available for {pkg})."
                if fix else f"Upgrade {pkg}; no automatic fix is available — check the advisory."
            )
            if not advisories:
                fid, dedupe = fingerprint(NAME, f"npm:{pkg}", rel_lock, f"{pkg}:{info.get('range','')}")
                findings.append(Finding(
                    id=fid, scanner=NAME, rule=f"npm:{pkg}", severity=native_sev,
                    file=rel_lock, line=None,
                    plain_summary=_dep_summary(pkg),
                    description=f"{pkg} ({info.get('range','?')}) has a known vulnerability.",
                    remediation_hint=fix_hint, dedupe_hash=dedupe,
                    details={"package": pkg, "severity_native": info.get("severity"), "range": info.get("range")},
                ))
                continue
            for adv in advisories:
                source = adv.get("source") or adv.get("url") or f"npm:{pkg}"
                url = adv.get("url") or ""
                m = re.search(r"GHSA-[0-9a-z-]+", url)
                rule = m.group(0) if m else f"npm-advisory-{source}"
                sev = _SEV.get(adv.get("severity", info.get("severity", "low")), native_sev)
                cwes = normalize_cwes(adv.get("cwe"))
                title = adv.get("title") or f"{pkg} has a known vulnerability."
                fid, dedupe = fingerprint(NAME, rule, rel_lock, f"{pkg}:{source}")
                findings.append(Finding(
                    id=fid, scanner=NAME, rule=rule, severity=sev,
                    file=rel_lock, line=None,
                    plain_summary=_dep_summary(pkg),
                    description=title, remediation_hint=fix_hint, dedupe_hash=dedupe,
                    details={
                        "package": pkg, "severity_native": adv.get("severity"),
                        "range": adv.get("range"), "url": adv.get("url"), "cwe": cwes,
                        "fix_available": bool(fix),
                    },
                ))
    return completed(NAME, version, findings)
