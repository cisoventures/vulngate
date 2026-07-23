"""npm audit adapter — JavaScript/npm dependency vulnerabilities (SCA).

Uses the npm already on the machine; no extra install needed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..knowledge import dependency_summary
from ..schema import Finding, fingerprint
from .base import (ScanOutput, completed, errored, normalize_cwes,
                   not_applicable, rel_posix, resolve_cmd, run_cmd, unavailable)

NAME = "npm-audit"
_SEV = {"critical": "critical", "high": "high", "moderate": "medium", "low": "low", "info": "low"}


def _dev_scope(lock_dir: Path) -> dict[str, str]:
    """Map package name -> 'runtime' | 'development' from package-lock.json.

    package-lock v2/v3 marks an entry `"dev": true` when it's reachable ONLY
    through devDependencies (a build-only tool). A package is 'development' when
    EVERY lockfile entry for it is dev; 'runtime' if any entry ships in the app.
    This is what lets us tell the user whether a "HIGH" is in their live app or
    just their build toolchain.
    """
    try:
        data = json.loads((lock_dir / "package-lock.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    scope: dict[str, str] = {}
    for path, meta in (data.get("packages") or {}).items():
        if not path:                       # "" is the root project entry
            continue
        name = path.split("node_modules/")[-1]
        if not name:
            continue
        is_dev = bool((meta or {}).get("dev"))
        if name not in scope:
            scope[name] = "development" if is_dev else "runtime"
        elif not is_dev:                   # any non-dev occurrence wins
            scope[name] = "runtime"
    return scope


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
        scope_map = _dev_scope(d)          # package -> runtime | development
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
            scope = scope_map.get(pkg, "unknown")   # runtime | development | unknown
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
                    plain_summary=dependency_summary(pkg, scope),
                    description=f"{pkg} ({info.get('range','?')}) has a known vulnerability.",
                    remediation_hint=fix_hint, dedupe_hash=dedupe,
                    details={"package": pkg, "severity_native": info.get("severity"),
                             "range": info.get("range"), "dependency_scope": scope},
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
                    plain_summary=dependency_summary(pkg, scope),
                    description=title, remediation_hint=fix_hint, dedupe_hash=dedupe,
                    details={
                        "package": pkg, "severity_native": adv.get("severity"),
                        "range": adv.get("range"), "url": adv.get("url"), "cwe": cwes,
                        "fix_available": bool(fix), "dependency_scope": scope,
                    },
                ))
    return completed(NAME, version, findings)
