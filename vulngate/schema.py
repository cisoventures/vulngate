"""vulngate findings schema v1 — the single normalized shape every scanner maps into.

The whole tool exists to turn many scanners' bespoke output into ONE stable
structure. Everything downstream (terminal report, findings.json, SARIF export,
the Phase 2 Action, the Phase 3 MCP server) reads only what this module defines.

Safety property: findings never carry raw secret values or source snippets.
findings.json may be committed or pasted into a chat, so it must be safe to share.
Code context is fetched live from the working tree by the MCP layer, never persisted.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

SCHEMA_VERSION = "1.0.0"

# The only four severities that may appear in output. Each scanner's native
# severity is mapped onto this scale in its adapter module.
SEVERITIES = ("critical", "high", "medium", "low")

# Ordering used for --fail-on threshold comparisons and summary sorting.
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def at_or_above(severity: str, threshold: str) -> bool:
    """True if `severity` is at least as severe as `threshold`."""
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(threshold, 0)


def fingerprint(scanner: str, rule: str, rel_path: str, native_identity: str) -> tuple[str, str]:
    """Compute a stable (id, dedupe_hash) pair for a finding.

    Deliberately excludes line number, description, remediation text, and
    timestamps so a finding keeps its identity when code shifts around it or
    when wording changes. `native_identity` is a non-secret, scanner-supplied
    stable token (semgrep fingerprint, gitleaks fingerprint, advisory id, ...).

    Returns (id, dedupe_hash):
      id         -> "vg_" + first 96 bits (24 hex) — short, readable, stable.
      dedupe_hash-> "sha256:" + full digest.
    """
    canonical = "|".join((scanner, rule or "", rel_path or "", native_identity or ""))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"vg_{digest[:24]}", f"sha256:{digest}"


@dataclass
class Finding:
    id: str
    scanner: str
    rule: str
    severity: str
    file: str
    line: Optional[int]            # required key, nullable (dep advisories have no line)
    plain_summary: str            # jargon-free "what this means for you"
    description: str
    remediation_hint: str
    dedupe_hash: str
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScannerRun:
    """One scanner's execution record — surfaced in scan.scanners[].

    `status` distinguishes *why* a scanner produced no findings so a zero is
    never ambiguous:
      completed       ran and reported (0+ findings)
      not_applicable  nothing for it to scan (no matching files/manifests)
      disabled        turned off in config
      unavailable     the tool isn't installed
      error           present + applicable, but failed to run or parse

    `applicable` (did this repo have work for the scanner?) and `available`
    (is the tool installed?) are the orthogonal facts scan.status derives from;
    either may be null when that fact wasn't determined (e.g. a disabled scanner
    is never probed for applicability).
    """
    name: str
    version: Optional[str]
    status: str                   # completed | not_applicable | disabled | unavailable | error
    finding_count: int = 0
    message: Optional[str] = None
    applicable: Optional[bool] = None
    available: Optional[bool] = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Diagnostic:
    """A run condition (e.g. 'scanner not installed') — NOT a vulnerability.

    Kept out of findings[] so severity counts stay honest.
    """
    scanner: str
    level: str                    # info | warning | error
    code: str
    message: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def config_hash(resolved_config: dict[str, Any]) -> str:
    """Stable sha256 over the resolved config dict — provenance for the receipt.

    Sorted-key JSON so the same effective settings always hash the same, letting
    a reviewer confirm two scans ran under identical policy.
    """
    canonical = json.dumps(resolved_config, sort_keys=True, default=str)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_report(
    *,
    tool_version: str,
    target: str,
    started_at: str,
    completed_at: str,
    duration_ms: int,
    fail_on: str,
    scan_status: str,
    exit_code: int,
    commit: Optional[str],
    config_hash: str,
    scanners: list[ScannerRun],
    findings: list[Finding],
    diagnostics: list[Diagnostic],
) -> dict[str, Any]:
    """Assemble the top-level envelope that gets written to findings.json."""
    summary = {s: 0 for s in SEVERITIES}
    for f in findings:
        if f.severity in summary:
            summary[f.severity] += 1
    summary_block = {"total": len(findings), **summary}

    return {
        "schema_version": SCHEMA_VERSION,
        "scan": {
            "tool_version": tool_version,
            "target": target,
            "started_at": started_at,
            "duration_ms": duration_ms,
            "fail_on": fail_on,
            "status": scan_status,        # complete | partial | no_coverage | error
            "exit_code": exit_code,
            "receipt": {
                "commit": commit,
                "config_hash": config_hash,
                "scanner_versions": {s.name: s.version for s in scanners},
                "started_at": started_at,
                "completed_at": completed_at,
            },
            "scanners": [s.as_dict() for s in scanners],
        },
        "summary": summary_block,
        "findings": [f.as_dict() for f in findings],
        "diagnostics": [d.as_dict() for d in diagnostics],
    }
