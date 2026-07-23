"""vulngate CLI — orchestrates scanners, normalizes output, sets CI exit codes.

Exit codes (precedence 2 > 1 > 0):
  0  clean, or nothing at/above the --fail-on threshold
  1  at least one finding at/above the threshold
  2  tool error (bad target/config, or every applicable scanner failed)
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import ConfigError, load_config
from .detect import detect
from .report import terminal_report, to_sarif
from .schema import (Diagnostic, Finding, ScannerRun, build_report,
                     config_hash as compute_config_hash, gates_the_build)
from .scanners.base import disabled as disabled_run
from .scanners import (gitleaks_scanner, npm_audit_scanner, pip_audit_scanner,
                       semgrep_scanner)

# Registry — the ONLY place scanners are listed. Everything else is generic.
SCANNERS = {
    "semgrep": semgrep_scanner,
    "gitleaks": gitleaks_scanner,
    "pip-audit": pip_audit_scanner,
    "npm-audit": npm_audit_scanner,
}


def derive_scan_status(runs: list[ScannerRun]) -> str:
    """Reduce per-scanner outcomes to one scan.status.

      error       nothing completed and at least one applicable scanner errored
      no_coverage nothing completed at all (a security gate must fail closed)
      partial     something ran, but an applicable scanner errored or wasn't installed
      complete    every scanner that applied to this repo ran successfully

    A coverage gap is an *applicable* scanner that didn't complete (errored or
    unavailable). not_applicable and disabled scanners are never gaps.
    """
    completed = sum(1 for r in runs if r.status == "completed")
    errored = sum(1 for r in runs if r.status == "error")
    gaps = sum(1 for r in runs if r.applicable and r.status != "completed")
    if completed == 0 and errored > 0:
        return "error"
    if completed == 0:
        return "no_coverage"
    return "partial" if gaps > 0 else "complete"


def _git_commit(root: Path) -> str | None:
    """Current commit SHA for the scan receipt, or None outside a git repo."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    return proc.stdout.strip() if proc.returncode == 0 and proc.stdout.strip() else None


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vulngate", description="Agent-neutral security checks before you ship.")
    p.add_argument("--version", action="version", version=f"vulngate {__version__}")
    sub = p.add_subparsers(dest="command")

    gate = sub.add_parser("gate", help="re-evaluate an existing findings.json against a threshold (exit code only)")
    gate.add_argument("findings", nargs="?", default="findings.json", help="path to a findings.json (default: findings.json)")
    gate.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], help="severity threshold (default: the value recorded in the file)")
    gate.add_argument("--allow-no-coverage", action="store_true", help="pass instead of failing when no scanner ran (default: fail closed)")
    gate.add_argument("--ignore-dev-deps", action="store_true", help="don't fail on build-only (dev) dependency flaws (default: use the policy recorded in the file)")
    gate.add_argument("--quiet", action="store_true", help="suppress the one-line verdict")

    scan = sub.add_parser("scan", help="scan a repository or path")
    scan.add_argument("path", nargs="?", default=".", help="path to scan (default: .)")
    scan.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], help="severity threshold that fails the run (default: high)")
    scan.add_argument("--config", help="path to a config file")
    scan.add_argument("--json", dest="json_out", nargs="?", const="findings.json", default="findings.json", help="write findings JSON here (default: findings.json; '-' for stdout only skip)")
    scan.add_argument("--sarif", help="also write a SARIF file here")
    scan.add_argument("--exclude", action="append", default=[], help="glob to exclude (repeatable)")
    scan.add_argument("--no-deps", action="store_true", default=None, help="pass --no-deps to pip-audit (skip resolution; for fully-pinned requirement files)")
    scan.add_argument("--dep-severity", choices=["critical", "high", "medium", "low"], help="severity for dependency findings lacking a CVSS score (default: medium)")
    scan.add_argument("--allow-no-coverage", action="store_true", default=None, help="exit 0 instead of 2 when no scanner ran (default: fail closed)")
    scan.add_argument("--ignore-dev-deps", action="store_true", default=None, help="don't fail the gate on build-only (dev) dependency flaws — they're still reported (recommended for vibecoder setups)")
    scan.add_argument("--no-color", action="store_true", help="disable colored output")
    scan.add_argument("--quiet", action="store_true", help="suppress the terminal summary")

    sarif = sub.add_parser("sarif", help="project an existing findings.json to SARIF (regenerate after diff-filter/triage)")
    sarif.add_argument("findings", nargs="?", default="findings.json", help="path to a findings.json (default: findings.json)")
    sarif.add_argument("--out", help="write SARIF here (default: stdout)")
    return p


def _run_scan(args) -> int:
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"vulngate: target not found: {args.path}", file=sys.stderr)
        return 2
    try:
        cfg = load_config(root, args.config)
    except ConfigError as e:
        print(f"vulngate: {e}", file=sys.stderr)
        return 2

    fail_on = args.fail_on or cfg["fail_on"]
    exclude = list(cfg["exclude"]) + list(args.exclude)
    disabled = set(cfg["disable"])
    ignore = set(cfg["ignore"])
    allow_no_coverage = args.allow_no_coverage if args.allow_no_coverage is not None else cfg["allow_no_coverage"]
    # Resolve the build-only-dep gate policy (CLI flag wins over config).
    fail_on_dev_deps = (not args.ignore_dev_deps) if args.ignore_dev_deps is not None else cfg["fail_on_dev_deps"]
    opts = {
        "no_deps": args.no_deps if args.no_deps is not None else cfg["no_deps"],
        "dependency_severity": args.dep_severity or cfg["dependency_severity"],
    }

    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    t0 = time.monotonic()

    det = detect(root, exclude)

    findings: list[Finding] = []
    runs: list[ScannerRun] = []
    diags: list[Diagnostic] = []
    for name, module in SCANNERS.items():
        if name in disabled:
            out = disabled_run(name, "disabled in config")
        else:
            out = module.run(root, det, opts)
        runs.append(out.run)
        findings.extend(out.findings)
        diags.extend(out.diagnostics)

    # Apply ignore list (by finding id or rule); dedupe by id.
    seen: set[str] = set()
    kept: list[Finding] = []
    for f in findings:
        if f.id in ignore or f.rule in ignore or f.id in seen:
            continue
        seen.add(f.id)
        kept.append(f)
    findings = kept

    # Derive scan.status from applicability + completion.
    scan_status = derive_scan_status(runs)
    tool_error = scan_status == "error" or (scan_status == "no_coverage" and not allow_no_coverage)
    if scan_status == "no_coverage":
        # Nothing actually ran. Fail CLOSED — a security gate must not report a
        # clean pass when it scanned nothing (opt out with --allow-no-coverage).
        diags.append(Diagnostic(
            scanner="vulngate", level="warning", code="no_coverage",
            message="No scanner produced results — coverage is zero. Install scanners "
                    "(pip install 'vulngate[scanners]'; brew install gitleaks), or pass "
                    "--allow-no-coverage to accept it.",
        ))

    threshold_hit = any(gates_the_build(f, fail_on, fail_on_dev_deps) for f in findings)
    exit_code = 2 if tool_error else (1 if threshold_hit else 0)

    # Scan receipt — provenance so a findings.json is self-describing and
    # auditable: which commit, under which effective config, with which tools.
    resolved_cfg = {
        "fail_on": fail_on,
        "exclude": sorted(exclude),
        "disable": sorted(disabled),
        "ignore": sorted(ignore),
        "no_deps": opts["no_deps"],
        "dependency_severity": opts["dependency_severity"],
        "allow_no_coverage": allow_no_coverage,
        "fail_on_dev_deps": fail_on_dev_deps,
    }
    completed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    report = build_report(
        tool_version=__version__, target=args.path, started_at=started,
        completed_at=completed_at,
        duration_ms=int((time.monotonic() - t0) * 1000), fail_on=fail_on,
        scan_status=scan_status, exit_code=exit_code,
        fail_on_dev_deps=fail_on_dev_deps,
        commit=_git_commit(root), config_hash=compute_config_hash(resolved_cfg),
        scanners=runs, findings=findings, diagnostics=diags,
    )

    if args.json_out and args.json_out != "-":
        Path(args.json_out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(to_sarif(report), indent=2) + "\n", encoding="utf-8")
    if not args.quiet:
        print(terminal_report(report, color=not args.no_color))
    return exit_code


def _run_gate(args) -> int:
    """Re-evaluate a findings.json (possibly after diff-filtering or LLM triage)
    against the threshold. Threshold logic lives here so the Action never
    reimplements it. Exit: 2 tool error, 1 over threshold, 0 clean."""
    p = Path(args.findings)
    if not p.exists():
        print(f"vulngate: findings file not found: {args.findings}", file=sys.stderr)
        return 2
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"vulngate: could not read {args.findings}: {e}", file=sys.stderr)
        return 2
    status = data.get("scan", {}).get("status")
    if status == "error":
        return 2
    if status == "no_coverage" and not args.allow_no_coverage:
        if not args.quiet:
            print("vulngate gate: FAIL — no scanner ran (zero coverage). "
                  "Pass --allow-no-coverage to override.", file=sys.stderr)
        return 2
    fail_on = args.fail_on or data.get("scan", {}).get("fail_on", "high")
    # Honor the build-only-dep policy recorded by the scan, unless overridden.
    fail_on_dev_deps = False if args.ignore_dev_deps else data.get("scan", {}).get("fail_on_dev_deps", True)
    findings = data.get("findings", [])
    gating = [f for f in findings if gates_the_build(f, fail_on, fail_on_dev_deps)]
    hit = bool(gating)
    if not args.quiet:
        verdict = "FAIL" if hit else "PASS"
        print(f"vulngate gate: {verdict} — {len(gating)} blocking of {len(findings)} finding(s), threshold '{fail_on}'")
    return 1 if hit else 0


def _run_sarif(args) -> int:
    """Project an existing findings.json to SARIF. Kept separate from `scan` so the
    Action can regenerate SARIF from the FINAL findings.json (after diff-filter and
    triage) — keeping the Security tab consistent with the PR comment and gate.
    Exit: 2 if the file is missing/unreadable, else 0."""
    p = Path(args.findings)
    if not p.exists():
        print(f"vulngate: findings file not found: {args.findings}", file=sys.stderr)
        return 2
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"vulngate: could not read {args.findings}: {e}", file=sys.stderr)
        return 2
    sarif = json.dumps(to_sarif(data), indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(sarif, encoding="utf-8")
    else:
        sys.stdout.write(sarif)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "gate":
        return _run_gate(args)
    if args.command == "sarif":
        return _run_sarif(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
