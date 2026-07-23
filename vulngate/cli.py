"""vulngate CLI — orchestrates scanners, normalizes output, sets CI exit codes.

Exit codes (precedence 2 > 1 > 0):
  0  clean, or nothing at/above the --fail-on threshold
  1  at least one finding at/above the threshold
  2  tool error (bad target/config, or every applicable scanner failed)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import ConfigError, load_config
from .detect import detect
from .report import terminal_report, to_sarif
from .schema import (Diagnostic, Finding, ScannerRun, at_or_above, build_report)
from .scanners import (gitleaks_scanner, npm_audit_scanner, pip_audit_scanner,
                       semgrep_scanner)

# Registry — the ONLY place scanners are listed. Everything else is generic.
SCANNERS = {
    "semgrep": semgrep_scanner,
    "gitleaks": gitleaks_scanner,
    "pip-audit": pip_audit_scanner,
    "npm-audit": npm_audit_scanner,
}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vulngate", description="Agent-neutral security checks before you ship.")
    p.add_argument("--version", action="version", version=f"vulngate {__version__}")
    sub = p.add_subparsers(dest="command")

    gate = sub.add_parser("gate", help="re-evaluate an existing findings.json against a threshold (exit code only)")
    gate.add_argument("findings", nargs="?", default="findings.json", help="path to a findings.json (default: findings.json)")
    gate.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], help="severity threshold (default: the value recorded in the file)")
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
    scan.add_argument("--no-color", action="store_true", help="disable colored output")
    scan.add_argument("--quiet", action="store_true", help="suppress the terminal summary")
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
            runs.append(ScannerRun(name=name, version=None, status="skipped", message="disabled in config"))
            continue
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

    # Determine scan status.
    completed = sum(1 for r in runs if r.status == "completed")
    errored = sum(1 for r in runs if r.status == "error")
    if completed == 0 and errored > 0:
        scan_status, tool_error = "error", True
    elif completed == 0:
        # Nothing actually ran — never report this as a clean "complete" pass.
        scan_status, tool_error = "no_coverage", False
        diags.append(Diagnostic(
            scanner="vulngate", level="warning", code="no_coverage",
            message="No scanner produced results — coverage is zero. Install scanners "
                    "(pip install 'vulngate[scanners]'; brew install gitleaks).",
        ))
    elif errored or any(r.status == "skipped" for r in runs):
        scan_status, tool_error = "partial", False
    else:
        scan_status, tool_error = "complete", False

    threshold_hit = any(at_or_above(f.severity, fail_on) for f in findings)
    exit_code = 2 if tool_error else (1 if threshold_hit else 0)

    report = build_report(
        tool_version=__version__, target=args.path, started_at=started,
        duration_ms=int((time.monotonic() - t0) * 1000), fail_on=fail_on,
        scan_status=scan_status, exit_code=exit_code, scanners=runs,
        findings=findings, diagnostics=diags,
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
    if data.get("scan", {}).get("status") == "error":
        return 2
    fail_on = args.fail_on or data.get("scan", {}).get("fail_on", "high")
    findings = data.get("findings", [])
    hit = any(at_or_above(f.get("severity", "low"), fail_on) for f in findings)
    if not args.quiet:
        verdict = "FAIL" if hit else "PASS"
        print(f"vulngate gate: {verdict} — {len(findings)} finding(s), threshold '{fail_on}'")
    return 1 if hit else 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "gate":
        return _run_gate(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
