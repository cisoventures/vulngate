"""vulngate MCP server — the flagship vibe-coder loop.

A local stdio MCP server (no hosting) that lets a host agent (Claude Code,
Cursor, Codex, Windsurf, …) run vulngate and then explain and fix findings on
the USER's own subscription. It is a thin wrapper: it shells out to the same CLI
and never reimplements scan logic, and it makes NO LLM calls of its own.

Boundary (stated in every tool description, because descriptions are prompts):
  * Read-only against the repo, EXCEPT it writes findings.json when scanning.
  * Code snippets are read LIVE from the working tree and returned to the agent;
    they are never persisted into findings.json.
  * suggest_patch returns context only — the agent drafts the fix and the human
    approves it. This server never writes or applies code.

The tool functions below (`_scan_repo`, `_explain_finding`, `_suggest_patch`)
are plain and importable so they can be tested without an MCP client.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

FINDINGS_NAME = "findings.json"


# ── core helpers (no MCP dependency — unit-testable) ─────────────────────────
def _findings_path(path: str) -> Path:
    root = Path(path).resolve()
    return (root if root.is_dir() else root.parent) / FINDINGS_NAME


def _scan_repo(path: str = ".", fail_on: str = "high", block_on_build_only_deps: bool = False) -> dict[str, Any]:
    """Run the CLI and return the normalized findings envelope.

    Defaults to NOT failing on build-only (dev) dependency flaws — this is the
    vibecoder loop, and a flaw in the build toolchain never ships to the live
    app, so it's reported but shouldn't read as a blocking failure. Pass
    block_on_build_only_deps=True for the strict, CI-style verdict."""
    out = _findings_path(path)
    argv = [sys.executable, "-m", "vulngate.cli", "scan", path,
            "--fail-on", fail_on, "--json", str(out), "--quiet", "--no-color"]
    if not block_on_build_only_deps:
        argv.append("--ignore-dev-deps")
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=900)
    if proc.returncode == 2:  # tool error (bad target/config/all-scanners-failed)
        return {"error": "vulngate scan failed", "detail": (proc.stderr or "").strip()[-500:]}
    try:
        return json.loads(out.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return {"error": f"could not read scan output: {e}"}


def _load(path: str) -> dict[str, Any] | None:
    p = _findings_path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _find(data: dict, finding_id: str) -> dict | None:
    for f in data.get("findings", []):
        if f.get("id") == finding_id or f.get("dedupe_hash") == finding_id:
            return f
    return None


def _snippet(path: str, rel_file: str, line, radius: int) -> str:
    """Live-read numbered code context. Never persisted, and confined to the repo
    root — a manipulated finding path (e.g. '../../etc/passwd') is refused rather
    than handed to the host agent."""
    root = Path(path).resolve()
    base = root if root.is_dir() else root.parent
    target = (base / rel_file).resolve()
    if not target.is_relative_to(base):   # path escapes the scanned tree
        return ""
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if not line:
        return "\n".join(f"{i + 1}: {t}" for i, t in enumerate(lines[:24]))
    lo, hi = max(0, line - 1 - radius), min(len(lines), line + radius)
    return "\n".join(f"{i + 1}: {lines[i]}" for i in range(lo, hi))


def _not_found(finding_id: str) -> dict:
    return {"error": f"no finding with id '{finding_id}'. Run scan_repo first, "
                     "then pass an id from its findings[]."}


def _explain_finding(finding_id: str, path: str = ".") -> dict[str, Any]:
    data = _load(path)
    if data is None:
        return {"error": "no findings.json — run scan_repo first."}
    f = _find(data, finding_id)
    if f is None:
        return _not_found(finding_id)
    return {
        "finding": f,
        "code": _snippet(path, f.get("file", ""), f.get("line"), radius=6),
        "rule": f.get("rule"),
        "rule_url": (f.get("details") or {}).get("rule_url"),
        "remediation_hint": f.get("remediation_hint"),
        "guidance": ("Explain this finding to the user in plain English — what the risk is and "
                     "why it matters for them. Use plain_summary as a starting point. Do not modify "
                     "code. For secret findings, help the user rotate and remove the secret; do not "
                     "echo the secret value back."),
    }


def _suggest_patch(finding_id: str, path: str = ".") -> dict[str, Any]:
    data = _load(path)
    if data is None:
        return {"error": "no findings.json — run scan_repo first."}
    f = _find(data, finding_id)
    if f is None:
        return _not_found(finding_id)
    return {
        "finding": f,
        "code_context": _snippet(path, f.get("file", ""), f.get("line"), radius=14),
        "file": f.get("file"),
        "line": f.get("line"),
        "remediation_hint": f.get("remediation_hint"),
        "instructions": ("Draft a MINIMAL patch that fixes only this finding, then present the diff "
                         "to the user for approval before applying it. This tool does not write or "
                         "apply code — proposing and applying stay with the agent and the human."),
    }


def _scanner_run(data: dict, scanner: str) -> dict | None:
    for s in (data.get("scan", {}) or {}).get("scanners", []):
        if s.get("name") == scanner:
            return s
    return None


def _verify_fix(finding_id: str, path: str = ".") -> dict[str, Any]:
    """Re-scan after a fix and confirm the finding's stable id is actually gone.

    The stable, line-independent id is what makes this trustworthy: an edit that
    shifts code around keeps the id, so a disappearance means the *pattern* is
    gone, not that lines moved. The critical safety check: a finding can also
    vanish because its scanner didn't run this time (not installed, errored) —
    that is NOT a fix. We confirm the owning scanner `completed` in the re-scan
    before ever reporting 'fixed'; otherwise the verdict is 'inconclusive'.
    """
    before = _load(path)
    if before is None:
        return {"error": "no findings.json — run scan_repo first, then verify_fix after applying a fix."}
    original = _find(before, finding_id)
    # Re-scan (this overwrites findings.json with the post-fix 'after' state).
    after = _scan_repo(path)
    if "error" in after:
        return {"verdict": "inconclusive", "reason": "the re-scan failed to run; cannot confirm the fix",
                "detail": after.get("detail", ""), "scan_error": after.get("error")}

    still = _find(after, finding_id)
    scanner = (original or still or {}).get("scanner")
    run = _scanner_run(after, scanner) if scanner else None
    scanner_completed = bool(run) and run.get("status") == "completed"
    remaining = after.get("summary", {}).get("total")

    if still is not None:
        verdict, message = "still_present", (
            "The finding is still reported after re-scanning — the fix didn't remove it. "
            "Inspect the current code and try a different approach.")
    elif original is None:
        # The id wasn't in the baseline, so there's nothing to compare against.
        verdict, message = "unknown_finding", (
            f"No finding with id '{finding_id}' in the previous findings.json, so there's "
            "nothing to verify. Re-run scan_repo and pass a current id.")
    elif not scanner_completed:
        status = run.get("status") if run else "missing"
        verdict, message = "inconclusive", (
            f"The finding is gone, but its scanner ('{scanner}') did not complete this run "
            f"(status: {status}) — a disappearance from a scanner that didn't run is not a "
            "confirmed fix. Restore the scanner and verify again.")
    else:
        verdict, message = "fixed", (
            f"Confirmed: '{scanner}' re-ran and no longer reports this finding. The fix removed it.")

    return {
        "verdict": verdict,               # fixed | still_present | inconclusive | unknown_finding
        "finding_id": finding_id,
        "message": message,
        "resolved": verdict == "fixed",
        "original_finding": original,     # what it was (may be null if not in baseline)
        "scanner": scanner,
        "scanner_status": run.get("status") if run else None,
        "scan_status": (after.get("scan", {}) or {}).get("status"),
        "remaining_total": remaining,
        "guidance": ("Report the verdict plainly. Only 'fixed' means the issue is resolved and "
                     "confirmed by a scanner that actually ran. For 'still_present', help the user "
                     "revise the fix. For 'inconclusive', the scanner didn't complete — get it "
                     "installed/working before trusting a clean result."),
    }


# ── MCP wiring (guarded so the module imports without the SDK) ───────────────
try:
    from mcp.server.fastmcp import FastMCP

    _mcp = FastMCP("vulngate")

    @_mcp.tool()
    def scan_repo(path: str = ".", fail_on: str = "high",
                  block_on_build_only_deps: bool = False) -> dict:
        """Run vulngate's deterministic security scanners (SAST via Semgrep, secrets
        via gitleaks, dependency audit via pip-audit / npm audit) over a local repo
        and return normalized findings. Writes findings.json to the scanned directory
        — the ONLY write this server performs; it is otherwise read-only. Makes no LLM
        calls itself. Call this first, then use the returned findings[].id values with
        explain_finding / suggest_patch.

        Args:
            path: repo or directory to scan (default ".").
            fail_on: severity threshold recorded for the gate (critical|high|medium|low).
            block_on_build_only_deps: default False — a known flaw in a build-only
                (dev) dependency is reported but does NOT fail the gate, because it
                never ships to the live app. Set True for a strict, CI-style verdict.
        """
        return _scan_repo(path, fail_on, block_on_build_only_deps)

    @_mcp.tool()
    def explain_finding(finding_id: str, path: str = ".") -> dict:
        """Return full context for one finding (by an id from scan_repo) so YOU, the
        host agent, can explain it to the user in plain English on their own
        subscription. Includes a code snippet read LIVE from the working tree (never
        persisted), the rule reference, and the remediation hint. Read-only. Run
        scan_repo first.
        """
        return _explain_finding(finding_id, path)

    @_mcp.tool()
    def suggest_patch(finding_id: str, path: str = ".") -> dict:
        """Return a finding plus wider surrounding code context, formatted for YOU to
        draft a fix. This tool NEVER writes or applies code — you propose a patch and
        the human approves it before it lands. Read-only against the repo. Run
        scan_repo first.
        """
        return _suggest_patch(finding_id, path)

    @_mcp.tool()
    def verify_fix(finding_id: str, path: str = ".") -> dict:
        """After a fix has been applied, RE-SCAN and confirm the finding (by its stable
        id from scan_repo) is actually gone. Returns a verdict: 'fixed' (the owning
        scanner re-ran and no longer reports it), 'still_present' (the fix didn't remove
        it), 'inconclusive' (it's gone but the scanner didn't complete this run, so a
        clean result can't be trusted), or 'unknown_finding'. This re-runs the scanners
        and overwrites findings.json; it makes no LLM calls and never edits code. Use it
        to close the loop after suggest_patch and the user applying the change.
        """
        return _verify_fix(finding_id, path)

except ImportError:  # pragma: no cover
    _mcp = None


def main() -> int:
    if _mcp is None:
        print("vulngate-mcp requires the MCP SDK: pip install 'vulngate[mcp]'", file=sys.stderr)
        return 1
    _mcp.run()  # stdio transport
    return 0


if __name__ == "__main__":
    sys.exit(main())
