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


def _scan_repo(path: str = ".", fail_on: str = "high") -> dict[str, Any]:
    """Run the CLI and return the normalized findings envelope."""
    out = _findings_path(path)
    proc = subprocess.run(
        [sys.executable, "-m", "vulngate.cli", "scan", path,
         "--fail-on", fail_on, "--json", str(out), "--quiet", "--no-color"],
        capture_output=True, text=True, timeout=900,
    )
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
    """Live-read numbered code context. Never persisted."""
    root = Path(path).resolve()
    target = (root if root.is_dir() else root.parent) / rel_file
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


# ── MCP wiring (guarded so the module imports without the SDK) ───────────────
try:
    from mcp.server.fastmcp import FastMCP

    _mcp = FastMCP("vulngate")

    @_mcp.tool()
    def scan_repo(path: str = ".", fail_on: str = "high") -> dict:
        """Run vulngate's deterministic security scanners (SAST via Semgrep, secrets
        via gitleaks, dependency audit via pip-audit / npm audit) over a local repo
        and return normalized findings. Writes findings.json to the scanned directory
        — the ONLY write this server performs; it is otherwise read-only. Makes no LLM
        calls itself. Call this first, then use the returned findings[].id values with
        explain_finding / suggest_patch.

        Args:
            path: repo or directory to scan (default ".").
            fail_on: severity threshold recorded for the gate (critical|high|medium|low).
        """
        return _scan_repo(path, fail_on)

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
