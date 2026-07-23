"""Tests for the Action-layer scripts — no network. Focus: the PR comment's
verdict must come from the findings it shows, not a possibly-stale exit code
(so comment / gate / JSON never disagree)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "action" / "scripts"))

from pr_comment import render_markdown  # noqa: E402


def _finding(sev):
    return {"scanner": "semgrep", "rule": "r", "severity": sev, "file": "a.py",
            "line": 1, "plain_summary": "p", "description": "d",
            "remediation_hint": "x", "details": {}}


def _data(exit_code, findings, status="complete"):
    return {
        "scan": {"tool_version": "1", "target": ".", "fail_on": "high",
                 "status": status, "exit_code": exit_code, "scanners": []},
        "summary": {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0},
        "findings": findings,
    }


def test_verdict_ignores_stale_exit_code():
    # stale exit_code=1 but nothing at/above 'high' -> comment says Passed
    passed = render_markdown(_data(1, [_finding("low")]))
    assert "Passed" in passed and "Failed" not in passed
    # stale exit_code=0 but a high finding present -> comment says Failed
    failed = render_markdown(_data(0, [_finding("high")]))
    assert "Failed" in failed


def test_verdict_no_coverage():
    md = render_markdown(_data(0, [], status="no_coverage"))
    assert "No coverage" in md
