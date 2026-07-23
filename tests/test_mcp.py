"""Unit tests for the MCP server's tool logic — no MCP client, no network.

The end-to-end scan (scan_repo → explain → suggest against a real repo) is
exercised separately; these cover the pure helpers.
"""

import json
from pathlib import Path

import vulngate.mcp_server as mcp
from vulngate.mcp_server import (_explain_finding, _find, _findings_path,
                                 _snippet, _suggest_patch, _verify_fix)

FIX = Path(__file__).resolve().parents[1] / "test-fixtures" / "vulnerable-sample"


def _envelope(findings, scanners):
    """Minimal findings envelope for verify_fix tests."""
    return {
        "scan": {"target": ".", "status": "complete",
                 "scanners": [{"name": n, "status": s} for n, s in scanners]},
        "summary": {"total": len(findings)},
        "findings": findings,
    }


def _f(fid="vg_x", scanner="semgrep"):
    return {"id": fid, "scanner": scanner, "rule": "r", "severity": "high",
            "file": "a.py", "line": 2, "plain_summary": "p", "description": "d",
            "remediation_hint": "fix", "dedupe_hash": "sha256:z", "details": {}}


def test_findings_path(tmp_path):
    assert _findings_path(str(tmp_path)) == tmp_path / "findings.json"
    f = tmp_path / "code.py"
    f.write_text("x = 1\n")
    assert _findings_path(str(f)) == tmp_path / "findings.json"  # file -> its dir


def test_find_by_id_or_hash():
    data = {"findings": [{"id": "vg_abc", "dedupe_hash": "sha256:xyz"}]}
    assert _find(data, "vg_abc")["id"] == "vg_abc"
    assert _find(data, "sha256:xyz")["id"] == "vg_abc"
    assert _find(data, "nope") is None


def test_snippet_is_live_and_numbered():
    snip = _snippet(str(FIX), "src/app.py", 11, radius=2)
    assert "11:" in snip and "subprocess" in snip  # read live from the working tree


def test_snippet_refuses_path_traversal(tmp_path):
    (tmp_path / "safe.py").write_text("ok = 1\n")
    (tmp_path.parent / "outside.txt").write_text("SECRET OUTSIDE THE REPO\n")
    # a manipulated finding path that escapes the scanned root yields nothing
    assert _snippet(str(tmp_path), "../outside.txt", 1, radius=3) == ""
    # a legitimate in-repo path still works
    assert "ok" in _snippet(str(tmp_path), "safe.py", 1, radius=3)


def test_explain_and_suggest(tmp_path):
    (tmp_path / "a.py").write_text("import os\nresult = eval(user_input)\n")
    data = {"scan": {"target": "."}, "findings": [{
        "id": "vg_test", "scanner": "semgrep", "rule": "eval-detected", "severity": "high",
        "file": "a.py", "line": 2, "plain_summary": "runs a string as code",
        "description": "eval", "remediation_hint": "avoid eval", "dedupe_hash": "sha256:z",
        "details": {"rule_url": "https://sg.run/x"}}]}
    (tmp_path / "findings.json").write_text(json.dumps(data))

    ex = _explain_finding("vg_test", str(tmp_path))
    assert ex["finding"]["id"] == "vg_test"
    assert "eval" in ex["code"] and ex["rule_url"] == "https://sg.run/x"
    assert "plain English" in ex["guidance"]

    sp = _suggest_patch("vg_test", str(tmp_path))
    assert sp["file"] == "a.py" and "code_context" in sp
    assert "approv" in sp["instructions"].lower()  # "approval" / "approves"

    assert "error" in _explain_finding("does-not-exist", str(tmp_path))  # bad id
    clean = tmp_path / "clean"; clean.mkdir()
    assert "error" in _explain_finding("vg_test", str(clean))            # no findings.json


def _prep(tmp_path, before_findings, scanners):
    """Write the 'before' findings.json to a temp repo root."""
    (tmp_path / "findings.json").write_text(json.dumps(_envelope(before_findings, scanners)))


def test_verify_fix_confirmed_when_gone_and_scanner_completed(tmp_path, monkeypatch):
    _prep(tmp_path, [_f()], [("semgrep", "completed")])
    # re-scan: finding gone, owning scanner completed -> fixed
    monkeypatch.setattr(mcp, "_scan_repo", lambda p, *a, **k: _envelope([], [("semgrep", "completed")]))
    r = _verify_fix("vg_x", str(tmp_path))
    assert r["verdict"] == "fixed" and r["resolved"] is True
    assert r["scanner"] == "semgrep"


def test_verify_fix_still_present(tmp_path, monkeypatch):
    _prep(tmp_path, [_f()], [("semgrep", "completed")])
    monkeypatch.setattr(mcp, "_scan_repo", lambda p, *a, **k: _envelope([_f()], [("semgrep", "completed")]))
    r = _verify_fix("vg_x", str(tmp_path))
    assert r["verdict"] == "still_present" and r["resolved"] is False


def test_verify_fix_inconclusive_when_scanner_did_not_run(tmp_path, monkeypatch):
    # The finding vanishes ONLY because the scanner isn't installed this time —
    # that must NOT read as a fix (the core safety property).
    _prep(tmp_path, [_f()], [("semgrep", "completed")])
    monkeypatch.setattr(mcp, "_scan_repo", lambda p, *a, **k: _envelope([], [("semgrep", "unavailable")]))
    r = _verify_fix("vg_x", str(tmp_path))
    assert r["verdict"] == "inconclusive" and r["resolved"] is False


def test_verify_fix_inconclusive_when_rescan_fails(tmp_path, monkeypatch):
    _prep(tmp_path, [_f()], [("semgrep", "completed")])
    monkeypatch.setattr(mcp, "_scan_repo", lambda p, *a, **k: {"error": "vulngate scan failed", "detail": "boom"})
    r = _verify_fix("vg_x", str(tmp_path))
    assert r["verdict"] == "inconclusive" and "boom" in r["detail"]


def test_verify_fix_unknown_finding(tmp_path, monkeypatch):
    _prep(tmp_path, [_f(fid="vg_other")], [("semgrep", "completed")])
    monkeypatch.setattr(mcp, "_scan_repo", lambda p, *a, **k: _envelope([_f(fid="vg_other")], [("semgrep", "completed")]))
    r = _verify_fix("vg_missing", str(tmp_path))
    assert r["verdict"] == "unknown_finding"


def test_verify_fix_needs_baseline(tmp_path):
    assert "error" in _verify_fix("vg_x", str(tmp_path))   # no findings.json yet
