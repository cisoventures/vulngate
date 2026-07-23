"""Unit tests for vulngate's core — no network, no scanners required.

The scanner adapters themselves are exercised end-to-end against
test-fixtures/ (see the e2e job in CI); these cover the deterministic core.
"""

from pathlib import Path

from vulngate.config import ConfigError, load_config
from vulngate.detect import detect
from vulngate.knowledge import plain_summary
from vulngate.report import _short_rule, to_sarif
from vulngate.schema import (Diagnostic, Finding, ScannerRun, at_or_above,
                             build_report, fingerprint)

FIXTURE = Path(__file__).resolve().parents[1] / "test-fixtures" / "vulnerable-sample"


def _finding(**kw):
    base = dict(
        id="x", scanner="semgrep", rule="r", severity="high", file="a.py",
        line=1, plain_summary="p", description="d", remediation_hint="fix",
        dedupe_hash="sha256:x", details={},
    )
    base.update(kw)
    return Finding(**base)


def test_severity_threshold():
    assert at_or_above("critical", "high")
    assert at_or_above("high", "high")
    assert not at_or_above("medium", "high")
    assert at_or_above("low", "low")


def test_fingerprint_stable_and_line_independent():
    a = fingerprint("semgrep", "rule-x", "src/app.py", "native-1")
    b = fingerprint("semgrep", "rule-x", "src/app.py", "native-1")
    assert a == b                      # deterministic
    assert a[0].startswith("vg_") and len(a[0]) == 27  # vg_ + 24 hex
    assert a[1].startswith("sha256:")
    # Different location/native identity -> different id
    assert fingerprint("semgrep", "rule-x", "src/other.py", "native-1")[0] != a[0]


def test_plain_summary_prefers_cwe_then_keyword_then_default():
    assert "system command" in plain_summary(scanner="semgrep", rule="r", cwes=["CWE-78"], description="d")
    assert "system command" in plain_summary(scanner="semgrep", rule="dangerous-subprocess", cwes=[], description="d")
    assert plain_summary(scanner="pip-audit", rule="r", cwes=[], description="") .startswith("A Python package")


def test_detect_finds_manifests(tmp_path):
    det = detect(FIXTURE)
    assert "python" in det.languages
    assert any(p.name == "requirements.txt" for p in det.py_requirements)
    assert det.npm_lock_dirs  # package-lock.json present


def test_config_defaults_and_override(tmp_path):
    assert load_config(tmp_path, None)["fail_on"] == "high"
    (tmp_path / "vulngate.toml").write_text('fail_on = "critical"\ndisable = ["gitleaks"]\n')
    cfg = load_config(tmp_path, None)
    assert cfg["fail_on"] == "critical" and "gitleaks" in cfg["disable"]


def test_config_rejects_bad_fail_on(tmp_path):
    (tmp_path / "vulngate.toml").write_text('fail_on = "nope"\n')
    try:
        load_config(tmp_path, None)
        assert False, "expected ConfigError"
    except ConfigError:
        pass


def test_dependency_severity_config(tmp_path):
    assert load_config(tmp_path, None)["dependency_severity"] == "medium"
    (tmp_path / "vulngate.toml").write_text('dependency_severity = "high"\n')
    assert load_config(tmp_path, None)["dependency_severity"] == "high"
    (tmp_path / "vulngate.toml").write_text('dependency_severity = "sky"\n')
    try:
        load_config(tmp_path, None)
        assert False, "expected ConfigError"
    except ConfigError:
        pass


def test_short_rule_display():
    # semgrep duplicates the leaf segment; collapse it
    assert _short_rule("python.lang.security.audit.eval-detected.eval-detected") == "eval-detected"
    # dotless ids (advisories, npm) pass through untouched
    assert _short_rule("GHSA-jf85-cpcp-j695") == "GHSA-jf85-cpcp-j695"
    assert _short_rule("PYSEC-2018-28") == "PYSEC-2018-28"


def test_build_report_summary_and_sarif():
    findings = [_finding(id="a", severity="high"), _finding(id="b", severity="low", file="b.py", line=None)]
    report = build_report(
        tool_version="0.1.0", target=".", started_at="2026-07-23T00:00:00Z",
        duration_ms=5, fail_on="high", scan_status="complete", exit_code=1,
        scanners=[ScannerRun("semgrep", "1.0", "completed", 2)],
        findings=findings, diagnostics=[Diagnostic("gitleaks", "warning", "scanner_not_installed", "nope")],
    )
    assert report["summary"] == {"total": 2, "critical": 0, "high": 1, "medium": 0, "low": 1}
    sarif = to_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 2
    # null-line finding must omit region but keep artifactLocation
    locs = [r["locations"][0]["physicalLocation"] for r in sarif["runs"][0]["results"]]
    assert any("region" not in pl for pl in locs)
