"""Unit tests for vulngate's core — no network, no scanners required.

The scanner adapters themselves are exercised end-to-end against
test-fixtures/ (see the e2e job in CI); these cover the deterministic core.
"""

import json
from pathlib import Path

from vulngate.cli import derive_scan_status, main
from vulngate.config import ConfigError, load_config
from vulngate.scanners.base import (completed, disabled, errored,
                                    not_applicable, unavailable)
from vulngate.scanners.semgrep_scanner import _has_results, _native_identity
from vulngate.detect import detect
from vulngate.knowledge import (dependency_summary, plain_summary,
                                relevant_glossary)
from vulngate.scanners.npm_audit_scanner import _dev_scope
from vulngate.scanners.pip_audit_scanner import _req_scope
from vulngate.report import _short_rule, to_sarif
from vulngate.schema import (Diagnostic, Finding, ScannerRun, at_or_above,
                             build_report, config_hash, fingerprint)

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


def test_plain_summary_expanded_pack_coverage():
    # CWE path (new entries)
    assert "SSRF" in plain_summary(scanner="semgrep", rule="r", cwes=["CWE-918"], description="d")
    assert "open redirect" in plain_summary(scanner="semgrep", rule="r", cwes=["CWE-601"], description="d")
    assert "prototype" in plain_summary(scanner="semgrep", rule="r", cwes=["CWE-1321"], description="d")
    # keyword fallback path (no CWE) resolves to the mapped summary, not the raw description
    assert "SSRF" in plain_summary(scanner="semgrep", rule="nextjs-ssrf", cwes=[], description="raw")
    assert "NoSQL" in plain_summary(scanner="semgrep", rule="mongo-nosql-injection", cwes=[], description="raw")
    # every keyword mapping points at a real CWE summary string (no dangling refs)
    from vulngate.knowledge import CWE_SUMMARIES, KEYWORD_SUMMARIES
    covered = set(CWE_SUMMARIES.values())
    assert all(text in covered for _kw, text in KEYWORD_SUMMARIES)


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


def test_gate_fails_closed_on_no_coverage(tmp_path):
    data = {"scan": {"status": "no_coverage", "fail_on": "high", "exit_code": 0}, "findings": []}
    p = tmp_path / "f.json"
    p.write_text(json.dumps(data))
    assert main(["gate", str(p), "--quiet"]) == 2                        # fail closed
    assert main(["gate", str(p), "--quiet", "--allow-no-coverage"]) == 0  # explicit opt-out


def test_sarif_subcommand_projects_findings_json(tmp_path, capsys):
    report = _report()
    fp = tmp_path / "findings.json"
    fp.write_text(json.dumps(report))
    # --out writes a file
    out = tmp_path / "out.sarif"
    assert main(["sarif", str(fp), "--out", str(out)]) == 0
    sarif = json.loads(out.read_text())
    assert sarif["version"] == "2.1.0" and len(sarif["runs"][0]["results"]) == 2
    # no --out streams to stdout
    capsys.readouterr()
    assert main(["sarif", str(fp)]) == 0
    assert '"version": "2.1.0"' in capsys.readouterr().out
    # missing file -> exit 2 (matches gate/scan tool-error convention)
    assert main(["sarif", str(tmp_path / "nope.json")]) == 2


def test_dependency_summary_distinguishes_runtime_from_build_only():
    dev = dependency_summary("wrangler", "development")
    run = dependency_summary("lodash", "runtime")
    unk = dependency_summary("foo", "unknown")
    assert "build-only tool" in dev and "isn't exposed" in dev
    assert "live app actually runs" in run and "exposed to the internet" in run
    assert "known security flaw" in unk and "build-only" not in unk  # neutral fallback


def test_npm_dev_scope_from_lockfile(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "root"},
            "node_modules/lodash": {"version": "1"},                    # runtime (no dev flag)
            "node_modules/wrangler": {"version": "1", "dev": True},     # build-only
            "node_modules/esbuild": {"version": "1", "dev": True},      # build-only (nested below)
            "node_modules/wrangler/node_modules/esbuild": {"version": "2", "dev": True},
        },
    }))
    scope = _dev_scope(tmp_path)
    assert scope["lodash"] == "runtime"
    assert scope["wrangler"] == "development"
    assert scope["esbuild"] == "development"


def test_npm_dev_scope_any_runtime_occurrence_wins(tmp_path):
    # A package that appears both as a dev and a prod dep is runtime-reachable.
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/x": {"version": "1", "dev": True},
            "node_modules/a/node_modules/x": {"version": "2"},   # non-dev path
        },
    }))
    assert _dev_scope(tmp_path)["x"] == "runtime"


def test_pip_req_scope_from_filename():
    assert _req_scope("requirements.txt") == "runtime"
    assert _req_scope("requirements-dev.txt") == "development"
    assert _req_scope("test-requirements.txt") == "development"
    assert _req_scope("app/requirements.txt") == "runtime"


def test_relevant_glossary_only_shows_applicable_terms():
    dep_dev = {"scanner": "npm-audit", "details": {"dependency_scope": "development"}}
    secret = {"scanner": "gitleaks", "details": {}}
    terms = dict(relevant_glossary([dep_dev, secret]))
    assert "dependency" in terms and "build-only tool" in terms and "secret" in terms
    # a pure-SAST scan needs neither "dependency" nor "secret"
    sast_only = dict(relevant_glossary([{"scanner": "semgrep", "details": {}}]))
    assert "dependency" not in sast_only and "secret" not in sast_only and "severity" in sast_only
    assert relevant_glossary([]) == []


def test_semgrep_placeholder_fingerprint_keeps_distinct_lines_distinct():
    # Regression: Semgrep OSS stamps every finding with extra.fingerprint =
    # "requires login". Two DISTINCT matches of the same rule in the same file
    # (different lines) must NOT collapse into one dedupe id.
    rule, rel = "javascript.audit.detect-non-literal-regexp", "src/index.js"
    ph = {"fingerprint": "requires login"}
    n865 = _native_identity(rule, rel, {"line": 865, "col": 13}, ph)
    n911 = _native_identity(rule, rel, {"line": 911, "col": 13}, ph)
    assert n865 != n911                                   # location keeps them apart
    assert fingerprint(rule, rule, rel, n865)[0] != fingerprint(rule, rule, rel, n911)[0]  # different ids
    # identical location still collapses (a genuine duplicate)
    assert n865 == _native_identity(rule, rel, {"line": 865, "col": 13}, ph)
    # a REAL fingerprint (logged-in semgrep) is used verbatim and stays line-independent
    assert _native_identity(rule, rel, {"line": 865}, {"fingerprint": "abc123"}) == "abc123"
    assert _native_identity(rule, rel, {"line": 999}, {"fingerprint": "abc123"}) == "abc123"


def test_semgrep_crash_output_treated_as_invalid():
    assert _has_results({"results": []})   # a real scan with zero findings
    assert not _has_results({})            # crash that emitted empty '{}'
    assert not _has_results([])            # non-report payload
    assert not _has_results(None)


def _report(**over):
    findings = over.pop("findings", [_finding(id="a", severity="high"),
                                     _finding(id="b", severity="low", file="b.py", line=None)])
    base = dict(
        tool_version="0.1.0", target=".", started_at="2026-07-23T00:00:00Z",
        completed_at="2026-07-23T00:00:05Z", duration_ms=5, fail_on="high",
        scan_status="complete", exit_code=1, commit="abc123",
        config_hash="sha256:" + "0" * 64,
        scanners=[ScannerRun("semgrep", "1.0", "completed", 2, applicable=True, available=True)],
        diagnostics=[], findings=findings,
    )
    base.update(over)
    return build_report(**base)


def test_terminal_report_labels_scope_caveat_and_glossary():
    from vulngate.report import terminal_report
    dep = _finding(id="d", scanner="npm-audit", rule="GHSA-x", severity="high",
                   file="package-lock.json", line=None,
                   details={"package": "wrangler", "dependency_scope": "development"}).as_dict()
    sast = _finding(id="s", scanner="semgrep", rule="r", severity="low").as_dict()
    report = _report(findings=[], scanners=[ScannerRun("npm-audit", "1", "completed", 1)])
    report["findings"] = [dep, sast]
    out = terminal_report(report, color=False)
    assert "build-only tool" in out                     # dependency scope label
    assert "known issue" in out and "advisor" not in out  # plainer wording, no "advisory"
    assert "false alarm" in out                          # SAST caveat present
    assert "what these words mean" in out and "build-only tool —" in out  # glossary


def test_build_report_summary_and_sarif():
    report = _report()
    assert report["summary"] == {"total": 2, "critical": 0, "high": 1, "medium": 0, "low": 1}
    sarif = to_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 2
    # null-line finding must omit region but keep artifactLocation
    locs = [r["locations"][0]["physicalLocation"] for r in sarif["runs"][0]["results"]]
    assert any("region" not in pl for pl in locs)


def test_scan_receipt_present_and_provenance():
    report = _report()
    receipt = report["scan"]["receipt"]
    assert receipt["commit"] == "abc123"
    assert receipt["config_hash"].startswith("sha256:")
    assert receipt["scanner_versions"] == {"semgrep": "1.0"}          # name -> version
    assert receipt["started_at"] == "2026-07-23T00:00:00Z"
    assert receipt["completed_at"] == "2026-07-23T00:00:05Z"


def test_config_hash_is_stable_and_order_independent():
    a = config_hash({"fail_on": "high", "exclude": ["a", "b"]})
    b = config_hash({"exclude": ["a", "b"], "fail_on": "high"})   # key order
    assert a == b and a.startswith("sha256:")
    assert config_hash({"fail_on": "low"}) != a                   # different policy -> different hash


def _run(name, status, applicable=None, available=None):
    return ScannerRun(name=name, version=None, status=status,
                      applicable=applicable, available=available)


def test_scanner_status_helpers_set_applicable_available():
    assert not_applicable("x", "r").run.status == "not_applicable"
    assert not_applicable("x", "r").run.applicable is False
    assert unavailable("x", "r").run.applicable is True and unavailable("x", "r").run.available is False
    assert disabled("x", "r").run.status == "disabled"
    assert errored("x", None, "boom").run.applicable is True
    assert completed("x", "1.0", []).run.available is True


def test_derive_scan_status_taxonomy():
    # every applicable scanner completed -> complete (n/a and disabled don't count)
    assert derive_scan_status([
        completed("semgrep", "1", []).run, completed("gitleaks", "1", []).run,
        not_applicable("pip-audit", "r").run, disabled("npm-audit", "r").run,
    ]) == "complete"
    # an applicable-but-unavailable scanner is a coverage gap -> partial
    assert derive_scan_status([
        completed("semgrep", "1", []).run, unavailable("gitleaks", "r").run,
    ]) == "partial"
    # an applicable scanner that errored, alongside a success -> partial
    assert derive_scan_status([
        completed("semgrep", "1", []).run, errored("gitleaks", "1", "boom").run,
    ]) == "partial"
    # nothing completed, an error present -> error
    assert derive_scan_status([errored("semgrep", "1", "boom").run]) == "error"
    # nothing completed, only n/a + disabled -> no_coverage (fail closed upstream)
    assert derive_scan_status([
        not_applicable("pip-audit", "r").run, disabled("npm-audit", "r").run,
    ]) == "no_coverage"
