#!/usr/bin/env python3
"""Render findings.json as a PR comment and upsert it (edit-in-place).

Finds a prior vulngate comment by a hidden marker and PATCHes it, so pushing
new commits updates one comment instead of spamming a new one each time.
Pure stdlib (urllib) — no dependencies. Best-effort: never fails the build.

Env: GITHUB_TOKEN, GITHUB_REPOSITORY (owner/repo), GITHUB_EVENT_PATH.
Arg:  path to findings.json (default: findings.json).
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

# vulngate is pip-installed in the Action before this script runs, so we reuse
# its single source of plain-English truth instead of duplicating the strings.
try:
    from vulngate.knowledge import CODE_FINDING_CAVEAT, relevant_glossary
except Exception:  # pragma: no cover - keep the comment step best-effort
    CODE_FINDING_CAVEAT = ("A scanner flagged this code pattern — it can be a false alarm, "
                           "so confirm it applies before changing anything.")
    def relevant_glossary(_findings):
        return []

MARKER = "<!-- vulngate-report -->"
SEVERITIES = ("critical", "high", "medium", "low")
EMOJI = {"critical": "🟣", "high": "🔴", "medium": "🟡", "low": "🔵"}
DEP = ("pip-audit", "npm-audit")
SCOPE_LABEL = {"development": "build-only tool", "runtime": "in your live app"}
API = "https://api.github.com"


# ── markdown rendering (pure, testable) ──────────────────────────────────────
def render_markdown(data: dict) -> str:
    scan, summary = data["scan"], data["summary"]
    findings = data["findings"]
    # Derive the verdict from the findings actually shown (source of truth), not a
    # possibly-stale scan.exit_code — so comment, gate, and JSON always agree.
    _RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    fail_on = scan.get("fail_on", "high")
    fail_on_dev_deps = scan.get("fail_on_dev_deps", True)

    def _gates(f):
        if _RANK.get(f["severity"], 0) < _RANK.get(fail_on, 0):
            return False
        if not fail_on_dev_deps and (f.get("details") or {}).get("dependency_scope") == "development":
            return False
        return True

    non_blocking = sum(
        1 for f in findings
        if _RANK.get(f["severity"], 0) >= _RANK.get(fail_on, 0)
        and not fail_on_dev_deps
        and (f.get("details") or {}).get("dependency_scope") == "development"
    )
    if scan.get("status") == "error":
        ec, verdict = 2, "⚠️ **Tool error**"
    elif any(_gates(f) for f in findings):
        ec, verdict = 1, "❌ **Failed**"
    elif scan.get("status") == "no_coverage":
        ec, verdict = 0, "⚠️ **No coverage** — no scanner ran"
    else:
        ec, verdict = 0, "✅ **Passed**"

    out = [MARKER, "## vulngate security report", ""]
    out.append(f"{verdict} — threshold `{scan['fail_on']}`, {summary['total']} finding(s)")
    if non_blocking:
        out.append(f"\n> ℹ️ {non_blocking} build-only issue(s) shown below are **not blocking** — build-only tools don't ship to your live app.")
    out.append("")
    counts = " · ".join(f"{EMOJI[s]} {summary[s]} {s}" for s in SEVERITIES if summary[s]) or "none"
    out.append(f"**Severity:** {counts}")

    scanners = ", ".join(
        f"`{s['name']}`" + ("" if s["status"] == "completed" else f" ({s['status']})")
        for s in scan["scanners"]
    )
    out.append(f"**Scanners:** {scanners}")
    if any(s.get("triage") for s in findings):
        out.append("**LLM triage:** on (explanations and suggested fixes included)")
    out.append("")

    if not findings:
        out.append("No findings at or above the threshold. 🎉")
        return "\n".join(out)

    # Code findings individually; dependency findings grouped per package.
    code = [f for f in findings if f["scanner"] not in DEP]
    deps: dict[tuple, list] = {}
    for f in findings:
        if f["scanner"] in DEP:
            deps.setdefault((f["scanner"], f["file"], (f["details"] or {}).get("package", "?")), []).append(f)

    if code:
        out.append("<details open><summary><b>Code findings</b></summary>\n")
        for f in sorted(code, key=lambda x: SEVERITIES.index(x["severity"])):
            loc = f["file"] + (f":{f['line']}" if f.get("line") else "")
            out.append(f"- {EMOJI[f['severity']]} **{f['severity'].upper()}** `{loc}` — {f['plain_summary']}")
            out.append(f"  - _{f['scanner']}_ · `{f['rule']}` · fix: {f['remediation_hint']}")
            # Semgrep matches a pattern and can be wrong — say so gently.
            if f["scanner"] == "semgrep":
                out.append(f"  - _{CODE_FINDING_CAVEAT}_")
            t = f.get("triage")
            if t:
                fp = " · ⚠️ likely false positive" if t.get("false_positive") else ""
                out.append(f"  - 🤖 {t.get('explanation','').strip()}{fp}")
                if t.get("suggested_fix"):
                    out.append(f"  - 🤖 suggested fix: {t['suggested_fix'].strip()}")
        out.append("\n</details>")

    if deps:
        out.append("\n<details><summary><b>Dependency findings</b></summary>\n")
        for (scanner, file, pkg), fs in sorted(deps.items(), key=lambda kv: SEVERITIES.index(min((x["severity"] for x in kv[1]), key=SEVERITIES.index))):
            sev = min((x["severity"] for x in fs), key=SEVERITIES.index)
            scope = (fs[0].get("details") or {}).get("dependency_scope")
            scope_txt = f" · _{SCOPE_LABEL[scope]}_" if scope in SCOPE_LABEL else ""
            n = len(fs)
            out.append(f"- {EMOJI[sev]} **{sev.upper()}** `{pkg}` — {n} known issue{'' if n == 1 else 's'} in `{file}` (_{scanner}_){scope_txt}")
        out.append("\n</details>")

    glossary = relevant_glossary(findings)
    if glossary:
        out.append("\n<details><summary><b>What these words mean</b></summary>\n")
        for term, definition in glossary:
            out.append(f"- **{term}** — {definition}")
        out.append("\n</details>")

    out.append(f"\n<sub>Generated by [vulngate](https://github.com/cisoventures/vulngate) · we scan the code, not the agents.</sub>")
    return "\n".join(out)


# ── GitHub API (stdlib) ──────────────────────────────────────────────────────
def _api(method: str, url: str, token: str, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
        "User-Agent": "vulngate",
    })
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read() or "null")


def _pr_number(event_path: str | None) -> int | None:
    if not event_path or not Path(event_path).exists():
        return None
    try:
        ev = json.loads(Path(event_path).read_text())
    except (json.JSONDecodeError, OSError):
        return None
    return (ev.get("pull_request") or {}).get("number") or ev.get("number")


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "findings.json"
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    pr = _pr_number(os.environ.get("GITHUB_EVENT_PATH"))
    if not (token and repo and pr):
        print("pr_comment: not a PR context (or missing token/repo); skipping")
        return 0
    try:
        data = json.loads(Path(path).read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"pr_comment: cannot read {path}: {e}", file=sys.stderr)
        return 0

    body = render_markdown(data)
    try:
        comments = _api("GET", f"{API}/repos/{repo}/issues/{pr}/comments?per_page=100", token) or []
        existing = next((c for c in comments if MARKER in (c.get("body") or "")), None)
        if existing:
            _api("PATCH", f"{API}/repos/{repo}/issues/comments/{existing['id']}", token, {"body": body})
            print(f"pr_comment: updated comment {existing['id']}")
        else:
            _api("POST", f"{API}/repos/{repo}/issues/{pr}/comments", token, {"body": body})
            print("pr_comment: created comment")
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        print(f"pr_comment: GitHub API error (skipping): {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
