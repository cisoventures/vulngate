#!/usr/bin/env python3
"""Filter findings.json to files changed in the current PR (diff mode).

Keeps the comment and gate focused on what the PR actually touched, instead of
failing on pre-existing debt. Scanner-agnostic: a finding is kept if its file
is in the PR's changed-file set (dependency findings survive when the lockfile
changed). Pure stdlib; best-effort — on any error the file is left unchanged.

Env: GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_EVENT_PATH.
Arg:  path to findings.json (default: findings.json).
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path

SEVERITIES = ("critical", "high", "medium", "low")
API = "https://api.github.com"


def _pr_number(event_path: str | None) -> int | None:
    if not event_path or not Path(event_path).exists():
        return None
    try:
        ev = json.loads(Path(event_path).read_text())
    except (json.JSONDecodeError, OSError):
        return None
    return (ev.get("pull_request") or {}).get("number") or ev.get("number")


def _changed_files(repo: str, pr: int, token: str) -> set[str]:
    files: set[str] = set()
    page = 1
    while True:
        url = f"{API}/repos/{repo}/pulls/{pr}/files?per_page=100&page={page}"
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "vulngate",
        })
        with urllib.request.urlopen(req, timeout=30) as r:
            batch = json.loads(r.read() or "[]")
        if not batch:
            break
        files.update(f["filename"] for f in batch)
        if len(batch) < 100:
            break
        page += 1
    return files


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "findings.json"
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    pr = _pr_number(os.environ.get("GITHUB_EVENT_PATH"))
    if not (token and repo and pr):
        print("diff_filter: not a PR context; leaving findings unchanged")
        return 0
    try:
        data = json.loads(Path(path).read_text())
        changed = _changed_files(repo, pr, token)
    except Exception as e:  # noqa: BLE001 — best-effort, never break CI
        print(f"diff_filter: skipping ({e})", file=sys.stderr)
        return 0

    before = data.get("findings", [])
    kept = [f for f in before if f.get("file") in changed]
    data["findings"] = kept
    summary = {s: 0 for s in SEVERITIES}
    for f in kept:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1
    data["summary"] = {"total": len(kept), **summary}
    data.setdefault("scan", {})["diff_scoped"] = True
    Path(path).write_text(json.dumps(data, indent=2) + "\n")
    print(f"diff_filter: {len(before)} → {len(kept)} findings on {len(changed)} changed file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
