#!/usr/bin/env python3
"""Keep vulngate's pinned scanner versions fresh.

Pinning the scanners protects the supply chain, but it creates the opposite
problem: a stale security scanner silently loses detection. That trade-off is
worst for gitleaks, whose secret-detection rules are compiled INTO the binary —
an old gitleaks simply cannot recognise newer token formats. (Semgrep degrades
more gracefully: `p/default` rules are fetched from its registry at scan time,
so a pinned engine still runs current rules.)

The pins live inside shell `run:` blocks in action.yml, where Dependabot cannot
see them. This script closes that blind spot: it finds the latest release of each
pinned tool, rewrites the pin — recomputing gitleaks' sha256 for EVERY
architecture, because a version bump with stale checksums breaks the build — and
leaves a PR for a human to review.

Net effect: still pinned, still checksummed, still tested, still reviewed — just
never stale.

Honest limit: snapshotting the release's own checksums cannot detect a poisoned
*initial* release (trust-on-first-use). What it does buy is that an artifact,
once vetted, cannot be swapped underneath us later, and that version changes are
never silent.

Usage:
    python scripts/check_scanner_freshness.py            # report only; exit 1 if stale
    python scripts/check_scanner_freshness.py --write    # apply the new pins
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

ACTION = Path(__file__).resolve().parents[1] / "action.yml"
UA = {"User-Agent": "vulngate-scanner-freshness"}
# gitleaks release assets we pin a checksum for, keyed by the arch label in action.yml.
GITLEAKS_ARCHES = ("x64", "arm64")


def _request(url: str) -> urllib.request.Request:
    req = urllib.request.Request(url, headers=UA)
    # Unauthenticated GitHub API calls share a 60/hour budget per IP, and hosted
    # runners share IPs — that is what failed the 2026-09-07 run (WHI-145). In CI
    # the workflow token lifts it to 1,000+/hour. The token goes ONLY to
    # api.github.com, and as an *unredirected* header so a redirect can never
    # carry it to another host.
    token = os.environ.get("GITHUB_TOKEN")
    if token and urlsplit(url).hostname == "api.github.com":
        req.add_unredirected_header("Authorization", f"Bearer {token}")
    return req


def _open(url: str):
    try:
        return urllib.request.urlopen(_request(url), timeout=30)
    except urllib.error.HTTPError as e:
        if e.code in (403, 429) and e.headers.get("X-RateLimit-Remaining") == "0":
            authed = "with" if os.environ.get("GITHUB_TOKEN") else "WITHOUT"
            raise RuntimeError(
                f"GitHub API rate limit hit {authed} a token ({url}); resets at epoch "
                f"{e.headers.get('X-RateLimit-Reset', '?')}. Nothing was checked — "
                "this is NOT 'all current'.") from e
        raise


def _get_json(url: str) -> dict:
    with _open(url) as r:
        return json.loads(r.read())


def _get_text(url: str) -> str:
    with _open(url) as r:
        return r.read().decode("utf-8", errors="replace")


def latest_pypi(pkg: str) -> str:
    return _get_json(f"https://pypi.org/pypi/{pkg}/json")["info"]["version"]


def latest_gitleaks() -> str:
    tag = _get_json("https://api.github.com/repos/gitleaks/gitleaks/releases/latest")["tag_name"]
    return tag.lstrip("v")


def gitleaks_checksums(version: str) -> dict[str, str]:
    """sha256 per arch, read from the release's checksums file at UPDATE time.

    Snapshotting it here (reviewed in a PR) is deliberately different from
    verifying against it at RUNTIME: the runtime must not trust a file that a
    compromised release could rewrite alongside the artifact.
    """
    base = f"https://github.com/gitleaks/gitleaks/releases/download/v{version}"
    text = _get_text(f"{base}/gitleaks_{version}_checksums.txt")
    out: dict[str, str] = {}
    for arch in GITLEAKS_ARCHES:
        asset = f"gitleaks_{version}_linux_{arch}.tar.gz"
        for line in text.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].lstrip("*") == asset:
                out[arch] = parts[0]
                break
        if arch not in out:
            raise RuntimeError(f"no sha256 for {asset} in the release checksums")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write", action="store_true", help="apply the new pins to action.yml")
    args = ap.parse_args()

    text = ACTION.read_text(encoding="utf-8")
    original = text
    changes: list[str] = []

    # ── PyPI-pinned tools embedded in `run:` shell lines ─────────────────────
    for pkg in ("semgrep", "pip-audit", "anthropic"):
        pattern = re.compile(rf"{re.escape(pkg)}==([0-9][0-9A-Za-z.\-]*)")
        found = pattern.search(text)
        if not found:
            # A pin we can't see is a pin we can't check. Skipping it would end in
            # "All scanner pins are current" — the silent staleness this job exists to prevent.
            raise RuntimeError(f"{pkg}: pin not found in action.yml (did the format change?)")
        current, newest = found.group(1), latest_pypi(pkg)
        if current != newest:
            text = pattern.sub(f"{pkg}=={newest}", text)
            changes.append(f"{pkg} {current} -> {newest}")
        print(f"  {pkg}: pinned {current} · latest {newest} {'(STALE)' if current != newest else '(current)'}")

    # ── gitleaks: version AND the per-arch sha256 must move together ─────────
    ver_re = re.compile(r'(GITLEAKS_VERSION:\s*")([0-9][0-9A-Za-z.\-]*)(")')
    m = ver_re.search(text)
    if m:
        current, newest = m.group(2), latest_gitleaks()
        print(f"  gitleaks: pinned {current} · latest {newest} {'(STALE)' if current != newest else '(current)'}")
        if current != newest:
            sums = gitleaks_checksums(newest)          # fail loudly before rewriting anything
            text = ver_re.sub(rf"\g<1>{newest}\g<3>", text)
            for arch, digest in sums.items():
                arch_re = re.compile(rf'(arch="{arch}";\s*sum=")([0-9a-f]{{64}})(")')
                if not arch_re.search(text):
                    raise RuntimeError(f"could not locate the {arch} sha256 line to update")
                text = arch_re.sub(rf"\g<1>{digest}\g<3>", text)
            changes.append(f"gitleaks {current} -> {newest} (+ sha256 for {', '.join(sums)})")
    else:
        raise RuntimeError("gitleaks: GITLEAKS_VERSION pin not found in action.yml")

    if not changes:
        print("\nAll scanner pins are current.")
        return 0

    print("\nUpdates available:")
    for c in changes:
        print(f"  - {c}")

    if args.write and text != original:
        ACTION.write_text(text, encoding="utf-8")
        print(f"\nWrote {ACTION.name}.")
    elif not args.write:
        print("\n(run with --write to apply)")
    return 1


def cli() -> int:
    """Exit 0 = all current, 1 = updates found, 2 = the check itself failed."""
    try:
        return main()
    except Exception as e:                     # network/parse failure must be loud, not silent
        print(f"scanner-freshness: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(cli())
