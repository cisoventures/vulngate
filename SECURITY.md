# Security Policy

vulngate is a security tool, so a flaw in vulngate is a flaw in someone's gate.
Reports are welcome and taken seriously.

## Reporting a vulnerability

**Use [private vulnerability reporting](https://github.com/cisoventures/vulngate/security/advisories/new)**
— GitHub's private channel on this repository. Please don't open a public issue
for a security problem.

Helpful to include: what an attacker gains, the smallest steps to reproduce,
affected version (`vulngate --version`), and whether it affects the CLI, the
GitHub Action, or the MCP server.

This project is **community-maintained with no SLA**. There is no guaranteed
response time, and no bug bounty. Reports are still read, and fixes ship as a
normal release with credit if you want it.

## Supported versions

The latest release on [PyPI](https://pypi.org/project/vulngate/) is supported.
Fixes ship forward in a new release rather than as backports to older ones.

## In scope

- Anything that makes vulngate **miss a finding it should catch**, or report a
  scan as complete when a scanner didn't actually run.
- Secret values, source snippets, or absolute paths leaking into `findings.json`,
  the terminal output, SARIF, or the PR comment. `findings.json` is meant to be
  safe to share; if it isn't, that's a bug.
- Command injection or path traversal through scan targets, config, MCP
  arguments, or the Action's inputs.
- Anything that lets repository contents escape the machine the scan runs on.
- Weaknesses in our own supply chain: the pinned scanner versions, the gitleaks
  checksums, the SHA-pinned actions, or the release process.

## Out of scope

- **Findings that vulngate reports about *your* code.** Those are the tool
  working; fix them in your repo.
- Vulnerabilities in the underlying scanners themselves (Semgrep, Gitleaks,
  pip-audit, npm audit) — report those upstream. If vulngate *uses* one
  unsafely, that is in scope.
- False positives and false negatives from a scanner's own rules. Rule quality
  is an ordinary issue, not a security report.
- Anything requiring an attacker who already controls the machine running the scan.

## What vulngate does to limit its own blast radius

- **No network egress of your code.** The core makes no LLM calls. Optional
  triage runs only when you pass your own API key.
- **No secrets or snippets** are ever written into a finding — a hard rule for
  every scanner adapter.
- **Fails closed on zero coverage:** if nothing could be scanned, the run fails
  rather than reporting a clean result.
- **Pinned supply chain:** actions pinned by commit SHA, gitleaks verified
  against a hardcoded per-architecture checksum, scanners installed at exact
  versions — with a weekly job that keeps those pins current and fails loudly
  if it can't check.
