# vulngate

[![PyPI](https://img.shields.io/pypi/v/vulngate.svg)](https://pypi.org/project/vulngate/)
[![Python](https://img.shields.io/pypi/pyversions/vulngate.svg)](https://pypi.org/project/vulngate/)
[![CI](https://github.com/cisoventures/vulngate/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/cisoventures/vulngate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/cisoventures/vulngate/blob/main/LICENSE)
[![Marketplace](https://img.shields.io/badge/Marketplace-vulngate-2ea44f?logo=github)](https://github.com/marketplace/actions/vulngate)

**Agent-neutral security checks before you ship.** Find, understand, and fix
vulnerabilities in your code — whether it was written by Claude Code, Cursor,
Codex, Windsurf, Gemini CLI, or a human.

> **We scan the code the agents produce — not the agents themselves.**
> (Tools like skill/MCP supply-chain scanners secure the agent. vulngate
> secures the code that lands in your repo.)

[Install](#install) · [CLI](#usage) · [GitHub Action](#use-it-in-ci-the-enforcement-point) ·
[MCP server](#use-it-with-your-agent-the-vibe-coder-loop) · [Pinning](#releases-versioning-and-pinning) ·
[Security](#security) · [PyPI](https://pypi.org/project/vulngate/) ·
[Marketplace](https://github.com/marketplace/actions/vulngate) ·
[Releases](https://github.com/cisoventures/vulngate/releases)

---

## Philosophy: $0 forever, bring-your-own-inference

- **The core makes no LLM calls.** vulngate orchestrates deterministic scanners
  (SAST, secrets, dependency audit) and normalizes their output. It costs
  nothing to run and sends your code to no one.
- **Understanding and auto-fixing happen through _your_ agent.** A "vibe coder"
  who can't read `CWE-78` is already working inside an AI agent — so vulngate
  hands that agent structured findings (Phase 3, MCP) and it explains the risk
  in plain English and drafts the fix, on your subscription, not a maintainer's.
- **Even with no agent and no API key, you still get value:** every finding
  ships with a `plain_summary` — one jargon-free sentence — from a built-in,
  offline knowledge pack.
- **CI is the enforcement point.** An agent in an IDE can ignore instructions;
  a CI check blocks the merge. vulngate is CI-friendly from day one (stable
  exit codes, SARIF, JSON).

## What it runs

| Scanner | Kind | Auto-runs when |
|---|---|---|
| [Semgrep](https://semgrep.dev) | SAST (code patterns) | source files are present |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secrets | always (scans the tree) |
| [pip-audit](https://github.com/pypa/pip-audit) | Python deps | a `requirements*.txt` is present |
| `npm audit` | npm deps | a `package-lock.json` is present |

Missing a scanner? vulngate **warns and skips it** — it never crashes. Install
scanners to widen coverage.

## Install

```bash
# Core + the Python scanners (Semgrep, pip-audit) in one shot.
pip install "vulngate[scanners]"

# Gitleaks is a Go binary (optional, for secret scanning):
brew install gitleaks        # or see the gitleaks releases page
```

Python **3.11, 3.12 and 3.13** are tested on every commit. Prefer a throwaway
environment? `uvx --from "vulngate[scanners]" vulngate scan .` runs it without
installing anything permanently.

The core alone (`pip install vulngate`) has **zero dependencies** — it's pure
stdlib and will run, degrading gracefully to whatever scanners you have.

## Usage

```bash
vulngate scan .                      # scan the current repo
vulngate scan ./src --fail-on medium # stricter threshold
vulngate scan . --sarif results.sarif
vulngate gate findings.json          # re-check an existing report against the threshold (exit code only)
vulngate sarif findings.json --out results.sarif  # project a findings.json to SARIF
```

Outputs, every run:
- a **pretty terminal summary** grouped by severity, each finding with a
  plain-English line and a fix hint. Vulnerable dependencies are labelled
  **`in your live app`** vs **`build-only tool`** (a flaw in your build toolchain
  is not the same risk as one in shipped code), code-pattern findings carry a
  *"this can be a false alarm — confirm it applies"* caveat, and a short
  **glossary** defines any jargon that appears;
- **`findings.json`** — the normalized schema (see [`schemas/findings.schema.json`](schemas/findings.schema.json)),
  including a **scan receipt** (`scan.receipt`: commit, config hash, scanner
  versions, timestamps) so a report is self-describing and auditable;
- optional **SARIF** for GitHub code scanning.

Every scanner's outcome is recorded with an honest status —
`completed` · `not_applicable` (nothing to scan) · `unavailable` (not installed)
· `disabled` (config) · `error` — and the overall `scan.status`
(`complete` / `partial` / `no_coverage` / `error`) is derived from them, so a
`0` findings result is never confused with a scanner that didn't run.

### Exit codes (CI-friendly)

| Code | Meaning |
|---|---|
| `0` | clean, or nothing at/above the `--fail-on` threshold |
| `1` | at least one finding at/above the threshold (default: `high`) |
| `2` | tool error (bad target/config, or every applicable scanner failed) |

A *missing* scanner is a skip with a warning — **not** exit `2`.

### Zero-config, with optional config

Drop a `vulngate.toml` at your repo root (all keys optional; reused identically
by every later phase):

```toml
fail_on = "high"                 # critical | high | medium | low
exclude = ["tests/*", "*.min.js"]
disable = ["gitleaks"]           # scanner names to skip
ignore  = ["python.lang.security.audit.some-rule", "vg_ab12cd..."]  # rule or finding id
fail_on_dev_deps = true          # do build-only (dev) dependency flaws block the gate?
```

**Build-only vs live-app dependencies.** A vulnerable *build-only* dependency
(your dev toolchain — bundlers, test runners, CLIs) never ships to the running
app, so it isn't the same risk as a flaw in a package your app actually runs.
By default vulngate is strict (build-only flaws still block). For an app-team or
vibecoder setup, set `fail_on_dev_deps = false` (or pass `--ignore-dev-deps`, or
the Action's `ignore-dev-deps: true`): build-only flaws are **still reported**,
just not treated as blocking. The local MCP server — the vibecoder agent loop —
uses this lenient behavior by default.

## Use it in CI (the enforcement point)

Add the Action to block merges on findings at/above your threshold:

```yaml
# .github/workflows/vulngate.yml
name: vulngate
on: pull_request
permissions:
  contents: read
  pull-requests: write     # for the PR comment
  security-events: write   # for SARIF upload
  actions: read            # required by the SARIF upload action
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
      # Pin by commit, not by tag — see "Releases, versioning and pinning" below.
      - uses: cisoventures/vulngate@b6a322b92b494341a9d702e2c8e91856a9096412  # v1.5.5
        with:
          fail-on: high
          # ignore-dev-deps: true                                 # build-only dep flaws: report, don't block
          # anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}   # optional: your key → LLM triage + fix suggestions
```

It upserts a **single** PR comment (never spams), uploads SARIF to the Security
tab, and fails the check above the threshold. See [`action/`](action/) for all
inputs. The optional LLM triage runs on **your** key — omit it and the free
deterministic gate is fully useful.

Add four lines so those pins never go stale — Dependabot opens a reviewable PR
for each new vulngate release:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule: { interval: "weekly" }
```

**Private repos:** uploading SARIF to the Security tab needs a public repo or
GitHub Advanced Security. vulngate detects when code scanning isn't available and
**skips the upload** rather than failing your build — a passing scan always stays
a passing build. (Set `upload-sarif: false` to skip the check entirely.)

## Use it with your agent (the vibe-coder loop)

Install the local MCP server (no hosting, no key) and your agent — Claude Code,
Cursor, Codex, Windsurf — can scan, explain in plain English, and draft fixes on
your own subscription:

```bash
pip install "vulngate[mcp,scanners]"
claude mcp add vulngate -- vulngate-mcp      # Claude Code; other agents in mcp-server/

# or without installing anything permanently:
# uvx --from "vulngate[mcp,scanners]" vulngate-mcp
```

Then: *"scan my repo"* → *"what's the worst one?"* (plain-English explanation) →
*"fix it"* (the agent drafts a patch, you approve). The server is read-only except
for writing `findings.json`; it never writes code and makes no LLM calls itself.
See [`mcp-server/`](mcp-server/) for per-agent config.

## Roadmap

| Phase | What | Status |
|---|---|---|
| **1** | CLI core — orchestrate + normalize + SARIF/JSON + exit codes | ✅ shipped |
| **2** | GitHub Action — PR comment, SARIF upload, threshold gate, optional BYO-key LLM triage | ✅ shipped |
| **3** | MCP server — `scan_repo` / `explain_finding` / `suggest_patch` / `verify_fix` for your agent (the flagship vibe-coder loop) | ✅ shipped |
| **4** | Instruction adapters — `SKILL.md`, `.cursor/rules`, `AGENTS.md` + distribution | ✅ shipped |
| **—** | Maintenance — a weekly job checks every pinned scanner against its latest release and opens a reviewed PR, so pinning never means stale detection | ♻️ ongoing |

Each phase is independently useful — stopping after any one leaves a complete tool.

## Releases, versioning and pinning

vulngate follows semantic versioning. Every release is tagged (`v1.5.5`) and
listed under [Releases](https://github.com/cisoventures/vulngate/releases); the
Python package is on [PyPI](https://pypi.org/project/vulngate/).

The `v1` tag also exists and moves to the newest 1.x release. **Prefer a commit
SHA anyway** — for vulngate and for every other third-party action you use. A
moving tag means the code running in your pipeline can change without a diff,
a review or a record, which is exactly the property a security gate shouldn't
have. Pair the SHA with Dependabot (four lines, above) and updates arrive as
pull requests you can read.

```yaml
uses: cisoventures/vulngate@b6a322b92b494341a9d702e2c8e91856a9096412  # v1.5.5
```

## Security

**Reporting a vulnerability in vulngate itself:** please use
[private vulnerability reporting](https://github.com/cisoventures/vulngate/security/advisories/new)
rather than a public issue — see [SECURITY.md](SECURITY.md).

What vulngate does to stay worth trusting:

- **Your code never leaves your machine.** The core makes no LLM calls and
  uploads nothing. Optional triage runs only when *you* supply an API key.
- **`findings.json` is safe to share** — no secret values, no source snippets,
  no absolute paths.
- **Our own supply chain is pinned:** every GitHub Action is pinned by commit
  SHA, the gitleaks binary is verified against a hardcoded checksum for each
  architecture, and the scanners install at exact versions.
- **Pinned but not stale:** a weekly job re-checks each pinned scanner, proves
  the new versions still catch the test fixture, and opens a PR for a human to
  review. It fails loudly rather than reporting "all current" when it couldn't
  check.

## Contributing

Community-maintained, no SLA — see [CONTRIBUTING.md](CONTRIBUTING.md). The
easiest first contribution is a new entry in the plain-English
[knowledge pack](vulngate/knowledge.py). Questions and bug reports →
[Issues](https://github.com/cisoventures/vulngate/issues). Security reports →
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). vulngate is complementary to vendor-native security tooling,
including Anthropic's Claude-native security suite — this is the universal
on-ramp; theirs is the Claude-native deep end.
