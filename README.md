# vulngate

**Agent-neutral security checks before you ship.** Find, understand, and fix
vulnerabilities in your code — whether it was written by Claude Code, Cursor,
Codex, Windsurf, Gemini CLI, or a human.

> **We scan the code the agents produce — not the agents themselves.**
> (Tools like skill/MCP supply-chain scanners secure the agent. vulngate
> secures the code that lands in your repo.)

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
# PyPI publish is pending — until then, install from source:
#   pip install "vulngate[scanners] @ git+https://github.com/cisoventures/vulngate.git"
pip install "vulngate[scanners]"

# Gitleaks is a Go binary (optional, for secret scanning):
brew install gitleaks        # or see the gitleaks releases page
```

The core alone (`pip install vulngate`) has **zero dependencies** — it's pure
stdlib and will run, degrading gracefully to whatever scanners you have.

## Usage

```bash
vulngate scan .                      # scan the current repo
vulngate scan ./src --fail-on medium # stricter threshold
vulngate scan . --sarif results.sarif
```

Outputs, every run:
- a **pretty terminal summary** grouped by severity, each finding with a
  plain-English line and a fix hint;
- **`findings.json`** — the normalized schema (see [`schemas/findings.schema.json`](schemas/findings.schema.json));
- optional **SARIF** for GitHub code scanning.

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
```

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
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cisoventures/vulngate@v1
        with:
          fail-on: high
          # anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}   # optional: your key → LLM triage + fix suggestions
```

It upserts a **single** PR comment (never spams), uploads SARIF to the Security
tab, and fails the check above the threshold. See [`action/`](action/) for all
inputs. The optional LLM triage runs on **your** key — omit it and the free
deterministic gate is fully useful.

## Use it with your agent (the vibe-coder loop)

Install the local MCP server (no hosting, no key) and your agent — Claude Code,
Cursor, Codex, Windsurf — can scan, explain in plain English, and draft fixes on
your own subscription:

```bash
pip install "vulngate[mcp,scanners]"
claude mcp add vulngate -- vulngate-mcp      # Claude Code; other agents in mcp-server/
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
| **3** | MCP server — `scan_repo` / `explain_finding` / `suggest_patch` for your agent (the flagship vibe-coder loop) | ✅ shipped |
| **4** | Instruction adapters — `SKILL.md`, `.cursor/rules`, `AGENTS.md` + distribution | ⬜ planned |

Each phase is independently useful — stopping after any one leaves a complete tool.

## Contributing

Community-maintained, no SLA — see [CONTRIBUTING.md](CONTRIBUTING.md). The
easiest first contribution is a new entry in the plain-English
[knowledge pack](vulngate/knowledge.py). Questions → GitHub Discussions.

## License

[MIT](LICENSE). vulngate is complementary to vendor-native security tooling,
including Anthropic's Claude-native security suite — this is the universal
on-ramp; theirs is the Claude-native deep end.
