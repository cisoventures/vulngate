# action/ — Phase 2 ✅ (GitHub Action, the enforcement layer)

A composite Action that wraps the CLI so a failing scan can **block the merge**.
No scan logic is duplicated here — it installs and calls `vulngate`, then
handles the GitHub-specific surface (comment, SARIF, gate).

## Usage

```yaml
# .github/workflows/vulngate.yml
name: vulngate
on: pull_request
permissions:
  contents: read
  pull-requests: write     # PR comment
  security-events: write   # SARIF upload
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cisoventures/vulngate@v1
        with:
          fail-on: high
```

(Full example: [`example-workflow.yml`](example-workflow.yml).)

## What it does each run

1. Installs `vulngate[scanners]` + gitleaks, runs the scan → `findings.json` + SARIF.
2. **Diff filter** (optional, `diff-only: true`) — narrows findings to PR-changed
   files so you don't fail on pre-existing debt.
3. **LLM triage** (optional, `anthropic-api-key`) — your own key adds a
   false-positive judgement, a plain-English explanation, and a suggested fix per
   code finding. Absent the key, skipped silently.
4. Uploads SARIF to the Security tab.
5. Upserts a **single** PR comment (edited in place on every push — never spammed).
6. Re-runs `vulngate gate` so diff-filtering/triage affect the pass/fail verdict.

## Inputs

| Input | Default | Purpose |
|---|---|---|
| `paths` | `.` | Path to scan |
| `fail-on` | `high` | Threshold that fails the check |
| `config` | – | Path to a `vulngate.toml` |
| `comment` | `true` | Upsert the PR comment |
| `upload-sarif` | `true` | Upload SARIF to code scanning |
| `diff-only` | `false` | Limit to PR-changed files |
| `install-gitleaks` | `true` | Install gitleaks for secret scanning |
| `anthropic-api-key` | – | BYO key for LLM triage (empty = skipped) |
| `anthropic-model` | `claude-opus-4-8` | Triage model when a key is set |

## Triage safety

Scanned code is untrusted input to the model, so triage **flags** likely false
positives but does not remove them from the gate by default — a scanner a code
comment could talk out of failing the build would be worse than useless. Opt into
dropping high-confidence false positives with `VULNGATE_TRIAGE_FILTER=true`.
