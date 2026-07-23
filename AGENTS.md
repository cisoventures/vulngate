# AGENTS.md

Guidance for any coding agent working in this repository. (This is also a live
example of the Phase-4 adapter — see [`adapters/`](adapters/).)

## Security gate — dogfood vulngate on itself

Before declaring a code change deployment-ready, run vulngate on this repo and
resolve findings at or above `high`:

```bash
pip install -e ".[dev,scanners]"   # brew install gitleaks for secret scanning
vulngate scan . --fail-on high
```

The vuln scanner must not itself ship vulns — treat a finding on our own code as
a blocker, not a warning.

## Working on the code

- Keep the **core dependency-free** (stdlib only). Scanners are external tools we
  shell out to, never import.
- One CLI core; the Action, MCP server, and adapters are thin wrappers — never
  duplicate scan logic (see [CONTRIBUTING.md](CONTRIBUTING.md)).
- `findings.json` must never contain secret values or source snippets.
- Run `pytest -q` (network-free) before finishing.
